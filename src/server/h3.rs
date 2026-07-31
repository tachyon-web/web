use bytes::{Buf, Bytes};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;

use crate::server::{REQUEST_TIMEOUT, Server};

impl<S> Server<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Serve HTTP/3 over QUIC using the given s2n-quic server.
    ///
    /// # Errors
    ///
    /// Returns an error if FIPS compliance enforcement fails. The accept loop
    /// itself never surfaces per-connection errors as an `Err`; it just stops
    /// when `quic_server.accept()` returns `None`.
    pub async fn serve_h3(self, mut quic_server: s2n_quic::Server) -> Result<(), std::io::Error> {
        crate::server::enforce_fips_compliance()?;
        let state = Arc::new(self);
        let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(state.max_connections));

        while let Some(conn) = quic_server.accept().await {
            let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
                break;
            };
            let state = state.clone();
            tokio::spawn(async move {
                state.handle_h3_connection(conn).await;
                drop(permit);
            });
        }
        Ok(())
    }

    async fn handle_h3_connection(self: Arc<Self>, conn: s2n_quic::Connection) {
        let Ok(peer) = conn.remote_addr() else {
            return;
        };

        let h3_conn = s2n_quic_h3::Connection::new(conn);
        let Ok(mut h3_server) = h3::server::Connection::new(h3_conn).await else {
            return;
        };

        // Limit concurrent streams per connection for DoS protection.
        let stream_semaphore = Arc::new(tokio::sync::Semaphore::new(256));

        loop {
            let Ok(stream_permit) = stream_semaphore.clone().acquire_owned().await else {
                break;
            };
            match h3_server.accept().await {
                Ok(Some(resolver)) => {
                    let state = self.clone();
                    tokio::spawn(async move {
                        state.handle_h3_request(resolver, peer).await;
                        drop(stream_permit);
                    });
                }
                Ok(None) => {
                    drop(stream_permit);
                    break;
                }
                Err(e) => {
                    drop(stream_permit);
                    let err_str = e.to_string();
                    if !err_str.contains("application error")
                        && !err_str.contains("ConnectionError")
                    {
                        tracing::debug!("[h3] Stream accept error: {}", e);
                    }
                    break;
                }
            }
        }
    }

    async fn read_h3_body(
        &self,
        parts: &hyper::http::request::Parts,
        stream: &mut h3::server::RequestStream<s2n_quic_h3::BidiStream<Bytes>, Bytes>,
    ) -> Result<Bytes, StatusCode> {
        let method = &parts.method;
        if method == hyper::Method::GET || method == hyper::Method::HEAD {
            return Ok(Bytes::new());
        }

        let content_length = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let cap = if content_length > 0 && content_length <= self.max_body_size {
            content_length
        } else {
            0
        };

        // Strictly enforce zero-trust client allocation limits (DoS prevention).
        // Pre-allocate up to 256 KiB directly to avoid reallocations for standard payloads.
        let initial_allocation = if cap > 0 && cap <= 256 * 1024 {
            cap
        } else {
            std::cmp::min(cap, 64 * 1024)
        };
        let mut body_vec = Vec::with_capacity(initial_allocation);

        let timeout_res = tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        while chunk.has_remaining() {
                            let data = chunk.chunk();
                            if body_vec.len() + data.len() > self.max_body_size {
                                return Err(StatusCode::PAYLOAD_TOO_LARGE);
                            }
                            body_vec.extend_from_slice(data);
                            let len = data.len();
                            chunk.advance(len);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return Err(StatusCode::BAD_REQUEST),
                }
            }
            Ok(())
        })
        .await;

        match timeout_res {
            Ok(Err(status)) => Err(status),
            Err(_) => Err(StatusCode::REQUEST_TIMEOUT),
            Ok(Ok(())) => Ok(Bytes::from(body_vec)),
        }
    }

    async fn handle_h3_request(
        self: Arc<Self>,
        resolver: h3::server::RequestResolver<s2n_quic_h3::Connection, Bytes>,
        peer: std::net::SocketAddr,
    ) {
        let resolve_res = tokio::time::timeout(REQUEST_TIMEOUT, resolver.resolve_request()).await;

        let Ok(Ok((req, mut stream))) = resolve_res else {
            return;
        };

        let (parts, ()) = req.into_parts();

        let body_bytes = match self.read_h3_body(&parts, &mut stream).await {
            Ok(bytes) => bytes,
            Err(status) => {
                let _ = stream
                    .send_response(
                        Response::builder()
                            .status(status)
                            .body(())
                            .unwrap_or_else(|_| Response::new(())),
                    )
                    .await;
                let _ = stream.finish().await;
                return;
            }
        };

        // HTTP/3 stream frames aren't a standard `hyper::body::Body`, so (unlike the
        // HTTP/1.1 and HTTP/2 paths) this body is fully buffered up front by
        // `read_h3_body` rather than streamed lazily. It's still wrapped in the same
        // unified `Body` type so it flows through the same extractor pipeline —
        // `BodyStream`/`Request<Body>` handlers work identically, they just don't get
        // the zero-buffering benefit over HTTP/3 in this version.
        let mut rebuild_req =
            Request::from_parts(parts, crate::http::response::Body::full(body_bytes));
        #[cfg(feature = "original-uri")]
        {
            let orig_uri = rebuild_req.uri().clone();
            rebuild_req
                .extensions_mut()
                .insert(crate::routing::extract::OriginalUri(orig_uri));
        }
        rebuild_req
            .extensions_mut()
            .insert(crate::routing::extract::ConnectInfo(peer));
        rebuild_req
            .extensions_mut()
            .insert(crate::routing::extract::MaxBodySize(self.max_body_size));

        let full_resp = self.router.handle_request(rebuild_req).await;

        let (resp_parts, body) = full_resp.into_parts();
        let resp = Response::from_parts(resp_parts, ());

        if stream.send_response(resp).await.is_ok() {
            use http_body_util::BodyExt;
            let mut body = body;
            while let Some(frame_res) = body.frame().await {
                if let Ok(frame) = frame_res {
                    let send_res = if let Some(data) = frame.data_ref() {
                        stream.send_data(data.clone()).await
                    } else if let Some(trailers) = frame.trailers_ref() {
                        stream.send_trailers(trailers.clone()).await
                    } else {
                        Ok(())
                    };

                    if send_res.is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        let _ = stream.finish().await;
    }
}

#[cfg(all(test, feature = "cert-gen"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use crate::routing::{Router, get, post};
    use crate::server::Server;
    use bytes::{Buf, Bytes};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::sync::Arc;

    async fn hello() -> &'static str {
        "hello from h3"
    }

    async fn echo(body: Bytes) -> Vec<u8> {
        body.to_vec()
    }

    /// Builds a self-signed `rustls::ServerConfig` (ALPN "h3") from PEM cert/key strings.
    /// Hand-rolled via `crate::tls::pem` (mirroring `Server::start_all_inner`/`RustlsConfig::
    /// from_pem` in `server/mod.rs`) rather than reusing `TlsPolicy::server_config_from_pem`, so
    /// this test module only needs `cert-gen` — not also `tor`/`i2p` — to compile.
    fn build_server_config(cert_pem: &str, key_pem: &str) -> rustls::ServerConfig {
        let cert_chain: Vec<CertificateDer<'static>> = crate::tls::pem::certs(cert_pem.as_bytes());
        let key_der: PrivateKeyDer<'static> =
            crate::tls::pem::private_key(key_pem.as_bytes()).expect("parse private key");

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .expect("build rustls ServerConfig");
        config.alpn_protocols = vec![b"h3".to_vec()];
        config
    }

    /// Starts a real `Server::serve_h3` on loopback (OS-assigned port) serving `app`. Returns the
    /// bound address and the self-signed cert's PEM (for the client to trust).
    fn start_h3_server(
        app: Router<()>,
        max_body_size: Option<usize>,
    ) -> (std::net::SocketAddr, String) {
        let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let config = build_server_config(&cert.cert_pem, &cert.key_pem);

        let quic_tls = s2n_quic::provider::tls::rustls::Server::from(Arc::new(config));
        let quic_server = s2n_quic::Server::builder()
            .with_tls(quic_tls)
            .expect("with_tls")
            .with_io("127.0.0.1:0")
            .expect("with_io")
            .start()
            .expect("start quic server");
        let addr = quic_server.local_addr().expect("local addr");

        let mut server = Server::new(app);
        if let Some(limit) = max_body_size {
            server = server.max_body_size(limit);
        }
        drop(tokio::spawn(async move {
            let _ = server.serve_h3(quic_server).await;
        }));

        (addr, cert.cert_pem)
    }

    /// Connects a real HTTP/3 client (over loopback UDP) to `addr`, trusting `cert_pem`. The
    /// returned `JoinHandle` drives the connection's control/QPACK streams in the background —
    /// per `h3::client::Connection`'s own docs, this must stay alive and polled for the
    /// connection to make progress while requests are in flight.
    async fn h3_connect(
        addr: std::net::SocketAddr,
        cert_pem: &str,
    ) -> (
        h3::client::SendRequest<s2n_quic_h3::OpenStreams, Bytes>,
        tokio::task::JoinHandle<()>,
    ) {
        let client_tls = s2n_quic::provider::tls::rustls::Client::builder()
            .with_certificate(cert_pem)
            .expect("with_certificate")
            .with_application_protocols(std::iter::once("h3"))
            .expect("with_application_protocols")
            .build()
            .expect("build client tls");
        let client = s2n_quic::Client::builder()
            .with_tls(client_tls)
            .expect("with_tls")
            .with_io("127.0.0.1:0")
            .expect("with_io")
            .start()
            .expect("start quic client");

        let quic_conn = client
            .connect(s2n_quic::client::Connect::new(addr).with_server_name("localhost"))
            .await
            .expect("quic connect");

        let h3_conn = s2n_quic_h3::Connection::new(quic_conn);
        let (mut driver, send_request) = h3::client::new(h3_conn).await.expect("h3 client new");
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        (send_request, driver_task)
    }

    /// Reads all remaining `DATA` frames off a response stream into a `Vec<u8>`.
    async fn recv_all<S>(stream: &mut h3::client::RequestStream<S, Bytes>) -> Vec<u8>
    where
        S: h3::quic::RecvStream,
    {
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.expect("recv_data") {
            while chunk.has_remaining() {
                let n = chunk.remaining();
                body.extend_from_slice(&chunk.copy_to_bytes(n));
            }
        }
        body
    }

    /// Full loopback HTTP/3 round trip: a real `s2n-quic`/`h3` client speaking QUIC to a real
    /// `Server::serve_h3`. Exercises `handle_h3_connection`'s accept loop, `read_h3_body`'s
    /// GET early-return and its `recv_data`/Content-Length-driven accumulation for POST, and
    /// `handle_h3_request`'s full response path (`send_response`, the `frame()`/`send_data()`
    /// loop, and `finish()`).
    #[tokio::test]
    async fn h3_get_and_post_round_trip() {
        let app = Router::new()
            .route("/", get(hello))
            .route("/echo", post(echo));
        let (addr, cert_pem) = start_h3_server(app, None);

        let (mut send_request, driver_task) = h3_connect(addr, &cert_pem).await;

        // GET / — covers the GET/HEAD early-return in `read_h3_body`.
        let get_req = hyper::Request::builder()
            .method("GET")
            .uri("https://localhost/")
            .body(())
            .expect("build GET request");
        let mut get_stream = send_request
            .send_request(get_req)
            .await
            .expect("send GET request");
        get_stream
            .finish()
            .await
            .expect("finish GET request stream");
        let get_response = get_stream.recv_response().await.expect("recv GET response");
        assert_eq!(get_response.status(), hyper::StatusCode::OK);
        let get_body = recv_all(&mut get_stream).await;
        assert_eq!(get_body, b"hello from h3");

        // POST /echo with a Content-Length under `max_body_size` — covers the `recv_data`
        // accumulation loop and the Content-Length pre-allocation branch in `read_h3_body`.
        let payload = b"round trip me over quic".to_vec();
        let post_req = hyper::Request::builder()
            .method("POST")
            .uri("https://localhost/echo")
            .header(hyper::header::CONTENT_LENGTH, payload.len())
            .body(())
            .expect("build POST request");
        let mut post_stream = send_request
            .send_request(post_req)
            .await
            .expect("send POST request");
        post_stream
            .send_data(Bytes::from(payload.clone()))
            .await
            .expect("send POST body");
        post_stream
            .finish()
            .await
            .expect("finish POST request stream");
        let post_response = post_stream
            .recv_response()
            .await
            .expect("recv POST response");
        assert_eq!(post_response.status(), hyper::StatusCode::OK);
        let post_body = recv_all(&mut post_stream).await;
        assert_eq!(post_body, payload);

        drop(send_request);
        driver_task.abort();
    }

    /// A POST body exceeding `max_body_size` — covers the `PAYLOAD_TOO_LARGE` branch in
    /// `read_h3_body`'s `recv_data` loop.
    #[tokio::test]
    async fn h3_post_over_max_body_size_is_rejected() {
        let app = Router::new().route("/echo", post(echo));
        let (addr, cert_pem) = start_h3_server(app, Some(8));

        let (mut send_request, driver_task) = h3_connect(addr, &cert_pem).await;

        let payload = vec![b'x'; 64];
        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://localhost/echo")
            .header(hyper::header::CONTENT_LENGTH, payload.len())
            .body(())
            .expect("build POST request");
        let mut stream = send_request
            .send_request(req)
            .await
            .expect("send POST request");
        stream
            .send_data(Bytes::from(payload))
            .await
            .expect("send POST body");
        stream.finish().await.expect("finish POST request stream");
        let response = stream.recv_response().await.expect("recv response");
        assert_eq!(response.status(), hyper::StatusCode::PAYLOAD_TOO_LARGE);

        drop(send_request);
        driver_task.abort();
    }
}
