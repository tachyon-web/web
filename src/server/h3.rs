use bytes::{Buf, Bytes};
use http_body_util::BodyExt as _;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;

use crate::server::accept::ConnectionLimit;
use crate::server::http::body_time_earned;
use crate::server::shared::{Origin, Shared};
use crate::server::{REQUEST_TIMEOUT, RESPONSE_WRITE_TIMEOUT};

/// Builds the QUIC endpoint HTTP/3 is served over, from a rustls config and a bind address.
pub(crate) fn build_quic_server(
    config: Arc<rustls::ServerConfig>,
    io: impl tachyon_quic::s2n_quic::provider::io::TryInto<
        Error: std::error::Error + Send + Sync + 'static,
    >,
    max_concurrent_streams: usize,
) -> Result<tachyon_quic::s2n_quic::Server, Box<dyn std::error::Error + Send + Sync>> {
    let limits = tachyon_quic::s2n_quic::provider::limits::Limits::new()
        // 1 MB flow-control windows match H/2 settings and saturate LAN pipes.
        .with_data_window(1_048_576)?
        .with_bidirectional_local_data_window(1_048_576)?
        .with_bidirectional_remote_data_window(1_048_576)?
        // 100ms is a safe, standard default initial RTT for public internet clients.
        .with_initial_round_trip_time(Duration::from_millis(100))?
        // Equal to the per-connection budget `handle_h3_connection` enforces, so QUIC flow
        // control applies the backpressure instead of us resetting streams on arrival.
        .with_max_open_remote_bidirectional_streams(
            u64::try_from(max_concurrent_streams).unwrap_or(u64::MAX),
        )?
        // Keep ACK overhead low: ACK every 4th packet (default is every 2nd).
        .with_ack_elicitation_interval(4)?
        // Disable active migration (saves state tracking).
        .with_active_connection_migration(false)?
        // Reduce connection-ID slots (fewer is fine for 0-RTT / stationary peers).
        .with_max_active_connection_ids(2)?
        // Aggressive handshake timeout: reject slow clients quickly.
        .with_max_handshake_duration(Duration::from_secs(5))?;

    Ok(tachyon_quic::s2n_quic::Server::builder()
        .with_tls(tachyon_quic::s2n_quic::provider::tls::rustls::Server::from(
            config,
        ))?
        .with_limits(limits)?
        .with_io(io)?
        .start()?)
}

/// Bounds one response-write await by [`RESPONSE_WRITE_TIMEOUT`], collapsing a stall into the
/// same `Err` the caller already handles by abandoning the stream.
async fn write_within<T, E>(
    write: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, ()> {
    match tokio::time::timeout(RESPONSE_WRITE_TIMEOUT, write).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(()),
        Err(_) => {
            crate::telemetry_debug!("[h3] response write stalled; abandoning stream");
            Err(())
        }
    }
}

/// Sends a bodyless response and finishes the stream.
///
/// Bounded like every other write: these are the cheapest responses for a peer to provoke, and
/// a peer holding its flow-control window shut would otherwise pin a stream permit each.
async fn send_head_only(
    stream: &mut tachyon_quic::h3::server::RequestStream<tachyon_quic::BidiStream<Bytes>, Bytes>,
    response: Response<()>,
) {
    let _ = write_within(stream.send_response(response)).await;
    let _ = write_within(stream.finish()).await;
}

/// Serves HTTP/3 on `quic_server` until the future is dropped.
pub(crate) async fn serve_h3(shared: Arc<Shared>, mut quic_server: tachyon_quic::s2n_quic::Server) {
    let port = quic_server.local_addr().ok().map(|addr| addr.port());
    while let Some(conn) = quic_server.accept().await {
        let permit = shared.connections.acquire().await;
        let shared = shared.clone();
        ConnectionLimit::serve(permit, async move {
            shared.handle_h3_connection(conn, port).await;
        });
    }
}

impl Shared {
    async fn handle_h3_connection(
        self: Arc<Self>,
        conn: tachyon_quic::s2n_quic::Connection,
        port: Option<u16>,
    ) {
        let Ok(peer) = conn.remote_addr() else {
            return;
        };
        let origin = Origin {
            peer: Some(peer),
            secure: true,
            h3_port: port,
        };

        // Bounded because this holds a connection permit: a peer could otherwise complete the
        // QUIC handshake, keep it alive with PINGs, and never open its HTTP/3 control stream.
        let setup = tokio::time::timeout(
            REQUEST_TIMEOUT,
            tachyon_quic::h3::server::Connection::new(tachyon_quic::Connection::new(conn)),
        );
        let Ok(Ok(mut h3_server)) = setup.await else {
            crate::telemetry_debug!("[h3] connection setup failed or timed out");
            return;
        };

        let stream_semaphore = Arc::new(tokio::sync::Semaphore::new(self.limits.max_h3_streams));

        let mut draining = false;
        loop {
            // `accept()` also drives the control stream, QPACK and GOAWAY, so it must run every
            // iteration rather than wait behind the stream semaphore — otherwise a peer holding
            // every stream open would stall the connection's control plane.
            let accepted = tokio::select! {
                accepted = h3_server.accept() => accepted,
                () = self.shutdown.requested(), if !draining => {
                    draining = true;
                    // GOAWAY: in-flight streams finish, new ones are refused, and `accept`
                    // then returns `None`.
                    if h3_server.shutdown(0).await.is_err() {
                        break;
                    }
                    continue;
                }
            };
            match accepted {
                Ok(Some(resolver)) => {
                    if let Ok(stream_permit) = stream_semaphore.clone().try_acquire_owned() {
                        let state = self.clone();
                        tokio::spawn(async move {
                            state.handle_h3_request(resolver, origin).await;
                            drop(stream_permit);
                        });
                    } else {
                        // At the in-flight limit: dropping the resolver cancels the stream, like
                        // h2's `REFUSED_STREAM`.
                        crate::telemetry_debug!(
                            "[h3] refusing stream: connection is at its in-flight limit"
                        );
                        drop(resolver);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let err_str = e.to_string();
                    if !err_str.contains("application error")
                        && !err_str.contains("ConnectionError")
                    {
                        crate::telemetry_debug!("[h3] stream accept error: {}", e);
                    }
                    break;
                }
            }
        }
        // Requests run on their own tasks; hold the connection permit until they finish, or
        // the shutdown drain returns while responses are still being written.
        let streams = u32::try_from(self.limits.max_h3_streams).unwrap_or(u32::MAX);
        let _ = stream_semaphore.acquire_many(streams).await;
    }

    async fn read_h3_body(
        &self,
        parts: &hyper::http::request::Parts,
        stream: &mut tachyon_quic::h3::server::RequestStream<
            tachyon_quic::BidiStream<Bytes>,
            Bytes,
        >,
    ) -> Result<Bytes, StatusCode> {
        let content_length = crate::server::security::content_length(&parts.headers)
            .map_err(|()| StatusCode::BAD_REQUEST)?;

        if content_length.is_some_and(|len| {
            usize::try_from(len).map_or(true, |len| len > self.limits.max_body_size)
        }) {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let content_length = content_length.and_then(|len| usize::try_from(len).ok());
        let limit = content_length.unwrap_or(self.limits.max_body_size);
        let over_limit = if content_length.is_some() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::PAYLOAD_TOO_LARGE
        };

        let mut body_vec = Vec::with_capacity(content_length.unwrap_or(0).min(256 * 1024));

        // Same rule as the HTTP/1.1 and HTTP/2 body: a grace period plus time earned per byte.
        let mut deadline = tokio::time::Instant::now()
            .checked_add(REQUEST_TIMEOUT)
            .ok_or(StatusCode::REQUEST_TIMEOUT)?;
        loop {
            let Ok(received) = tokio::time::timeout_at(deadline, stream.recv_data()).await else {
                return Err(StatusCode::REQUEST_TIMEOUT);
            };
            match received {
                Ok(Some(mut chunk)) => {
                    while chunk.has_remaining() {
                        let data = chunk.chunk();
                        if body_vec.len().saturating_add(data.len()) > limit {
                            return Err(over_limit);
                        }
                        body_vec.extend_from_slice(data);
                        let len = data.len();
                        chunk.advance(len);
                        deadline = deadline
                            .checked_add(body_time_earned(len))
                            .unwrap_or(deadline);
                    }
                }
                Ok(None) => break,
                Err(_) => return Err(StatusCode::BAD_REQUEST),
            }
        }
        if content_length.is_some_and(|declared| body_vec.len() != declared) {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(Bytes::from(body_vec))
    }

    async fn handle_h3_request(
        self: Arc<Self>,
        resolver: tachyon_quic::h3::server::RequestResolver<tachyon_quic::Connection, Bytes>,
        origin: Origin,
    ) {
        let resolve_res = tokio::time::timeout(REQUEST_TIMEOUT, resolver.resolve_request()).await;

        let Ok(Ok((req, mut stream))) = resolve_res else {
            return;
        };

        // Judged on its head before its body is buffered: a request the policy refuses must not
        // cost up to `max_body_size` of memory first.
        let mut req = req.map(|()| axum::body::Body::empty());
        if let Some(response) = self.reject(&mut req, origin) {
            send_head_only(&mut stream, response.map(|_| ())).await;
            return;
        }
        let (parts, _) = req.into_parts();

        let body_bytes = match self.read_h3_body(&parts, &mut stream).await {
            Ok(bytes) => bytes,
            Err(status) => {
                let mut response = Response::builder()
                    .status(status)
                    .body(())
                    .unwrap_or_else(|_| Response::new(()));
                self.finalize(&mut response, origin);
                send_head_only(&mut stream, response).await;
                return;
            }
        };

        let req = Request::from_parts(parts, axum::body::Body::from(body_bytes));
        let full_resp = self.route(req, origin).await;

        let (resp_parts, body) = full_resp.into_parts();
        let resp = Response::from_parts(resp_parts, ());

        // Each write is bounded, but `body.frame()` deliberately is not: that await is the
        // handler producing data, which an SSE or long-poll route is entitled to sit on
        // indefinitely. Only the *write* is something a peer can stall, by holding its
        // flow-control window shut, and only that needs a deadline.
        if write_within(stream.send_response(resp)).await.is_err() {
            return;
        }
        let mut body = body;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                stream.stop_stream(tachyon_quic::h3::error::Code::H3_INTERNAL_ERROR);
                return;
            };
            let send_res = if let Some(data) = frame.data_ref() {
                write_within(stream.send_data(data.clone())).await
            } else if let Some(trailers) = frame.trailers_ref() {
                write_within(stream.send_trailers(trailers.clone())).await
            } else {
                Ok(())
            };
            if send_res.is_err() {
                return;
            }
        }
        let _ = write_within(stream.finish()).await;
    }
}

// The test client offers neither ML-KEM-1024 nor ML-DSA-87, all a `cnsa` server accepts.
#[cfg(all(test, not(feature = "cnsa")))]
mod tests {
    use crate::Limits;
    use crate::server::shared::Shared;
    use axum::{
        Router,
        routing::{get, post},
    };
    use bytes::{Buf, Bytes};
    use std::sync::Arc;

    async fn hello() -> &'static str {
        "hello from h3"
    }

    async fn echo(body: Bytes) -> Vec<u8> {
        body.to_vec()
    }

    /// Serves `app` over HTTP/3 on loopback (OS-assigned port) with a fresh self-signed
    /// certificate. Returns the bound address and the certificate's PEM for the client.
    fn start_h3_server(
        app: Router<()>,
        limits: Limits,
        hosts: Option<Vec<String>>,
    ) -> (std::net::SocketAddr, String) {
        let tls = crate::tls::Tls::new()
            .domains(["localhost"])
            .self_signed(crate::tls::KeyAlgorithm::EcdsaP256);
        let built = crate::tls::certs::build(
            &tls,
            &crate::tls::TlsPolicy::new(),
            &["localhost".to_string()],
            "https://localhost",
            vec![b"h3".to_vec()],
        )
        .expect("build tls");
        let cert_pem = built
            .store
            .infos()
            .first()
            .map(|info| info.pem.clone())
            .expect("certificate");
        let quic_server =
            super::build_quic_server(built.config, "127.0.0.1:0", limits.max_h3_streams)
                .expect("start quic server");
        let addr = quic_server.local_addr().expect("local addr");

        let (trigger, shutdown) = crate::server::conn::Shutdown::new();
        let shared = Arc::new(Shared::new(
            app,
            limits,
            crate::SecurityPolicy::new(),
            crate::ServerInfo::new(),
            shutdown,
            crate::tls::TlsPolicy::new(),
        ));
        shared.set_hosts(hosts);
        drop(tokio::spawn(async move {
            let _trigger = trigger;
            super::serve_h3(shared, quic_server).await;
        }));

        (addr, cert_pem)
    }

    /// Connects a real HTTP/3 client (over loopback UDP) to `addr`, trusting `cert_pem`. The
    /// returned `JoinHandle` drives the connection's control/QPACK streams in the background —
    /// per `h3::client::Connection`'s own docs, this must stay alive and polled for the
    /// connection to make progress while requests are in flight.
    async fn h3_connect(
        addr: std::net::SocketAddr,
        cert_pem: &str,
    ) -> (
        tachyon_quic::h3::client::SendRequest<tachyon_quic::OpenStreams, Bytes>,
        tokio::task::JoinHandle<()>,
    ) {
        let client_tls = tachyon_quic::s2n_quic::provider::tls::rustls::Client::builder()
            .with_certificate(cert_pem)
            .expect("with_certificate")
            .with_application_protocols(std::iter::once("h3"))
            .expect("with_application_protocols")
            .build()
            .expect("build client tls");
        let client = tachyon_quic::s2n_quic::Client::builder()
            .with_tls(client_tls)
            .expect("with_tls")
            .with_io("127.0.0.1:0")
            .expect("with_io")
            .start()
            .expect("start quic client");

        let quic_conn = client
            .connect(
                tachyon_quic::s2n_quic::client::Connect::new(addr).with_server_name("localhost"),
            )
            .await
            .expect("quic connect");

        let h3_conn = tachyon_quic::Connection::new(quic_conn);
        let (mut driver, send_request) = tachyon_quic::h3::client::new(h3_conn)
            .await
            .expect("h3 client new");
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        (send_request, driver_task)
    }

    /// Reads all remaining `DATA` frames off a response stream into a `Vec<u8>`.
    async fn recv_all<S>(stream: &mut tachyon_quic::h3::client::RequestStream<S, Bytes>) -> Vec<u8>
    where
        S: tachyon_quic::h3::quic::RecvStream,
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
    /// `serve_h3`. Exercises `handle_h3_connection`'s setup and accept loop,
    /// `read_h3_body` for both a bodyless GET and a Content-Length-driven POST, and
    /// `handle_h3_request`'s full response path (`send_response`, the `frame()`/`send_data()`
    /// loop, and `finish()`).
    #[tokio::test]
    async fn h3_get_and_post_round_trip() {
        let app = Router::new()
            .route("/", get(hello))
            .route("/echo", post(echo));
        let (addr, cert_pem) = start_h3_server(app, Limits::default(), None);

        let (mut send_request, driver_task) = h3_connect(addr, &cert_pem).await;

        // GET / — a finished stream with no DATA frames, so `read_h3_body`'s recv loop ends
        // on the first `Ok(None)`.
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

    /// A body that doesn't match its declared `Content-Length` is malformed (RFC 9114 §4.1.2)
    /// and must be rejected in *both* directions.
    ///
    /// Over-sending is the tighter of the two bounds: the declared length caps buffering well
    /// below `max_body_size`, so a client can't declare one byte and then stream megabytes at
    /// the server before the generic limit notices. Under-sending matters for a different
    /// reason — a truncated body used to reach the handler silently, looking like a short but
    /// perfectly well-formed request, where HTTP/1.1 and HTTP/2 both fail it at the framing
    /// layer.
    #[tokio::test]
    async fn h3_content_length_mismatch_is_rejected_in_both_directions() {
        let app = Router::new().route("/echo", post(echo));
        // Generous body limit, so it's the declared length doing the rejecting, not `413`.
        let (addr, cert_pem) =
            start_h3_server(app, Limits::default().max_body_size(1024 * 1024), None);

        let (mut send_request, driver_task) = h3_connect(addr, &cert_pem).await;

        for (declared, actual) in [(1usize, 4096usize), (4096, 16)] {
            let req = hyper::Request::builder()
                .method("POST")
                .uri("https://localhost/echo")
                .header(hyper::header::CONTENT_LENGTH, declared)
                .body(())
                .expect("build POST request");
            let mut stream = send_request
                .send_request(req)
                .await
                .expect("send POST request");
            stream
                .send_data(Bytes::from(vec![b'x'; actual]))
                .await
                .expect("send POST body");
            stream.finish().await.expect("finish POST request stream");

            let response = stream.recv_response().await.expect("recv response");
            assert_eq!(
                response.status(),
                hyper::StatusCode::BAD_REQUEST,
                "declared {declared}, sent {actual}"
            );
        }

        drop(send_request);
        driver_task.abort();
    }

    /// The happy path the check above must not break: a body whose length matches its declared
    /// `Content-Length` exactly still round-trips.
    #[tokio::test]
    async fn h3_exact_content_length_still_round_trips() {
        let app = Router::new().route("/echo", post(echo));
        let (addr, cert_pem) = start_h3_server(app, Limits::default(), None);

        let (mut send_request, driver_task) = h3_connect(addr, &cert_pem).await;

        let payload = vec![b'z'; 4096];
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
            .send_data(Bytes::from(payload.clone()))
            .await
            .expect("send POST body");
        stream.finish().await.expect("finish POST request stream");

        let response = stream.recv_response().await.expect("recv response");
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert_eq!(recv_all(&mut stream).await, payload);

        drop(send_request);
        driver_task.abort();
    }

    /// A POST body exceeding `max_body_size` — covers the `PAYLOAD_TOO_LARGE` branch in
    /// `read_h3_body`'s `recv_data` loop.
    #[tokio::test]
    async fn h3_post_over_max_body_size_is_rejected() {
        let app = Router::new().route("/echo", post(echo));
        let (addr, cert_pem) = start_h3_server(app, Limits::default().max_body_size(8), None);

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

    /// A refused request is answered from its head alone. The body is declared but never sent,
    /// so a server that buffered it first would sit out the body deadline and answer `408`.
    #[tokio::test]
    async fn h3_policy_rejects_before_reading_the_body() {
        let app = Router::new().route("/echo", post(echo));
        let hosts = Some(vec!["example.invalid".to_string()]);
        let (addr, cert_pem) = start_h3_server(app, Limits::default(), hosts);
        let (mut send_request, driver_task) = h3_connect(addr, &cert_pem).await;

        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://localhost/echo")
            .header(hyper::header::CONTENT_LENGTH, 4096)
            .body(())
            .expect("build POST request");
        let mut stream = send_request
            .send_request(req)
            .await
            .expect("send POST request");

        let response =
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv_response())
                .await
                .expect("answered without waiting for the body")
                .expect("recv response");
        assert_eq!(response.status(), hyper::StatusCode::MISDIRECTED_REQUEST);

        drop(send_request);
        driver_task.abort();
    }
}
