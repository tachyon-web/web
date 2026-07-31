use crate::http::response::Body;
#[cfg(feature = "tls")]
use crate::server::TLS_HANDSHAKE_TIMEOUT;
use crate::server::{IS_LOCAL_WORKER, REQUEST_TIMEOUT, Server};
use bytes::Bytes;
use hyper::body::{Body as HyperBody, Frame, SizeHint};
use hyper::service::service_fn;
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpListener;
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;

pin_project_lite::pin_project! {
    /// Wraps an incoming request body with an absolute deadline for fully reading it.
    ///
    /// Bodies are streamed lazily now (see `hyper_handler`), so a handler that never
    /// touches the body (e.g. an arity-0 route) would otherwise never be bounded by any
    /// timeout — the client could send headers, declare a `Content-Length`, and simply
    /// never send the body, holding the connection open indefinitely. This restores the
    /// same bound `REQUEST_TIMEOUT` previously enforced by eager buffering, without
    /// requiring anything to actually poll the body for it to apply.
    ///
    /// The `Sleep` itself is only allocated the first time `poll_frame` is actually
    /// called, not eagerly per request: hyper's connection driver checks
    /// `is_end_stream()` (forwarded straight to `inner`, below) before ever polling a
    /// body it already knows is empty (e.g. any GET with no `Content-Length`), so an
    /// eagerly-constructed timer would be registered and dropped unpolled on every
    /// such request — a real timer-wheel allocation wasted on the single most common
    /// request shape. Deferring construction to first poll costs nothing: a body that's
    /// never polled was never at risk of stalling in the first place.
    struct DeadlineBody {
        #[pin]
        inner: hyper::body::Incoming,
        deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    }
}

impl HyperBody for DeadlineBody {
    type Data = Bytes;
    type Error = crate::http::error::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let deadline = this
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(REQUEST_TIMEOUT)));
        if deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(crate::http::error::Error::Rejection {
                status: hyper::StatusCode::REQUEST_TIMEOUT,
                message: "Timed out reading request body".to_string(),
            })));
        }
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(feature = "http2")]
#[derive(Clone, Copy, Debug)]
struct LocalExecutor;

#[cfg(feature = "http2")]
impl<F> hyper::rt::Executor<F> for LocalExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        IS_LOCAL_WORKER.with(|flag| {
            if flag.get() {
                drop(tokio::task::spawn_local(fut));
            } else {
                drop(tokio::spawn(fut));
            }
        });
    }
}

impl<S> Server<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Serve HTTP/1.1 (and, with the `http2` feature, HTTP/2 over cleartext —
    /// "h2c", detected via the connection preface with no ALPN needed) over
    /// plaintext TCP on the given listener.
    ///
    /// Without the `http2` feature this uses `hyper::server::conn::http1::Builder`
    /// directly — no protocol sniffing, no `auto` dispatch overhead. With it, it
    /// uses `hyper_util`'s `auto::Builder`, which peeks at the first bytes of each
    /// connection to detect an HTTP/2 client connection preface and falls back to
    /// HTTP/1.1 otherwise. Either builder is constructed once and cloned per
    /// connection (cheap: only pointer-sized fields).
    ///
    /// h2c has no browser support (browsers only ever negotiate HTTP/2 via TLS
    /// ALPN) but is exactly what most non-browser HTTP/2 clients (gRPC, `curl
    /// --http2-prior-knowledge`, many internal service meshes) expect when TLS is
    /// terminated upstream (e.g. behind a load balancer) or simply not wanted.
    ///
    /// # Errors
    ///
    /// Returns an error if FIPS compliance enforcement fails. Per-connection I/O
    /// errors (accept failures, handshake failures, etc.) are logged and do not
    /// terminate the accept loop.
    pub async fn serve_http(self, listener: TcpListener) -> Result<(), std::io::Error> {
        crate::server::enforce_fips_compliance()?;
        let state = Arc::new(self);
        let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(state.max_connections));

        // Build once outside the loop — `clone()` inside is a few pointer copies.
        // Three cases, matching whichever of `http1`/`http2` are enabled (at least
        // one always is — see the crate-level `compile_error!` in `lib.rs`):
        #[cfg(all(feature = "http1", feature = "http2"))]
        let builder = {
            // Both enabled: `auto::Builder` sniffs each connection's first bytes
            // for the HTTP/2 client preface and falls back to HTTP/1.1 otherwise.
            let mut b = hyper_util::server::conn::auto::Builder::new(LocalExecutor);
            let _ = b
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(REQUEST_TIMEOUT)
                .keep_alive(true)
                .max_buf_size(8192)
                .writev(true);
            let _ = b
                .http2()
                .timer(hyper_util::rt::TokioTimer::new())
                .initial_stream_window_size(65535)
                .initial_connection_window_size(1024 * 1024)
                .max_frame_size(16384)
                .max_concurrent_streams(200)
                .keep_alive_timeout(REQUEST_TIMEOUT);
            // RFC 8441: let `ws::WebSocketUpgrade` accept WebSocket-over-HTTP/2 requests.
            #[cfg(feature = "ws")]
            let _ = b.http2().enable_connect_protocol();
            b
        };
        #[cfg(all(feature = "http1", not(feature = "http2")))]
        let builder = {
            // http1 only: the low-level builder directly, no protocol-sniffing overhead.
            let mut b = hyper::server::conn::http1::Builder::new();
            let _ = b
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(REQUEST_TIMEOUT)
                .keep_alive(true)
                .max_buf_size(8192)
                .writev(true);
            b
        };
        #[cfg(all(feature = "http2", not(feature = "http1")))]
        let builder = {
            // http2 only: h2c with no HTTP/1.1 fallback at all — a client that
            // isn't speaking HTTP/2 with prior knowledge simply fails to connect.
            let mut b = hyper::server::conn::http2::Builder::new(LocalExecutor);
            let _ = b
                .timer(hyper_util::rt::TokioTimer::new())
                .initial_stream_window_size(65535)
                .initial_connection_window_size(1024 * 1024)
                .max_frame_size(16384)
                .max_concurrent_streams(200)
                .keep_alive_timeout(REQUEST_TIMEOUT);
            #[cfg(feature = "ws")]
            let _ = b.enable_connect_protocol();
            b
        };

        loop {
            let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
                break;
            };

            let (stream, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    drop(permit);
                    tracing::error!("[http] Accept error: {}", e);
                    if crate::server::is_resource_exhaustion(&e) {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            #[cfg(target_os = "linux")]
            {
                let sock_ref = socket2::SockRef::from(&stream);
                let _ = sock_ref.set_tcp_quickack(true);
            }
            let state = state.clone();
            let builder = builder.clone();

            let serve_fut = async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = service_fn(move |req| hyper_handler(state.clone(), req, peer));
                #[cfg(all(feature = "http1", feature = "http2"))]
                let result = builder.serve_connection_with_upgrades(io, svc).await;
                #[cfg(all(feature = "http1", not(feature = "http2")))]
                let result = builder.serve_connection(io, svc).with_upgrades().await;
                #[cfg(all(feature = "http2", not(feature = "http1")))]
                let result = builder.serve_connection(io, svc).await;
                if let Err(e) = result {
                    tracing::debug!("[http] Connection error: {}", e);
                }
                drop(permit);
            };

            IS_LOCAL_WORKER.with(|flag| {
                if flag.get() {
                    drop(tokio::task::spawn_local(serve_fut));
                } else {
                    drop(tokio::spawn(serve_fut));
                }
            });
        }
        Ok(())
    }

    /// Serve HTTP/1.1 and HTTP/2 over TLS (HTTPS) on the given listener and acceptor.
    ///
    /// # Errors
    ///
    /// Returns an error if FIPS compliance enforcement fails. Per-connection I/O
    /// errors (accept failures, handshake failures, etc.) are logged and do not
    /// terminate the accept loop.
    #[cfg(feature = "tls")]
    pub async fn serve_https(
        self,
        listener: TcpListener,
        acceptor: TlsAcceptor,
    ) -> Result<(), std::io::Error> {
        crate::server::enforce_fips_compliance()?;
        let state = Arc::new(self);
        let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(state.max_connections));

        loop {
            let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
                break;
            };

            let (tcp_stream, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    drop(permit);
                    tracing::error!("[https] Accept error: {}", e);
                    if crate::server::is_resource_exhaustion(&e) {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    continue;
                }
            };
            let _ = tcp_stream.set_nodelay(true);
            #[cfg(target_os = "linux")]
            {
                let sock_ref = socket2::SockRef::from(&tcp_stream);
                let _ = sock_ref.set_tcp_quickack(true);
            }
            let acceptor = acceptor.clone();
            let state = state.clone();

            let serve_fut = async move {
                let tls_stream =
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream))
                        .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            tracing::debug!("[https] TLS handshake error: {}", e);
                            drop(permit);
                            return;
                        }
                        Err(_) => {
                            tracing::debug!("[https] TLS handshake timed out");
                            drop(permit);
                            return;
                        }
                    };

                // Inspect TLS connection ALPN before consuming the stream.
                // Copy bytes out so the borrow ends before the move.
                #[cfg(feature = "http2")]
                let is_h2 = {
                    let (_, connection) = tls_stream.get_ref();
                    connection.alpn_protocol() == Some(b"h2")
                };

                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = service_fn(move |req| hyper_handler(state.clone(), req, peer));

                #[cfg(feature = "http2")]
                if is_h2 {
                    // Use low-level HTTP/2 connection builder
                    let mut builder = hyper::server::conn::http2::Builder::new(LocalExecutor);
                    let _ = builder
                        .timer(hyper_util::rt::TokioTimer::new())
                        .initial_stream_window_size(65535)
                        .initial_connection_window_size(1024 * 1024)
                        .max_frame_size(16384)
                        .max_concurrent_streams(200)
                        .keep_alive_timeout(REQUEST_TIMEOUT);
                    #[cfg(feature = "ws")]
                    let _ = builder.enable_connect_protocol();

                    if let Err(e) = builder.serve_connection(io, svc).await {
                        tracing::debug!("[https] HTTP/2 Connection error: {}", e);
                    }
                    drop(permit);
                    return;
                }

                // Fallback path for a connection that didn't negotiate h2 over ALPN.
                // With the `http1` feature this is the common case (HTTP/1.1 over
                // TLS); without it, ALPN only ever advertised "h2" (see
                // `alpn_protocols` in `server/mod.rs`), so a non-h2 connection here
                // means a non-compliant client picked a protocol we didn't offer —
                // there's no builder to serve it with, so the connection is dropped.
                #[cfg(feature = "http1")]
                {
                    // Use low-level HTTP/1.1 connection builder (bypasses auto-negotiation overhead)
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    let _ = builder
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(REQUEST_TIMEOUT)
                        .keep_alive(true)
                        .max_buf_size(8192);

                    if let Err(e) = builder.serve_connection(io, svc).with_upgrades().await {
                        tracing::debug!("[https] HTTP/1.1 Connection error: {}", e);
                    }
                }
                drop(permit);
            };

            IS_LOCAL_WORKER.with(|flag| {
                if flag.get() {
                    drop(tokio::task::spawn_local(serve_fut));
                } else {
                    drop(tokio::spawn(serve_fut));
                }
            });
        }
        Ok(())
    }

    /// Serve HTTP/1.1 and HTTP/2 over TLS (HTTPS) on the given listener with a custom `rustls::ServerConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if FIPS compliance enforcement fails. Per-connection I/O
    /// errors (accept failures, handshake failures, etc.) are logged and do not
    /// terminate the accept loop.
    #[cfg(feature = "tls")]
    pub async fn serve_https_config(
        self,
        listener: TcpListener,
        config: rustls::ServerConfig,
    ) -> Result<(), std::io::Error> {
        crate::server::enforce_fips_compliance()?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        self.serve_https(listener, acceptor).await
    }
}

pub(super) async fn hyper_handler<S>(
    state: Arc<Server<S>>,
    req: Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
) -> Result<Response<Body>, std::io::Error>
where
    S: Clone + Send + Sync + 'static,
{
    let (parts, incoming_body) = req.into_parts();

    let body = if HyperBody::is_end_stream(&incoming_body) {
        Body::empty()
    } else {
        Body::stream(DeadlineBody {
            inner: incoming_body,
            deadline: None,
        })
    };

    let mut rebuild_req = Request::from_parts(parts, body);
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
        .insert(crate::routing::extract::MaxBodySize(state.max_body_size));

    let resp = state.router.handle_request(rebuild_req).await;

    if let Some((min, max)) = state.response_jitter {
        tokio::time::sleep(crate::server::jittered_delay(min, max)).await;
    }

    Ok(resp)
}
