#[cfg(feature = "tls")]
use crate::server::TLS_HANDSHAKE_TIMEOUT;
use crate::server::accept::ConnectionLimit;
#[cfg(feature = "http1")]
use crate::server::tuning::tune_http1;
#[cfg(feature = "http2")]
use crate::server::tuning::tune_http2;
use crate::server::{REQUEST_TIMEOUT, Server};
use axum::body::Body;
use axum::response::IntoResponse as _;
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
    /// Bounds how long a request body may take to arrive in full.
    ///
    /// Bodies stream lazily, so without this a client could send headers declaring a
    /// `Content-Length` and then never send the body, holding the connection open
    /// indefinitely against a handler that never reads it.
    ///
    /// The `Sleep` is allocated on first poll rather than per request: hyper checks
    /// `is_end_stream()` before polling a body it knows is empty, so an eager timer would be
    /// registered and dropped unused on every bodyless GET.
    struct DeadlineBody {
        #[pin]
        inner: hyper::body::Incoming,
        deadline: Option<Pin<Box<tokio::time::Sleep>>>,
        remaining: usize,
        failed: bool,
    }
}

impl HyperBody for DeadlineBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if *this.failed {
            return Poll::Ready(None);
        }
        let deadline = this
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(REQUEST_TIMEOUT)));
        if deadline.as_mut().poll(cx).is_ready() {
            *this.failed = true;
            return Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out reading request body",
            )))));
        }
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let Some(remaining) = this.remaining.checked_sub(data.len()) else {
                        *this.failed = true;
                        return Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "request body exceeds configured limit",
                        )))));
                    };
                    *this.remaining = remaining;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(axum::Error::new(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Backoff after an accept failed because *this* process is out of descriptors or memory —
/// short, because the condition often clears as in-flight connections close.
const ACCEPT_EXHAUSTION_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);
/// Backoff after any other accept failure. Longer, because a listener failing for a reason
/// that isn't resource pressure is usually broken for good and retrying it is pointless —
/// matching the free-standing `serve()` path's own accept backoff in `listener.rs`.
const ACCEPT_FAULT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// Accepts the next connection, retrying until one arrives.
///
/// A failed accept is logged (and, on resource exhaustion, briefly backed off) and then
/// retried, so a single bad connection never tears the listener down. It never gives up,
/// which is what lets a caller looping on
/// [`ConnectionLimit::acquire`](crate::server::accept::ConnectionLimit::acquire)'s `None` treat
/// that as the only reason to stop.
pub(super) async fn accept_forever(
    listener: &TcpListener,
    log_tag: &str,
) -> (tokio::net::TcpStream, std::net::SocketAddr) {
    loop {
        if let Some(conn) = accept_tuned(listener, log_tag).await {
            return conn;
        }
    }
}

/// Accepts one connection, applying the socket tuning shared by every transport.
///
/// Returns `None` after logging (and, on resource exhaustion, briefly backing off) when the
/// accept failed.
async fn accept_tuned(
    listener: &TcpListener,
    log_tag: &str,
) -> Option<(tokio::net::TcpStream, std::net::SocketAddr)> {
    match listener.accept().await {
        Ok((stream, peer)) => {
            crate::server::accept::tune_tcp_stream(&stream);
            Some((stream, peer))
        }
        Err(e) => {
            if crate::server::accept::is_connection_error(&e) {
                // The peer vanished before we got to it — routine, and remote-triggerable, so
                // it must not reach `error!`. No backoff either: these consume one queued
                // connection each, so the loop can't spin on them.
                crate::telemetry_debug!("[{log_tag}] accept error: {e}");
                return None;
            }
            crate::telemetry_error!("[{log_tag}] accept error: {e}");
            // Everything else fails again immediately on retry, so without a pause
            // `accept_forever` would spin a core flat and flood the log for as long as the
            // condition lasts.
            let backoff = if crate::server::is_resource_exhaustion(&e) {
                ACCEPT_EXHAUSTION_BACKOFF
            } else {
                ACCEPT_FAULT_BACKOFF
            };
            tokio::time::sleep(backoff).await;
            None
        }
    }
}

/// Spawns a per-connection task on the current Tokio runtime.
pub(super) fn spawn_connection<F>(fut: F)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    drop(tokio::spawn(fut));
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
        spawn_connection(fut);
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

        // Build once outside the loop — `clone()` inside is a few pointer copies.
        // Three cases, matching whichever of `http1`/`http2` are enabled (at least
        // one always is — see the crate-level `compile_error!` in `lib.rs`):
        #[cfg(all(feature = "http1", feature = "http2"))]
        let builder = {
            // Both enabled: `auto::Builder` sniffs each connection's first bytes
            // for the HTTP/2 client preface and falls back to HTTP/1.1 otherwise.
            let mut b = hyper_util::server::conn::auto::Builder::new(LocalExecutor);
            tune_http1!(b.http1());
            let _ = b.http1().writev(true);
            tune_http2!(b.http2());
            b
        };
        #[cfg(all(feature = "http1", not(feature = "http2")))]
        let builder = {
            // http1 only: the low-level builder directly, no protocol-sniffing overhead.
            let mut b = hyper::server::conn::http1::Builder::new();
            tune_http1!(b);
            let _ = b.writev(true);
            b
        };
        #[cfg(all(feature = "http2", not(feature = "http1")))]
        let builder = {
            // http2 only: h2c with no HTTP/1.1 fallback at all — a client that
            // isn't speaking HTTP/2 with prior knowledge simply fails to connect.
            let mut b = hyper::server::conn::http2::Builder::new(LocalExecutor);
            tune_http2!(b);
            b
        };

        let limit = state.connection_limit.clone();
        while let Some(permit) = limit.acquire().await {
            let (stream, peer) = accept_forever(&listener, "http").await;
            let state = state.clone();
            let builder = builder.clone();

            ConnectionLimit::serve(permit, async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = service_fn(move |req| hyper_handler(state.clone(), req, peer, false));
                #[cfg(all(feature = "http1", feature = "http2"))]
                let result = builder.serve_connection_with_upgrades(io, svc).await;
                #[cfg(all(feature = "http1", not(feature = "http2")))]
                let result = builder.serve_connection(io, svc).with_upgrades().await;
                #[cfg(all(feature = "http2", not(feature = "http1")))]
                let result = builder.serve_connection(io, svc).await;
                if let Err(e) = result {
                    crate::telemetry_debug!("[http] connection error: {}", e);
                }
            });
        }
        Ok(())
    }

    /// Serve HTTP/1.1 and HTTP/2 over TLS (HTTPS) on the given listener and acceptor.
    ///
    /// # Errors
    ///
    /// Returns an error if FIPS compliance enforcement fails, or — under the `fips` feature —
    /// if `acceptor`'s `rustls::ServerConfig` doesn't itself negotiate FIPS-approved
    /// algorithms (see `assert_fips_server_config`; this catches a config
    /// built without going through [`TlsPolicy`](crate::tls::TlsPolicy)). Per-connection I/O
    /// errors (accept failures, handshake failures, etc.) are logged and do not terminate the
    /// accept loop.
    #[cfg(feature = "tls")]
    pub async fn serve_https(
        self,
        listener: TcpListener,
        acceptor: TlsAcceptor,
    ) -> Result<(), std::io::Error> {
        #[cfg(feature = "cnsa")]
        if !self.cnsa_identity_verified {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "CNSA mode refuses an opaque caller-supplied TLS config because its certificate identity cannot be verified",
            ));
        }
        crate::server::enforce_fips_compliance()?;
        #[cfg(feature = "fips")]
        crate::server::assert_fips_server_config(acceptor.config())?;
        let state = Arc::new(self);
        let limit = state.connection_limit.clone();
        while let Some(permit) = limit.acquire().await {
            let (tcp_stream, peer) = accept_forever(&listener, "https").await;
            let acceptor = acceptor.clone();
            let state = state.clone();

            ConnectionLimit::serve(permit, async move {
                let Ok(_handshake_permit) = state.tls_handshake_limit.clone().try_acquire_owned()
                else {
                    crate::telemetry_debug!("[https] tls handshake shed at concurrency limit");
                    return;
                };
                let tls_stream =
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream))
                        .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            crate::telemetry_debug!("[https] tls handshake error: {}", e);
                            return;
                        }
                        Err(_) => {
                            crate::telemetry_debug!("[https] tls handshake timed out");
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
                let svc = service_fn(move |req| hyper_handler(state.clone(), req, peer, true));

                #[cfg(feature = "http2")]
                if is_h2 {
                    // Use low-level HTTP/2 connection builder
                    let mut builder = hyper::server::conn::http2::Builder::new(LocalExecutor);
                    tune_http2!(builder);
                    if let Err(e) = builder.serve_connection(io, svc).await {
                        crate::telemetry_debug!("[https] http/2 connection error: {}", e);
                    }
                    // Skips the HTTP/1.1 fallback below, which only exists under `http1` —
                    // so without that feature there is nothing to skip and the `return` is
                    // the function's own tail, which `-D warnings` rejects.
                    #[cfg(feature = "http1")]
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
                    tune_http1!(builder);
                    if let Err(e) = builder.serve_connection(io, svc).with_upgrades().await {
                        crate::telemetry_debug!("[https] http/1.1 connection error: {}", e);
                    }
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
        let acceptor = TlsAcceptor::from(self.finalize_tls_config(config));
        self.serve_https(listener, acceptor).await
    }
}

/// Wraps an inbound request body in the shared read deadline.
///
/// Every entry point that hands a body to user code must go through here. Without it a peer
/// can send complete headers declaring a body and then dribble it forever, pinning a
/// connection permit for as long as it likes — `serve()` used to map `Incoming` straight into
/// a `Body`, and so had no body-read timeout at all.
pub(super) fn body_with_deadline(incoming: hyper::body::Incoming, max_body_size: usize) -> Body {
    if HyperBody::is_end_stream(&incoming) {
        Body::empty()
    } else {
        Body::new(DeadlineBody {
            inner: incoming,
            deadline: None,
            remaining: max_body_size,
            failed: false,
        })
    }
}

pub(super) async fn hyper_handler<S>(
    state: Arc<Server<S>>,
    req: Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    secure_transport: bool,
) -> Result<Response<Body>, std::io::Error>
where
    S: Clone + Send + Sync + 'static,
{
    let (parts, incoming_body) = req.into_parts();
    if incoming_body
        .size_hint()
        .upper()
        .is_some_and(|size| u64::try_from(state.max_body_size).is_ok_and(|limit| size > limit))
    {
        // Still goes through the policy: this early return is a response like any other, and
        // skipping it would leave the one reply a peer can trigger cheapest as the only one
        // without `nosniff`/HSTS and with whatever `Server` header the stack added.
        let mut response = (hyper::StatusCode::PAYLOAD_TOO_LARGE, Body::empty()).into_response();
        state
            .security_policy
            .finalize_response(&mut response, secure_transport);
        return Ok(response);
    }
    let body = body_with_deadline(incoming_body, state.max_body_size);

    Ok(state
        .dispatch(Request::from_parts(parts, body), peer, secure_transport)
        .await)
}
