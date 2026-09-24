#[cfg(feature = "tls")]
use crate::server::TLS_HANDSHAKE_TIMEOUT;
use crate::server::accept::ConnectionLimit;
use crate::server::stall::WriteDeadline;
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
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use tokio::net::TcpListener;
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;

/// The slowest a request body may arrive once [`REQUEST_TIMEOUT`]'s grace period is spent.
const MIN_BODY_RATE: u64 = 16 * 1024;
const BODY_ACTIVE: u8 = 0;
const BODY_COMPLETE: u8 = 1;
const BODY_FAILED: u8 = 2;

/// Extra time a body earns by delivering `bytes`, at [`MIN_BODY_RATE`].
///
/// A fixed window failed every upload slower than `max_body_size / 30s`; a bare per-chunk
/// timeout would let a peer drip one byte just under it forever. Earning time per byte asks
/// for a floor rate instead — shared with HTTP/3's body reader.
pub(super) fn body_time_earned(bytes: usize) -> std::time::Duration {
    let micros = u64::try_from(bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(1_000_000)
        .saturating_div(MIN_BODY_RATE);
    std::time::Duration::from_micros(micros)
}

pin_project_lite::pin_project! {
    /// Bounds how long a request body may take to arrive: [`REQUEST_TIMEOUT`] of grace, plus
    /// whatever [`body_time_earned`] grants for each chunk received.
    ///
    /// Bodies stream lazily, so without this a client could send headers declaring a
    /// `Content-Length` and then never send the body, holding the connection open
    /// indefinitely against a handler that never reads it.
    ///
    /// The `Sleep` is allocated on first poll rather than per request: hyper checks
    /// `is_end_stream()` before polling a body it knows is empty, so an eager timer would be
    /// registered and dropped unused on every bodyless GET.
    struct DeadlineBody<B> {
        #[pin]
        inner: B,
        deadline: Option<Pin<Box<tokio::time::Sleep>>>,
        remaining: usize,
        failed: bool,
        status: Arc<AtomicU8>,
    }
}

impl<B> DeadlineBody<B> {
    const fn new(inner: B, max_body_size: usize, status: Arc<AtomicU8>) -> Self {
        Self {
            inner,
            deadline: None,
            remaining: max_body_size,
            failed: false,
            status,
        }
    }
}

impl<B> HyperBody for DeadlineBody<B>
where
    B: HyperBody<Data = Bytes>,
    B::Error: Into<axum::BoxError>,
{
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
            this.status.store(BODY_FAILED, Ordering::Release);
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
                        this.status.store(BODY_FAILED, Ordering::Release);
                        return Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "request body exceeds configured limit",
                        )))));
                    };
                    *this.remaining = remaining;
                    let extended = deadline
                        .deadline()
                        .checked_add(body_time_earned(data.len()));
                    if let Some(extended) = extended {
                        deadline.as_mut().reset(extended);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.status.store(BODY_FAILED, Ordering::Release);
                Poll::Ready(Some(Err(axum::Error::new(e))))
            }
            Poll::Ready(None) => {
                this.status.store(BODY_COMPLETE, Ordering::Release);
                Poll::Ready(None)
            }
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
/// that isn't resource pressure is usually broken for good.
const ACCEPT_FAULT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// Accepts the next connection, retrying until one arrives.
///
/// A failed accept is logged (and backed off) and then retried, so a single bad connection
/// never tears the listener down.
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

impl Server {
    /// Serve HTTP/1.1 over plaintext TCP on the given listener — plus HTTP/2 over cleartext
    /// ("h2c", detected via the connection preface with no ALPN needed) when the `http2`
    /// feature is on *and* [`SecurityPolicy::allow_h2c`](crate::server::SecurityPolicy::allow_h2c)
    /// is set. With h2c off (the default) the HTTP/2 stack isn't reachable on this port at all.
    ///
    /// h2c has no browser support but is what gRPC, `curl --http2-prior-knowledge` and most
    /// service meshes speak when TLS is terminated upstream.
    ///
    /// Serves until the future is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error only if FIPS compliance enforcement fails. Per-connection errors are
    /// logged and never end the accept loop.
    pub async fn serve_http(self, listener: TcpListener) -> Result<(), std::io::Error> {
        crate::server::enforce_fips_compliance()?;
        let state = Arc::new(self);

        // Built once and cloned per connection. At least one of `http1`/`http2` is always on.
        #[cfg(feature = "http1")]
        let http1 = {
            let mut b = hyper::server::conn::http1::Builder::new();
            tune_http1!(b);
            let _ = b.writev(true);
            b
        };
        // HTTP/2 here only when h2c is allowed, so otherwise its parser isn't reachable at all.
        // A separate builder rather than `auto`'s `http1_only`, which
        // `serve_connection_with_upgrades` ignores.
        #[cfg(all(feature = "http1", feature = "http2"))]
        let auto = state.security_policy.allows_h2c().then(|| {
            let mut b =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            tune_http1!(b.http1());
            let _ = b.http1().writev(true);
            tune_http2!(b.http2());
            b
        });
        #[cfg(all(feature = "http2", not(feature = "http1")))]
        let http2 = {
            // No HTTP/1.1 fallback: only prior-knowledge HTTP/2 clients can connect.
            let mut b =
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
            tune_http2!(b);
            b
        };

        let limit = state.connection_limit.clone();
        loop {
            let (stream, peer) = accept_forever(&listener, "http").await;
            let permit = limit.acquire().await;
            let state = state.clone();
            #[cfg(feature = "http1")]
            let http1 = http1.clone();
            #[cfg(all(feature = "http1", feature = "http2"))]
            let auto = auto.clone();
            #[cfg(all(feature = "http2", not(feature = "http1")))]
            let http2 = http2.clone();

            ConnectionLimit::serve(permit, async move {
                let io = hyper_util::rt::TokioIo::new(WriteDeadline::new(stream));
                let svc =
                    service_fn(move |req| hyper_handler(state.clone(), req, Some(peer), false));
                #[cfg(all(feature = "http1", feature = "http2"))]
                let result = match auto {
                    Some(auto) => auto.serve_connection_with_upgrades(io, svc).await,
                    None => http1
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await
                        .map_err(Into::into),
                };
                #[cfg(all(feature = "http1", not(feature = "http2")))]
                let result = http1.serve_connection(io, svc).with_upgrades().await;
                #[cfg(all(feature = "http2", not(feature = "http1")))]
                let result = http2.serve_connection(io, svc).await;
                if let Err(e) = result {
                    crate::telemetry_debug!("[http] connection error: {}", e);
                }
            });
        }
    }

    /// Serve HTTP/1.1 and HTTP/2 over TLS (HTTPS) on the given listener and acceptor, until
    /// the future is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error only at startup: if FIPS compliance enforcement fails, if under `fips`
    /// `acceptor`'s config offers non-approved algorithms, or if under `cnsa` the config's
    /// certificate identity wasn't verified by this crate. Per-connection errors are logged
    /// and never end the accept loop.
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
        loop {
            let (tcp_stream, peer) = accept_forever(&listener, "https").await;
            let permit = limit.acquire().await;
            let acceptor = acceptor.clone();
            let state = state.clone();

            ConnectionLimit::serve(permit, async move {
                let Ok(handshake_permit) = state.tls_handshake_limit.clone().try_acquire_owned()
                else {
                    crate::telemetry_debug!("[https] tls handshake shed at concurrency limit");
                    return;
                };
                let tls_stream = match tokio::time::timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    acceptor.accept(WriteDeadline::new(tcp_stream)),
                )
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
                drop(handshake_permit);

                #[cfg(feature = "http2")]
                let is_h2 = {
                    let (_, connection) = tls_stream.get_ref();
                    connection.alpn_protocol() == Some(b"h2")
                };

                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc =
                    service_fn(move |req| hyper_handler(state.clone(), req, Some(peer), true));

                #[cfg(feature = "http2")]
                if is_h2 {
                    let mut builder = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    tune_http2!(builder);
                    if let Err(e) = builder.serve_connection(io, svc).await {
                        crate::telemetry_debug!("[https] http/2 connection error: {}", e);
                    }
                    // Without `http1` this is already the tail, and a `return` would be flagged.
                    #[cfg(feature = "http1")]
                    return;
                }

                // Without `http1`, ALPN only offered "h2", so a non-h2 peer is simply dropped.
                #[cfg(feature = "http1")]
                {
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    tune_http1!(builder);
                    if let Err(e) = builder.serve_connection(io, svc).with_upgrades().await {
                        crate::telemetry_debug!("[https] http/1.1 connection error: {}", e);
                    }
                }
            });
        }
    }

    /// [`serve_https`](Self::serve_https) with a `rustls::ServerConfig`, after applying this
    /// server's [`TlsPolicy`](crate::tls::TlsPolicy).
    ///
    /// # Errors
    ///
    /// Same as [`serve_https`](Self::serve_https).
    #[cfg(feature = "tls")]
    pub async fn serve_https_config(
        self,
        listener: TcpListener,
        config: rustls::ServerConfig,
    ) -> Result<(), std::io::Error> {
        let acceptor = TlsAcceptor::from(self.finalize_tls_config(config));
        self.serve_https(listener, acceptor).await
    }
}

/// Wraps an inbound request body in the shared read deadline.
///
/// Every entry point that hands a body to user code must go through here. Without it a peer
/// can send complete headers declaring a body and then dribble it forever, pinning a
/// connection permit for as long as it likes.
fn body_with_deadline(
    incoming: hyper::body::Incoming,
    max_body_size: usize,
) -> (Body, Option<Arc<AtomicU8>>) {
    if HyperBody::is_end_stream(&incoming) {
        (Body::empty(), None)
    } else {
        let status = Arc::new(AtomicU8::new(BODY_ACTIVE));
        (
            Body::new(DeadlineBody::new(incoming, max_body_size, status.clone())),
            Some(status),
        )
    }
}

pub(super) async fn hyper_handler(
    state: Arc<Server>,
    req: Request<hyper::body::Incoming>,
    peer: Option<std::net::SocketAddr>,
    secure_transport: bool,
) -> Result<Response<Body>, std::io::Error> {
    let (parts, incoming_body) = req.into_parts();
    if incoming_body.size_hint().upper().is_some_and(|size| {
        u64::try_from(state.limits.max_body_size).is_ok_and(|limit| size > limit)
    }) {
        // Still goes through the policy: this early return is a response like any other, and
        // skipping it would leave the one reply a peer can trigger cheapest as the only one
        // without `nosniff`/HSTS and with whatever `Server` header the stack added.
        let mut response = (hyper::StatusCode::PAYLOAD_TOO_LARGE, Body::empty()).into_response();
        state
            .security_policy
            .finalize_response(&mut response, secure_transport);
        if matches!(
            parts.version,
            hyper::Version::HTTP_10 | hyper::Version::HTTP_11
        ) && !incoming_body.is_end_stream()
        {
            let _ = response.headers_mut().insert(
                hyper::header::CONNECTION,
                hyper::header::HeaderValue::from_static("close"),
            );
        }
        return Ok(response);
    }
    let is_http1 = matches!(
        parts.version,
        hyper::Version::HTTP_10 | hyper::Version::HTTP_11
    );
    let (body, body_status) = body_with_deadline(incoming_body, state.limits.max_body_size);

    let mut response = state
        .dispatch(Request::from_parts(parts, body), peer, secure_transport)
        .await;
    if is_http1 && body_status.is_some_and(|status| status.load(Ordering::Acquire) != BODY_COMPLETE)
    {
        let _ = response.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{BODY_ACTIVE, DeadlineBody, REQUEST_TIMEOUT, body_time_earned};
    use bytes::Bytes;
    use http_body_util::{BodyExt as _, StreamBody};
    use hyper::body::Frame;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU8;
    use std::time::Duration;

    /// An upload that keeps a floor rate outlives the old fixed 30s window; one that stalls is
    /// still cut off once the time it earned runs out.
    #[tokio::test(start_paused = true)]
    async fn a_body_earns_time_for_every_byte_it_delivers() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(1);
        let mut body = DeadlineBody::new(
            StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)),
            usize::MAX,
            Arc::new(AtomicU8::new(BODY_ACTIVE)),
        );
        let gap = REQUEST_TIMEOUT.saturating_sub(Duration::from_secs(5));
        let mut chunk_len = 1;
        while body_time_earned(chunk_len) < gap {
            chunk_len = chunk_len.saturating_mul(2);
        }

        for _ in 0..3 {
            tx.send(Ok(Frame::data(Bytes::from(vec![0; chunk_len]))))
                .await
                .expect("body is listening");
            assert!(body.frame().await.expect("frame").is_ok());
            tokio::time::advance(gap).await;
        }

        let stalled = body.frame().await.expect("deadline fires");
        assert!(stalled.is_err());
    }
}
