use crate::server::REQUEST_TIMEOUT;
#[cfg(feature = "tls")]
use crate::server::TLS_HANDSHAKE_TIMEOUT;
use crate::server::accept::ConnectionLimit;
use crate::server::conn::{Shutdown, serve_connection};
use crate::server::shared::{Origin, Shared};
use crate::server::stall::WriteDeadline;
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
pub(crate) fn body_time_earned(bytes: usize) -> std::time::Duration {
    let micros = u64::try_from(bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(1_000_000)
        .saturating_div(MIN_BODY_RATE);
    std::time::Duration::from_micros(micros)
}

pin_project_lite::pin_project! {
    /// Bounds how long a request body may take to arrive: [`REQUEST_TIMEOUT`] of grace, plus
    /// whatever [`body_time_earned`] grants for each chunk received. Also caps its size, with
    /// the same [`LengthLimitError`](http_body_util::LengthLimitError) Axum answers `413` for.
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
        inner: http_body_util::Limited<B>,
        deadline: Option<Pin<Box<tokio::time::Sleep>>>,
        failed: bool,
        status: Arc<AtomicU8>,
    }
}

impl<B> DeadlineBody<B> {
    fn new(inner: B, max_body_size: usize, status: Arc<AtomicU8>) -> Self {
        Self {
            inner: http_body_util::Limited::new(inner, max_body_size),
            deadline: None,
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
    // `Limited`'s own error type, unwrapped: Axum looks through exactly two layers for
    // `LengthLimitError`, and a third would turn the limit's `413` into a `400`.
    type Error = axum::BoxError;

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
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out reading request body",
            )))));
        }
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
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
                *this.failed = true;
                this.status.store(BODY_FAILED, Ordering::Release);
                Poll::Ready(Some(Err(e)))
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

/// Accepts the next connection, retrying until one arrives, or `None` once shutdown is
/// requested — so the listener closes then rather than queueing clients during the drain.
///
/// A failed accept is logged (and backed off) and then retried, so a single bad connection
/// never tears the listener down.
pub(crate) async fn accept_next(
    listener: &TcpListener,
    log_tag: &str,
    shutdown: &Shutdown,
) -> Option<(tokio::net::TcpStream, std::net::SocketAddr)> {
    loop {
        // Biased: with clients queued, an unbiased pick kept accepting during the drain.
        tokio::select! {
            biased;
            () = shutdown.requested() => return None,
            accepted = accept_tuned(listener, log_tag) => if accepted.is_some() {
                return accepted;
            },
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
            // `accept_next` would spin a core flat and flood the log for as long as the
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

/// Serves plaintext HTTP/1.1 on `listener` — plus h2c when
/// [`SecurityPolicy::allow_h2c`](crate::SecurityPolicy::allow_h2c) is set; otherwise the HTTP/2
/// stack isn't reachable on this port at all. Accepts until shutdown.
pub(crate) async fn serve_plain(shared: Arc<Shared>, listener: TcpListener) {
    let http2 = shared.security.allows_h2c();
    loop {
        let Some((stream, peer)) = accept_next(&listener, "http", &shared.shutdown).await else {
            return;
        };
        let permit = shared.connections.acquire().await;
        let shared = shared.clone();
        ConnectionLimit::serve(permit, async move {
            let origin = Origin::plain(Some(peer));
            let handler = shared.clone();
            let svc = service_fn(move |req| hyper_handler(handler.clone(), req, origin));
            let io = WriteDeadline::new(stream);
            if let Err(e) = serve_connection(io, svc, http2, &shared.shutdown).await {
                crate::telemetry_debug!("[http] connection error: {e}");
            }
        });
    }
}

/// Serves HTTPS (HTTP/1.1 and HTTP/2 by ALPN) on `listener`. `h3_port` advertises HTTP/3
/// served beside it. Accepts until shutdown.
#[cfg(feature = "tls")]
pub(crate) async fn serve_tls(
    shared: Arc<Shared>,
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    h3_port: Option<u16>,
) {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let Some((stream, peer)) = accept_next(&listener, "https", &shared.shutdown).await else {
            return;
        };
        let permit = shared.connections.acquire().await;
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        ConnectionLimit::serve(permit, async move {
            let io = WriteDeadline::new(stream);
            let Some(tls) = tls_handshake(&shared, &acceptor, io, TLS_HANDSHAKE_TIMEOUT).await
            else {
                return;
            };
            let origin = Origin {
                peer: Some(peer),
                secure: true,
                h3_port,
            };
            let handler = shared.clone();
            let svc = service_fn(move |req| hyper_handler(handler.clone(), req, origin));
            if let Err(e) = serve_connection(tls, svc, true, &shared.shutdown).await {
                crate::telemetry_debug!("[https] connection error: {e}");
            }
        });
    }
}

/// A TLS handshake bounded in concurrency and time: excess handshakes are shed before any
/// asymmetric crypto runs, and a stalled one gives its connection permit back. Shared by every
/// TLS transport.
#[cfg(feature = "tls")]
pub(crate) async fn tls_handshake<IO>(
    shared: &Shared,
    acceptor: &TlsAcceptor,
    io: IO,
    timeout: std::time::Duration,
) -> Option<tokio_rustls::server::TlsStream<IO>>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Ok(_permit) = shared.tls_handshakes.clone().try_acquire_owned() else {
        crate::telemetry_debug!("[tls] handshake shed at concurrency limit");
        return None;
    };
    match tokio::time::timeout(timeout, acceptor.accept(io)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(e)) => {
            crate::telemetry_debug!("[tls] handshake error: {e}");
            None
        }
        Err(_) => {
            crate::telemetry_debug!("[tls] handshake timed out");
            None
        }
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

pub(crate) async fn hyper_handler(
    state: Arc<Shared>,
    req: Request<hyper::body::Incoming>,
    origin: Origin,
) -> Result<Response<Body>, std::io::Error> {
    let (parts, incoming_body) = req.into_parts();
    let is_http1 = matches!(
        parts.version,
        hyper::Version::HTTP_10 | hyper::Version::HTTP_11
    );
    // An HTTP/1.1 body left unread would be parsed as the next request, so the connection
    // closes after any response that didn't consume its request's body.
    let close = |response: &mut Response<Body>| {
        let _ = response.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
    };
    if incoming_body.size_hint().upper().is_some_and(|size| {
        u64::try_from(state.limits.max_body_size).is_ok_and(|limit| size > limit)
    }) {
        // Still goes through the policy: this early return is a response like any other, and
        // skipping it would leave the one reply a peer can trigger cheapest as the only one
        // without `nosniff`/HSTS and with whatever `Server` header the stack added.
        let mut response = (hyper::StatusCode::PAYLOAD_TOO_LARGE, Body::empty()).into_response();
        state.finalize(&mut response, origin);
        if is_http1 {
            close(&mut response);
        }
        return Ok(response);
    }
    let (body, body_status) = body_with_deadline(incoming_body, state.limits.max_body_size);

    let mut response = state
        .dispatch(Request::from_parts(parts, body), origin)
        .await;
    if is_http1 && body_status.is_some_and(|status| status.load(Ordering::Acquire) != BODY_COMPLETE)
    {
        close(&mut response);
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
