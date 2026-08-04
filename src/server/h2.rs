//! Tachyon's own HTTP/2 connection driver, sitting directly on [`h2`].
//!
//! Used in place of `hyper`'s HTTP/2 server only when
//! [`Server::early_hints`](crate::Server::early_hints) is configured. Everything else keeps
//! the `hyper` path.
//!
//! # Why this exists
//!
//! `h2` grew [`SendResponse::send_informational`], which is what actually puts a
//! `103 Early Hints` frame on the wire. `hyper` never calls it, and structurally cannot:
//! its `Service` returns one `Response`, so there is nowhere for a second, earlier response
//! to come from. Reaching `send_informational` means owning the loop between the connection
//! and the router, which is what this module is.
//!
//! # What it has to reimplement
//!
//! Everything `hyper` was doing for the HTTP/2 case: accepting streams, adapting
//! [`h2::RecvStream`] to a [`Body`], and pumping the response body under HTTP/2 flow
//! control. The flow-control pump follows `hyper`'s own ordering — poll the next body frame
//! *before* reserving connection window — because reserving speculatively can deadlock a
//! second stream against peers that only emit `WINDOW_UPDATE` once their receive window is
//! fully drained.
//!
//! # What it deliberately does not support
//!
//! **RFC 8441 extended `CONNECT`** — `WebSocket`s over HTTP/2. Tachyon's WebSocket support
//! is built on `hyper::upgrade`, which has no meaning for a request `hyper` never saw. An
//! extended `CONNECT` reaching this driver is answered `501 Not Implemented` rather than
//! silently mishandled. Browsers never send one; they open `WebSocket`s over HTTP/1.1, which
//! this driver does not touch.
//!
//! [`SendResponse::send_informational`]: h2::server::SendResponse::send_informational

use crate::http::early_hints;
use crate::http::response::Body;
use crate::http::sfv::{self, FromStructuredHeader, Priority};
use crate::server::{REQUEST_TIMEOUT, Server};
use bytes::Bytes;
use hyper::body::{Body as HyperBody, Frame, SizeHint};
use hyper::header::{HeaderMap, HeaderName};
use hyper::{Request, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

/// Streams the peer may have open at once, advertised in the initial `SETTINGS`.
const MAX_CONCURRENT_STREAMS: u32 = 200;

/// Advertised `SETTINGS_MAX_HEADER_LIST_SIZE`, matching what `hyper` sends.
const MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;

/// Headers that are meaningless — and, per [RFC 9113 §8.2.2], malformed — in HTTP/2.
///
/// A handler has no way to know which transport will carry its response, so one that sets
/// `Connection: close` for the benefit of HTTP/1.1 clients would otherwise have every
/// HTTP/2 response rejected by `h2` before it reached the wire. Stripping them costs one
/// pass over a short list and turns a hard failure into correct behaviour.
///
/// [RFC 9113 §8.2.2]: https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2
const CONNECTION_SPECIFIC_HEADERS: [HeaderName; 6] = [
    hyper::header::CONNECTION,
    hyper::header::TRANSFER_ENCODING,
    hyper::header::UPGRADE,
    hyper::header::PROXY_AUTHENTICATE,
    hyper::header::PROXY_AUTHORIZATION,
    HeaderName::from_static("keep-alive"),
];

/// Number of urgency levels defined by [RFC 9218]'s `Priority` header: `0` (highest) through
/// `7` (lowest).
///
/// [RFC 9218]: https://www.rfc-editor.org/rfc/rfc9218
const URGENCY_LEVELS: usize = 8;

/// Orders concurrent response bodies on one connection by [RFC 9218] urgency.
///
/// `h2` itself has no scheduler: it discards RFC 7540 `PRIORITY` frames, and grants
/// connection-level flow-control window to streams strictly in the order they call
/// `reserve_capacity` — see `h2`'s `prioritize::Prioritize::try_assign_capacity`. That means
/// urgency can be enforced entirely at this layer, by biasing *when* each stream is allowed to
/// call `reserve_capacity`, without touching `h2` internals.
///
/// A stream about to request capacity registers its urgency and waits until no stream at a
/// strictly higher priority (a lower urgency number) is also waiting. The wait is bounded —
/// [`PRIORITY_STARVATION_BOUND`] — so a continuously-busy high-urgency stream can slow lower
/// ones down but can never fully starve them. Deferring the call is always safe: a stream that
/// hasn't called `reserve_capacity` holds none of the connection's flow-control window, so it
/// costs the waiting stream latency and nothing else.
struct PriorityScheduler {
    /// Streams currently waiting to call `reserve_capacity`, indexed by urgency (`0..=7`).
    waiting: [AtomicUsize; URGENCY_LEVELS],
    /// Wakes every waiter whenever a stream leaves `waiting`, so a lower-urgency stream
    /// notices a higher one has cleared without sitting out its full timeout.
    cleared: tokio::sync::Notify,
}

/// Upper bound on how long a stream defers `reserve_capacity` for a higher-urgency sibling
/// before proceeding regardless. Long enough to give real priority under contention, short
/// enough that a perpetually-busy high-urgency stream cannot starve the rest of a connection.
const PRIORITY_STARVATION_BOUND: std::time::Duration = std::time::Duration::from_millis(20);

impl PriorityScheduler {
    fn new() -> Self {
        Self {
            waiting: std::array::from_fn(|_| AtomicUsize::new(0)),
            cleared: tokio::sync::Notify::new(),
        }
    }

    /// Blocks the calling stream until it is its turn to call `reserve_capacity`.
    ///
    /// A no-op — returns immediately — whenever no higher-urgency stream is contending, which
    /// is the common case on an uncongested connection.
    async fn turn(&self, urgency: u8) {
        let urgency = urgency as usize;
        self.waiting[urgency].fetch_add(1, Ordering::AcqRel);
        while self.higher_priority_waiting(urgency) {
            let _ = tokio::time::timeout(PRIORITY_STARVATION_BOUND, self.cleared.notified()).await;
        }
        self.waiting[urgency].fetch_sub(1, Ordering::AcqRel);
        // Lets any lower-urgency stream sitting in this same loop re-check immediately
        // instead of waiting out the rest of its timeout.
        self.cleared.notify_waiters();
    }

    fn higher_priority_waiting(&self, urgency: usize) -> bool {
        self.waiting[..urgency]
            .iter()
            .any(|count| count.load(Ordering::Acquire) > 0)
    }
}

/// Adapts an [`h2::RecvStream`] to Tachyon's [`Body`].
///
/// The one thing this must not get wrong is flow control: HTTP/2 receive windows only
/// reopen when the application says it has consumed the bytes, so a body that never calls
/// `release_capacity` stalls the peer after the initial window and hangs every upload past
/// 64 KiB. Capacity is released as each frame is handed upward.
///
/// It also bounds how long the body may take to arrive, exactly as `DeadlineBody` does on
/// the `hyper` path: without it a peer can open a stream, declare a body, send nothing, and
/// hold a handler task and its connection permit for as long as it likes. The `Sleep` is
/// allocated on first poll so a bodyless `GET` never registers a timer it won't use.
struct H2Body {
    inner: h2::RecvStream,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Set once `poll_data` has run dry, so trailers are polled exactly once afterwards.
    data_done: bool,
}

impl HyperBody for H2Body {
    type Data = Bytes;
    type Error = crate::http::error::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        let deadline = this
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(REQUEST_TIMEOUT)));
        if deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(crate::http::error::Error::Rejection {
                status: StatusCode::REQUEST_TIMEOUT,
                message: "Timed out reading request body".to_string(),
            })));
        }

        if !this.data_done {
            match this.inner.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    // Ignored deliberately: this fails only when the stream is already
                    // gone, in which case the window no longer matters.
                    let _ = this.inner.flow_control().release_capacity(len);
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(crate::http::error::Error::Internal(
                        e.to_string(),
                    ))));
                }
                Poll::Ready(None) => this.data_done = true,
                Poll::Pending => return Poll::Pending,
            }
        }

        match this.inner.poll_trailers(cx) {
            Poll::Ready(Ok(Some(trailers))) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(crate::http::error::Error::Internal(
                e.to_string(),
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Serves one HTTP/2 connection, dispatching each stream through the router.
///
/// Returns when the peer closes the connection or the handshake fails. Per-stream failures
/// reset that stream and leave the connection running, matching `hyper`.
pub(super) async fn serve_connection<S, IO>(
    state: Arc<Server<S>>,
    io: IO,
    peer: std::net::SocketAddr,
) -> Result<(), h2::Error>
where
    S: Clone + Send + Sync + 'static,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    // Mirrors `tune_http2!` in `server::http`, so switching drivers doesn't silently
    // change the connection's shape.
    let _ = builder
        .initial_window_size(65535)
        .initial_connection_window_size(1024 * 1024)
        .max_frame_size(16384)
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_header_list_size(MAX_HEADER_LIST_SIZE);

    let mut connection = builder.handshake::<_, Bytes>(io).await?;

    // Caps the handler tasks this one connection can have running at once.
    let stream_permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS as usize));
    // Shared across every stream on this connection, so `Priority` on one stream can defer
    // `reserve_capacity` on another. Per-connection, not global: streams on different
    // connections never contend for the same flow-control window anyway.
    let priority_scheduler = Arc::new(PriorityScheduler::new());

    // `accept` drives the whole connection, not just stream acceptance, so in-flight
    // streams keep making progress while this awaits.
    while let Some(accepted) = connection.accept().await {
        let (request, mut respond) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("[h2] stream accept error: {e}");
                continue;
            }
        };

        let Ok(permit) = Arc::clone(&stream_permits).try_acquire_owned() else {
            tracing::debug!("[h2] refusing stream: connection is at its in-flight limit");
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            continue;
        };

        let state = Arc::clone(&state);
        let priority_scheduler = Arc::clone(&priority_scheduler);
        super::http::spawn_connection(async move {
            handle_stream(state, request, respond, peer, priority_scheduler).await;
            drop(permit);
        });
    }
    Ok(())
}

/// Runs one request/response exchange, emitting any early hints the handler sends along the
/// way.
async fn handle_stream<S>(
    state: Arc<Server<S>>,
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer: std::net::SocketAddr,
    priority_scheduler: Arc<PriorityScheduler>,
) where
    S: Clone + Send + Sync + 'static,
{
    let (parts, recv_stream) = request.into_parts();

    if parts.method == hyper::Method::CONNECT {
        tracing::debug!("[h2] refusing extended CONNECT: unsupported by the native driver");
        respond_with_status(&mut respond, StatusCode::NOT_IMPLEMENTED);
        return;
    }

    let hints_permitted = state
        .early_hints
        .as_ref()
        .is_some_and(|config| config.permits(&parts.method, &parts.headers));

    // RFC 9218: the client's request-time hint. A missing or malformed field falls back to
    // the spec's default urgency (3) rather than rejecting the request over an advisory header.
    let mut urgency = sfv::header_or_default::<Priority>(&parts.headers).urgency();

    let body = if recv_stream.is_end_stream() {
        Body::empty()
    } else {
        Body::stream(H2Body {
            inner: recv_stream,
            deadline: None,
            data_done: false,
        })
    };
    let mut request = Request::from_parts(parts, body);

    let mut hint_receiver = hints_permitted.then(|| {
        let (receiver, handle) = early_hints::channel();
        let _ = request.extensions_mut().insert(handle);
        receiver
    });

    let mut dispatch = std::pin::pin!(state.dispatch(request, peer));

    // Reset, hints and the handler are polled together in one pass rather than through
    // `select!`, because all three need `&mut respond` and only one future can hold it.
    //
    // The reset check is what makes a peer's `RST_STREAM` actually stop the work: without
    // it the handler runs to completion for a client that stopped listening, which is the
    // amplification half of Rapid Reset. Dropping `dispatch` on the way out cancels the
    // handler mid-await and returns the connection permit.
    let response = std::future::poll_fn(|cx| {
        if respond.poll_reset(cx).is_ready() {
            return Poll::Ready(None);
        }
        // Drained before the handler is polled, so a hint queued in the same wake-up as the
        // final response still goes out first — a 103 after the 200 is a protocol error.
        if let Some(receiver) = hint_receiver.as_mut() {
            while let Poll::Ready(Some(headers)) = receiver.poll_recv(cx) {
                send_informational(&mut respond, headers);
            }
        }
        dispatch.as_mut().poll(cx).map(Some)
    })
    .await;

    let Some(response) = response else {
        tracing::debug!("[h2] stream reset by peer; handler cancelled");
        return;
    };

    let (mut parts, body) = response.into_parts();
    // RFC 9218 §4: the handler may reprioritize by setting `Priority` on the response itself,
    // overriding whatever the request carried. Read before stripping connection-specific
    // headers below (`Priority` isn't one of them, but this keeps the read next to its source).
    if parts.headers.contains_key(Priority::HEADER_NAME) {
        urgency = sfv::header_or_default::<Priority>(&parts.headers).urgency();
    }
    for header in CONNECTION_SPECIFIC_HEADERS {
        let _ = parts.headers.remove(header);
    }

    // A zero-length body rides on the response frame's END_STREAM flag rather than costing
    // an extra empty DATA frame.
    let empty_body = body.size_hint().exact() == Some(0);
    let head = Response::from_parts(parts, ());

    let send_stream = match respond.send_response(head, empty_body) {
        Ok(send_stream) => send_stream,
        Err(e) => {
            tracing::debug!("[h2] failed to send response head: {e}");
            return;
        }
    };
    if !empty_body {
        send_body(send_stream, body, urgency, &priority_scheduler).await;
    }
}

/// Emits a `103 Early Hints` informational response.
///
/// Failures are logged and swallowed: a hint that didn't make it costs the page its head
/// start, and nothing else. Tearing down a request over one would be strictly worse than
/// the situation the feature exists to improve.
fn send_informational(respond: &mut h2::server::SendResponse<Bytes>, headers: HeaderMap) {
    let mut hint = Response::new(());
    *hint.status_mut() = StatusCode::EARLY_HINTS;
    *hint.headers_mut() = headers;
    if let Err(e) = respond.send_informational(hint) {
        tracing::debug!("[h2] early hint not sent: {e}");
    }
}

/// Answers with a bodyless status, for the paths that fail before the router is reached.
fn respond_with_status(respond: &mut h2::server::SendResponse<Bytes>, status: StatusCode) {
    let mut response = Response::new(());
    *response.status_mut() = status;
    if let Err(e) = respond.send_response(response, true) {
        tracing::debug!("[h2] failed to send {status}: {e}");
    }
}

/// Streams `body` out under HTTP/2 flow control, honouring `urgency` against every other
/// stream on the connection via `scheduler`.
///
/// The frame is polled *before* any capacity is reserved. Reserving speculatively pins
/// connection-level window that this stream may not end up using, which deadlocks a
/// concurrent stream against peers that only emit `WINDOW_UPDATE` once their receive window
/// is fully drained — the same ordering `hyper` settled on.
async fn send_body(
    mut send_stream: h2::SendStream<Bytes>,
    body: Body,
    urgency: u8,
    scheduler: &PriorityScheduler,
) {
    let mut body = std::pin::pin!(body);

    loop {
        let frame = match std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => {
                tracing::debug!("[h2] response body failed mid-stream: {e}");
                // The client has already received a `200` and part of a body, so the only
                // way to signal "this is not the whole response" is to reset the stream.
                send_stream.send_reset(h2::Reason::INTERNAL_ERROR);
                return;
            }
            None => break,
        };

        match frame.into_data() {
            Ok(data) => {
                if data.is_empty() {
                    continue;
                }
                // Lets a higher-urgency sibling on this connection call `reserve_capacity`
                // first — see `PriorityScheduler`. A no-op when nothing is contending.
                scheduler.turn(urgency).await;
                send_stream.reserve_capacity(data.len());
                if !await_capacity(&mut send_stream).await {
                    return;
                }
                let end_of_stream = body.is_end_stream();
                if let Err(e) = send_stream.send_data(data, end_of_stream) {
                    tracing::debug!("[h2] failed to send body chunk: {e}");
                    return;
                }
                if end_of_stream {
                    return;
                }
            }
            Err(non_data) => {
                let Ok(trailers) = non_data.into_trailers() else {
                    continue;
                };
                send_stream.reserve_capacity(0);
                if let Err(e) = send_stream.send_trailers(trailers) {
                    tracing::debug!("[h2] failed to send trailers: {e}");
                }
                return;
            }
        }
    }

    // No trailers were sent, so the stream still needs an explicit end.
    if let Err(e) = send_stream.send_data(Bytes::new(), true) {
        tracing::debug!("[h2] failed to end response stream: {e}");
    }
}

/// Waits until the stream has send capacity, returning `false` if it will never get any —
/// the peer reset it, or the connection went away.
async fn await_capacity(send_stream: &mut h2::SendStream<Bytes>) -> bool {
    while send_stream.capacity() == 0 {
        let available = std::future::poll_fn(|cx| {
            // A reset makes every remaining byte pointless; without this check the send
            // would park on capacity that is never coming.
            if send_stream.poll_reset(cx).is_ready() {
                return Poll::Ready(None);
            }
            send_stream.poll_capacity(cx)
        })
        .await;

        match available {
            // A spurious zero-capacity wakeup; the `while` re-checks and re-parks.
            Some(Ok(0)) => {}
            Some(Ok(_)) => return true,
            Some(Err(e)) => {
                tracing::debug!("[h2] stream capacity error: {e}");
                return false;
            }
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{CONNECTION_SPECIFIC_HEADERS, serve_connection};
    use crate::http::early_hints::{EarlyHints, EarlyHintsConfig, Link};
    use crate::routing::{Router, get};
    use crate::server::Server;
    use bytes::Bytes;
    use hyper::header::HeaderValue;
    use hyper::{Request, StatusCode};
    use std::sync::Arc;
    use std::time::Duration;

    /// Client half of a live connection to `router`, served by the native driver over an
    /// in-memory duplex — no TLS, no sockets, but the same `h2` state machine on both ends.
    struct Harness {
        send_request: h2::client::SendRequest<Bytes>,
    }

    impl Harness {
        async fn spawn(router: Router<()>, early_hints: bool) -> Self {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);

            let mut server = Server::new(router);
            if early_hints {
                server = server.early_hints(EarlyHintsConfig::new());
            }
            let peer = "127.0.0.1:1234".parse().unwrap();
            drop(tokio::spawn(async move {
                let _ = serve_connection(Arc::new(server), server_io, peer).await;
            }));

            let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
            drop(tokio::spawn(async move {
                let _ = connection.await;
            }));
            Self { send_request }
        }

        fn get(&mut self, path: &str, navigate: bool) -> Exchange {
            let mut builder = Request::builder()
                .method("GET")
                .uri(format!("https://example.test{path}"));
            if navigate {
                builder = builder.header("sec-fetch-mode", "navigate");
            }
            let request = builder.body(()).unwrap();
            let (response, _send) = self.send_request.send_request(request, true).unwrap();
            Exchange { response }
        }
    }

    struct Exchange {
        response: h2::client::ResponseFuture,
    }

    impl Exchange {
        /// The next `1xx`, or `None` if the final response arrived without one.
        ///
        /// Bounded by a timeout so a regression that stops emitting hints fails the test
        /// instead of hanging it.
        async fn next_informational(&mut self) -> Option<hyper::Response<()>> {
            let poll = std::future::poll_fn(|cx| self.response.poll_informational(cx));
            match tokio::time::timeout(Duration::from_secs(5), poll).await {
                Ok(Some(Ok(response))) => Some(response),
                Ok(Some(Err(e))) => panic!("informational response error: {e}"),
                Ok(None) | Err(_) => None,
            }
        }

        async fn finish(self) -> (StatusCode, Vec<u8>) {
            let response = tokio::time::timeout(Duration::from_secs(5), self.response)
                .await
                .expect("final response timed out")
                .expect("final response failed");
            let status = response.status();
            let mut body = response.into_body();
            let mut collected = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.expect("body chunk");
                let len = chunk.len();
                let _ = body.flow_control().release_capacity(len);
                collected.extend_from_slice(&chunk);
            }
            (status, collected)
        }
    }

    fn link_values(response: &hyper::Response<()>) -> Vec<String> {
        response
            .headers()
            .get_all(hyper::header::LINK)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// The whole point: hints must land on the wire *before* the handler has finished, not
    /// be batched up and sent alongside the response they were supposed to precede.
    #[tokio::test]
    async fn early_hints_arrive_before_the_final_response() {
        let router: Router<()> = Router::new().route(
            "/",
            get(|hints: EarlyHints| async move {
                assert!(hints.is_supported(), "native driver must support hints");
                assert!(hints.send([
                    Link::preload("/static/app.css").as_style(),
                    Link::preconnect("https://cdn.example.com"),
                ]));
                // Stands in for the think-time early hints exist to overlap. The hint has
                // to be on the wire before this resolves.
                tokio::time::sleep(Duration::from_millis(50)).await;
                "the page"
            }),
        );

        let mut harness = Harness::spawn(router, true).await;
        let mut exchange = harness.get("/", true);

        let hint = exchange
            .next_informational()
            .await
            .expect("a 103 must arrive before the 200");
        assert_eq!(hint.status(), StatusCode::EARLY_HINTS);
        assert_eq!(
            link_values(&hint),
            vec![
                "</static/app.css>; rel=preload; as=style",
                "<https://cdn.example.com>; rel=preconnect",
            ],
        );

        let (status, body) = exchange.finish().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"the page");
    }

    /// The declarative form fires before the handler runs at all, so it works on a handler
    /// that knows nothing about early hints.
    #[tokio::test]
    async fn route_declared_hints_are_sent_without_handler_involvement() {
        let router: Router<()> = Router::new()
            .route(
                "/",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    "the page"
                }),
            )
            .early_hints([Link::preload("/static/app.js").as_script()]);

        let mut harness = Harness::spawn(router, true).await;
        let mut exchange = harness.get("/", true);

        let hint = exchange.next_informational().await.expect("a 103");
        assert_eq!(
            link_values(&hint),
            vec!["</static/app.js>; rel=preload; as=script"],
        );
        assert_eq!(exchange.finish().await.0, StatusCode::OK);
    }

    /// A request that isn't a navigation gets a disabled handle, so nothing goes on the
    /// wire and the response is unaffected.
    #[tokio::test]
    async fn non_navigations_get_a_disabled_handle() {
        let router: Router<()> = Router::new().route(
            "/",
            get(|hints: EarlyHints| async move {
                assert!(!hints.is_supported());
                assert!(!hints.send([Link::preload("/app.css").as_style()]));
                "the page"
            }),
        );

        let mut harness = Harness::spawn(router, true).await;
        let mut exchange = harness.get("/", false);

        assert!(exchange.next_informational().await.is_none());
        let (status, body) = exchange.finish().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"the page");
    }

    /// With no early-hints config the driver isn't used at all, but the router and handler
    /// are unchanged — so extraction must still succeed, silently disabled.
    #[tokio::test]
    async fn handlers_still_work_with_hints_unconfigured() {
        let router: Router<()> = Router::new().route(
            "/",
            get(|hints: EarlyHints| async move {
                assert!(!hints.is_supported());
                "the page"
            }),
        );

        let mut harness = Harness::spawn(router, false).await;
        let exchange = harness.get("/", true);
        assert_eq!(exchange.finish().await.1, b"the page");
    }

    /// A response larger than the 64 KiB initial stream window only completes if the
    /// flow-control pump waits for `WINDOW_UPDATE` instead of blasting the whole body.
    #[tokio::test]
    async fn responses_past_the_initial_window_complete() {
        const SIZE: usize = 512 * 1024;

        let router: Router<()> = Router::new().route(
            "/big",
            get(|| async {
                crate::http::response::Html(std::iter::repeat_n('x', SIZE).collect::<String>())
            }),
        );

        let mut harness = Harness::spawn(router, true).await;
        let (status, body) = harness.get("/big", true).finish().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.len(), SIZE, "body was truncated by flow control");
        assert!(body.iter().all(|&b| b == b'x'));
    }

    /// A request body larger than the initial window only completes if `H2Body` releases
    /// receive capacity as the application consumes frames.
    #[tokio::test]
    async fn request_bodies_past_the_initial_window_complete() {
        const SIZE: usize = 256 * 1024;

        let router: Router<()> = Router::new().route(
            "/upload",
            crate::routing::post(|body: String| async move { format!("{}", body.len()) }),
        );

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = Server::new(router).early_hints(EarlyHintsConfig::new());
        let peer = "127.0.0.1:1234".parse().unwrap();
        drop(tokio::spawn(async move {
            let _ = serve_connection(Arc::new(server), server_io, peer).await;
        }));

        let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
        drop(tokio::spawn(async move {
            let _ = connection.await;
        }));

        let request = Request::builder()
            .method("POST")
            .uri("https://example.test/upload")
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let (response, mut send_stream) = send_request.send_request(request, false).unwrap();

        drop(tokio::spawn(async move {
            let payload = vec![b'y'; SIZE];
            for chunk in payload.chunks(16 * 1024) {
                send_stream.reserve_capacity(chunk.len());
                while send_stream.capacity() == 0 {
                    match std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await {
                        Some(Ok(0)) => {}
                        Some(Ok(_)) => break,
                        _ => return,
                    }
                }
                if send_stream
                    .send_data(Bytes::copy_from_slice(chunk), false)
                    .is_err()
                {
                    return;
                }
            }
            let _ = send_stream.send_data(Bytes::new(), true);
        }));

        let response = tokio::time::timeout(Duration::from_secs(10), response)
            .await
            .expect("upload stalled — receive capacity was never released")
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let mut collected = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let len = chunk.len();
            let _ = body.flow_control().release_capacity(len);
            collected.extend_from_slice(&chunk);
        }
        assert_eq!(String::from_utf8(collected).unwrap(), SIZE.to_string());
    }

    /// A handler that sets HTTP/1.1 connection headers must not have every HTTP/2 response
    /// Rapid Reset (CVE-2023-44487): a peer that opens a stream and immediately resets it
    /// must not leave a handler running. `max_concurrent_streams` does not cover this —
    /// `h2` frees the slot the moment the reset lands — so without an explicit reset check
    /// each cheap HEADERS+RST_STREAM pair buys the attacker a full router dispatch.
    #[tokio::test]
    async fn resetting_a_stream_cancels_its_handler() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Counts handlers that ran to completion. A cancelled handler is dropped at its
        // first await point and never reaches the increment.
        let completed = StdArc::new(AtomicUsize::new(0));
        let seen = StdArc::clone(&completed);

        let router: Router<()> = Router::new().route(
            "/slow",
            get(move || {
                let seen = StdArc::clone(&seen);
                async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let _ = seen.fetch_add(1, Ordering::SeqCst);
                    "done"
                }
            }),
        );

        let mut harness = Harness::spawn(router, false).await;

        for _ in 0..50 {
            let request = Request::builder()
                .method("GET")
                .uri("https://example.test/slow")
                .body(())
                .unwrap();
            let (response, _send) = harness.send_request.send_request(request, true).unwrap();
            drop(response);
        }

        // Long enough for the resets to land and the handlers to be dropped, far short of
        // the 30s each handler would otherwise sleep for.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "handlers kept running after their streams were reset",
        );

        // The connection is still usable: refusing abandoned work must not break the peer.
        let (status, body) = harness.get("/", false).finish().await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _ = body;
    }

    /// A request that declares a body and never sends it must not pin a handler and its
    /// connection permit indefinitely — the gap `DeadlineBody` covers on the `hyper` path.
    #[tokio::test(start_paused = true)]
    async fn a_body_that_never_arrives_times_out() {
        let router: Router<()> = Router::new().route(
            "/upload",
            crate::routing::post(|body: String| async move { format!("{}", body.len()) }),
        );

        let mut harness = Harness::spawn(router, false).await;
        let request = Request::builder()
            .method("POST")
            .uri("https://example.test/upload")
            .body(())
            .unwrap();
        // `false`: the stream stays open, so the server is left waiting on a body that is
        // never coming.
        let (response, _send_stream) = harness.send_request.send_request(request, false).unwrap();

        // Auto-advanced past REQUEST_TIMEOUT by the paused clock rather than really slept.
        let response = tokio::time::timeout(Duration::from_secs(120), response)
            .await
            .expect("handler was never released — the body deadline did not fire")
            .expect("response");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    /// rejected by `h2` before it reaches the wire.
    #[test]
    fn connection_specific_headers_are_stripped() {
        let mut headers = hyper::HeaderMap::new();
        let _ = headers.insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));
        let _ = headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        let _ = headers.insert(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        let _ = headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );

        for header in CONNECTION_SPECIFIC_HEADERS {
            let _ = headers.remove(header);
        }

        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key(hyper::header::CONTENT_TYPE));
    }
}
