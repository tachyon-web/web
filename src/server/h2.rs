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
use crate::server::Server;
use bytes::Bytes;
use hyper::body::{Body as HyperBody, Frame, SizeHint};
use hyper::header::{HeaderMap, HeaderName};
use hyper::{Request, Response, StatusCode};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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

/// Adapts an [`h2::RecvStream`] to Tachyon's [`Body`].
///
/// The one thing this must not get wrong is flow control: HTTP/2 receive windows only
/// reopen when the application says it has consumed the bytes, so a body that never calls
/// `release_capacity` stalls the peer after the initial window and hangs every upload past
/// 64 KiB. Capacity is released as each frame is handed upward.
struct H2Body {
    inner: h2::RecvStream,
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
        .max_concurrent_streams(200);

    let mut connection = builder.handshake::<_, Bytes>(io).await?;

    // `accept` drives the whole connection, not just stream acceptance, so in-flight
    // streams keep making progress while this awaits.
    while let Some(accepted) = connection.accept().await {
        let (request, respond) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("[h2] stream accept error: {e}");
                continue;
            }
        };
        let state = state.clone();
        super::http::spawn_connection(async move {
            handle_stream(state, request, respond, peer).await;
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
) where
    S: Clone + Send + Sync + 'static,
{
    let (parts, recv_stream) = request.into_parts();

    // RFC 8441 extended CONNECT — see the module docs for why this is refused rather than
    // attempted.
    if parts.method == hyper::Method::CONNECT {
        tracing::debug!("[h2] refusing extended CONNECT: unsupported by the native driver");
        respond_with_status(&mut respond, StatusCode::NOT_IMPLEMENTED);
        return;
    }

    let hints_permitted = state
        .early_hints
        .as_ref()
        .is_some_and(|config| config.permits(&parts.method, &parts.headers));

    let mut request = Request::from_parts(
        parts,
        Body::stream(H2Body {
            inner: recv_stream,
            data_done: false,
        }),
    );

    let hint_receiver = hints_permitted.then(|| {
        let (receiver, handle) = early_hints::channel();
        let _ = request.extensions_mut().insert(handle);
        receiver
    });

    let dispatch = std::pin::pin!(state.dispatch(request, peer));
    let response = match hint_receiver {
        None => dispatch.await,
        Some(mut receiver) => {
            let mut dispatch = dispatch;
            loop {
                tokio::select! {
                    // Biased so a hint queued in the same poll as the final response still
                    // goes out first — a 103 after the 200 is a protocol error.
                    biased;
                    Some(headers) = receiver.recv() => send_informational(&mut respond, headers),
                    response = &mut dispatch => break response,
                }
            }
        }
    };

    let (mut parts, body) = response.into_parts();
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
        send_body(send_stream, body).await;
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

/// Streams `body` out under HTTP/2 flow control.
///
/// The frame is polled *before* any capacity is reserved. Reserving speculatively pins
/// connection-level window that this stream may not end up using, which deadlocks a
/// concurrent stream against peers that only emit `WINDOW_UPDATE` once their receive window
/// is fully drained — the same ordering `hyper` settled on.
async fn send_body(mut send_stream: h2::SendStream<Bytes>, body: Body) {
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
            let poll =
                std::future::poll_fn(|cx| self.response.poll_informational(cx));
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
                crate::http::response::Html(
                    std::iter::repeat_n('x', SIZE).collect::<String>(),
                )
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
