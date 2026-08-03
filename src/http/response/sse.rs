//! Server-Sent Events (SSE), mirroring `axum::response::sse`.
//!
//! ```rust,no_run
//! use tachyon_web::response::sse::{Event, Sse};
//! use tachyon_web::{Router, get};
//! use futures_core::Stream;
//! use std::convert::Infallible;
//! use std::pin::Pin;
//! use std::task::{Context, Poll};
//!
//! // A minimal, self-contained `Stream` yielding one event then finishing —
//! // in real code this would typically be a channel receiver or a `Stream`
//! // built with `tokio_stream`/`futures_util`'s combinators.
//! struct OnceStream(Option<Event>);
//!
//! impl Stream for OnceStream {
//!     type Item = Result<Event, Infallible>;
//!     fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//!         Poll::Ready(self.0.take().map(Ok))
//!     }
//! }
//!
//! async fn handler() -> Sse<OnceStream> {
//!     Sse::new(OnceStream(Some(Event::new().data("hello"))))
//! }
//!
//! let _app: Router<()> = Router::new().route("/events", get(handler));
//! ```
//!
//! Requires the `sse` feature.

use crate::http::error::Error;
use crate::http::response::{Body, IntoResponse};
use bytes::Bytes;
use futures_core::Stream;
use hyper::body::Frame;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::{Response, StatusCode};
use std::fmt::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A single Server-Sent Event.
///
/// Build one with the fluent setters and yield it from the stream passed to
/// [`Sse::new`]. Multi-line `data`/`comment` values are automatically split
/// across multiple wire-format lines, per the SSE spec.
#[derive(Debug, Default, Clone)]
#[allow(clippy::struct_field_names)] // `event` is the correct SSE wire-format field name.
pub struct Event {
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
    retry_ms: Option<u64>,
    comment: Option<String>,
}

/// Strips `\r`/`\n` from a single-line SSE field, without allocating in the common case.
fn strip_newlines(value: String) -> String {
    if value.contains(['\r', '\n']) {
        value.replace(['\r', '\n'], "")
    } else {
        value
    }
}

/// Writes a multi-line SSE field, one `<prefix> <line>` per line.
///
/// SSE treats `\n`, `\r\n` and a lone `\r` as the same line break, so all three are normalized
/// first: a stray `\r` left mid-line is one the client re-reads as a terminator, turning the
/// remainder into a field the caller never wrote.
fn write_multiline(buf: &mut String, prefix: &str, value: &str) {
    let normalized;
    let value = if value.contains('\r') {
        normalized = value.replace("\r\n", "\n").replace('\r', "\n");
        normalized.as_str()
    } else {
        value
    };
    for line in value.split('\n') {
        let _ = writeln!(buf, "{prefix} {line}");
    }
}

impl Event {
    /// Creates an empty event — add fields with the setters below.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the event's `data` field (the `data: ...` line(s)).
    #[must_use]
    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// JSON-encodes `data` and sets it as the event's `data` field, matching
    /// `axum::response::sse::Event::json_data`.
    ///
    /// # Errors
    /// Returns an error if `data` cannot be serialized to JSON.
    pub fn json_data(self, data: impl serde::Serialize) -> serde_json::Result<Self> {
        Ok(self.data(serde_json::to_string(&data)?))
    }

    /// Sets the event's `event` field (the event type/name).
    ///
    /// Single-line, unlike `data`/`comment`, so `\r`/`\n` are stripped: passed through, they'd
    /// let interpolated input end the line early and inject SSE fields of its own choosing.
    #[must_use]
    pub fn event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(strip_newlines(event.into()));
        self
    }

    /// Sets the event's `id` field.
    ///
    /// As with [`event`](Self::event), `\r`/`\n` are stripped — see that method for why.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(strip_newlines(id.into()));
        self
    }

    /// Sets the client's reconnection delay (the `retry: <ms>` line).
    #[must_use]
    pub fn retry(mut self, duration: std::time::Duration) -> Self {
        self.retry_ms = Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
        self
    }

    /// Sets a comment line (`: ...`), ignored by clients but useful as a
    /// keep-alive ping to stop idle proxies from closing the connection.
    #[must_use]
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Serializes this event into SSE wire format, terminated by a blank line.
    fn write_to(&self, buf: &mut String) {
        if let Some(comment) = &self.comment {
            write_multiline(buf, ":", comment);
        }
        if let Some(event) = &self.event {
            let _ = writeln!(buf, "event: {event}");
        }
        if let Some(data) = &self.data {
            write_multiline(buf, "data:", data);
        }
        if let Some(id) = &self.id {
            let _ = writeln!(buf, "id: {id}");
        }
        if let Some(retry_ms) = self.retry_ms {
            let _ = writeln!(buf, "retry: {retry_ms}");
        }
        buf.push('\n');
    }
}

/// Configures periodic keep-alive comment pings for an otherwise-idle
/// [`Sse`] stream, matching `axum::response::sse::KeepAlive`.
///
/// Some intermediary proxies/load balancers close connections that go quiet
/// for too long; interleaving a harmless `: <text>` comment line (ignored by
/// SSE clients) at a regular interval keeps the connection alive without the
/// caller's own stream needing to know about it.
#[derive(Debug, Clone)]
pub struct KeepAlive {
    event: Event,
    interval: std::time::Duration,
}

impl Default for KeepAlive {
    fn default() -> Self {
        Self {
            event: Event::new().comment(""),
            interval: std::time::Duration::from_secs(15),
        }
    }
}

impl KeepAlive {
    /// Creates a `KeepAlive` with the default 15-second interval and an
    /// empty comment ping.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how long the stream may stay idle before a keep-alive ping is
    /// sent.
    #[must_use]
    pub const fn interval(mut self, interval: std::time::Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Sets the keep-alive ping's comment text (sent as `: <text>`).
    #[must_use]
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.event = Event::new().comment(text);
        self
    }

    /// Sets the exact [`Event`] sent as the keep-alive ping, for cases where
    /// a comment alone isn't enough (e.g. clients that key off `event:`).
    #[must_use]
    pub fn event(mut self, event: Event) -> Self {
        self.event = event;
        self
    }
}

pin_project_lite::pin_project! {
    /// Wraps a stream, injecting `keep_alive.event` whenever the inner stream
    /// hasn't produced an item for `keep_alive.interval`.
    struct KeepAliveStream<S> {
        #[pin]
        stream: S,
        interval: tokio::time::Interval,
        comment_event: Event,
    }
}

impl<S, E> Stream for KeepAliveStream<S>
where
    S: Stream<Item = Result<Event, E>>,
{
    type Item = Result<Event, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.stream.poll_next(cx) {
            Poll::Ready(item) => {
                this.interval.reset();
                Poll::Ready(item)
            }
            Poll::Pending => this.interval.poll_tick(cx).map(|_| {
                this.interval.reset();
                Some(Ok(this.comment_event.clone()))
            }),
        }
    }
}

pin_project_lite::pin_project! {
    /// An SSE response body: adapts a `Stream<Item = Result<Event, E>>` into
    /// the `text/event-stream` wire format.
    struct EventStreamBody<S> {
        #[pin]
        stream: S,
    }
}

impl<S, E> hyper::body::Body for EventStreamBody<S>
where
    S: Stream<Item = Result<Event, E>>,
    E: Into<Error>,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.stream.poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                let mut buf = String::with_capacity(64);
                event.write_to(&mut buf);
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(buf)))))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A Server-Sent Events response, matching `axum::response::sse::Sse`.
///
/// Sets `Content-Type: text/event-stream` and `Cache-Control: no-cache`, then
/// streams each item of the wrapped stream in SSE wire format as it becomes
/// available — nothing is buffered.
#[must_use]
#[derive(Debug, Clone)]
pub struct Sse<S> {
    stream: S,
    keep_alive: Option<KeepAlive>,
}

impl<S, E> Sse<S>
where
    S: Stream<Item = Result<Event, E>> + Send + 'static,
    E: Into<Error> + 'static,
{
    /// Creates an SSE response from a stream of events.
    pub const fn new(stream: S) -> Self {
        Self {
            stream,
            keep_alive: None,
        }
    }

    /// Enables periodic keep-alive comment pings on this stream — see
    /// [`KeepAlive`].
    pub fn keep_alive(mut self, keep_alive: KeepAlive) -> Self {
        self.keep_alive = Some(keep_alive);
        self
    }
}

impl<S, E> IntoResponse for Sse<S>
where
    S: Stream<Item = Result<Event, E>> + Send + 'static,
    E: Into<Error> + 'static,
{
    fn into_response(self) -> Response<Body> {
        let body = if let Some(keep_alive) = self.keep_alive {
            Body::stream(EventStreamBody {
                stream: KeepAliveStream {
                    stream: self.stream,
                    // `tokio::time::interval`'s first tick always fires immediately —
                    // start the clock one interval in the future instead, so the first
                    // keep-alive ping only fires after the stream has actually been
                    // idle for `keep_alive.interval`, matching the documented behavior.
                    interval: tokio::time::interval_at(
                        tokio::time::Instant::now() + keep_alive.interval,
                        keep_alive.interval,
                    ),
                    comment_event: keep_alive.event,
                },
            })
        } else {
            Body::stream(EventStreamBody {
                stream: self.stream,
            })
        };
        let mut resp = Response::new(body);
        *resp.status_mut() = StatusCode::OK;
        let _ = resp
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
        let _ = resp
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        resp
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::convert::Infallible;

    #[allow(clippy::needless_pass_by_value)]
    fn wire_format(event: Event) -> String {
        let mut buf = String::new();
        event.write_to(&mut buf);
        buf
    }

    #[test]
    fn test_simple_data_event() {
        let s = wire_format(Event::new().data("hello"));
        assert_eq!(s, "data: hello\n\n");
    }

    #[test]
    fn test_event_with_name_and_id() {
        let s = wire_format(Event::new().event("update").data("payload").id("42"));
        assert_eq!(s, "event: update\ndata: payload\nid: 42\n\n");
    }

    #[test]
    fn test_multiline_data_split_across_lines() {
        let s = wire_format(Event::new().data("line1\nline2"));
        assert_eq!(s, "data: line1\ndata: line2\n\n");
    }

    #[test]
    fn test_comment_only_event() {
        let s = wire_format(Event::new().comment("keep-alive"));
        assert_eq!(s, ": keep-alive\n\n");
    }

    #[test]
    fn test_retry_field() {
        let s = wire_format(Event::new().retry(std::time::Duration::from_secs(5)));
        assert_eq!(s, "retry: 5000\n\n");
    }

    /// A newline in `event`/`id` must not be able to end the line and inject further fields.
    #[test]
    fn test_single_line_fields_strip_injected_newlines() {
        let s = wire_format(Event::new().id("42\ndata: injected").data("real"));
        assert_eq!(s, "data: real\nid: 42data: injected\n\n");

        let s = wire_format(Event::new().event("up\r\ndata: injected"));
        assert_eq!(s, "event: updata: injected\n\n");
    }

    /// `\n`, `\r\n` and a lone `\r` are all one line break to an SSE client.
    #[test]
    fn test_multiline_fields_normalize_every_line_break_form() {
        assert_eq!(
            wire_format(Event::new().data("a\r\nb\rc\nd")),
            "data: a\ndata: b\ndata: c\ndata: d\n\n"
        );
        assert_eq!(wire_format(Event::new().comment("x\r\ny")), ": x\n: y\n\n");
    }

    #[test]
    fn test_json_data() {
        #[derive(serde::Serialize)]
        struct Payload {
            n: u32,
        }
        let event = Event::new().json_data(Payload { n: 7 }).unwrap();
        assert_eq!(wire_format(event), "data: {\"n\":7}\n\n");
    }

    #[tokio::test]
    async fn test_sse_response_headers_and_body() {
        use http_body_util::BodyExt;

        let events: [Result<Event, Infallible>; 2] = [
            Ok(Event::new().data("first")),
            Ok(Event::new().data("second")),
        ];
        let stream = tokio_stream::iter(events);

        let resp = Sse::new(stream).into_response();
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        assert_eq!(resp.headers().get(CACHE_CONTROL).unwrap(), "no-cache");

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"data: first\n\ndata: second\n\n");
    }

    #[tokio::test(start_paused = true)]
    async fn test_keep_alive_pings_idle_stream() {
        use http_body_util::BodyExt;
        use std::time::Duration;

        // A stream that never produces anything on its own — any output must
        // come from the keep-alive ping.
        struct NeverStream;
        impl Stream for NeverStream {
            type Item = Result<Event, Infallible>;
            fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let resp = Sse::new(NeverStream)
            .keep_alive(
                KeepAlive::new()
                    .interval(Duration::from_secs(1))
                    .text("ping"),
            )
            .into_response();

        let mut body = resp.into_body();
        tokio::time::advance(Duration::from_secs(1)).await;
        let frame = body.frame().await.unwrap().unwrap();
        let data = frame.into_data().unwrap();
        assert_eq!(&data[..], b": ping\n\n");
    }

    #[tokio::test(start_paused = true)]
    async fn test_keep_alive_does_not_ping_before_first_interval_elapses() {
        use std::time::Duration;

        struct NeverStream;
        impl Stream for NeverStream {
            type Item = Result<Event, Infallible>;
            fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        // Constructed directly (rather than through `Sse::into_response`) so this
        // test exercises `KeepAliveStream::poll_next` itself without also routing
        // through the `Body`/`EventStreamBody` wire-format layer.
        let interval = Duration::from_secs(1);
        let mut kas = std::pin::pin!(KeepAliveStream {
            stream: NeverStream,
            interval: tokio::time::interval_at(tokio::time::Instant::now() + interval, interval),
            comment_event: Event::new().comment("ping"),
        });

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        // Polling immediately (no time advanced) must not yield a ping — the
        // stream hasn't been idle for a full interval yet. This regression-tests
        // `tokio::time::interval`'s "first tick fires immediately" behavior,
        // which must not leak through as a spurious ping.
        assert!(
            kas.as_mut().poll_next(&mut cx).is_pending(),
            "keep-alive must not fire before the configured interval elapses"
        );

        tokio::time::advance(interval).await;
        assert!(
            kas.as_mut().poll_next(&mut cx).is_ready(),
            "keep-alive must fire once the interval has actually elapsed"
        );
    }
}
