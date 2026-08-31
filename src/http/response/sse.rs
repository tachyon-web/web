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
use bytes::{BufMut, Bytes, BytesMut};
use futures_core::Stream;
use hyper::body::Frame;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::{Response, StatusCode};
use std::fmt::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The state of an event's buffer — active (still being built) or finalized (immutable,
/// cheap to clone; used for the keep-alive ping, which is built once and cloned per tick).
#[derive(Debug, Clone)]
enum Buffer {
    Active(BytesMut),
    Finalized(Bytes),
}

impl Buffer {
    /// Returns a mutable reference to the active buffer, converting a finalized one back to
    /// active first if needed.
    fn as_mut(&mut self) -> &mut BytesMut {
        if let Self::Finalized(bytes) = self {
            *self = Self::Active(BytesMut::from(std::mem::take(bytes)));
        }
        match self {
            Self::Active(bytes_mut) => bytes_mut,
            Self::Finalized(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct EventFlags(u8);

impl EventFlags {
    const HAS_DATA: Self = Self(0b0001);
    const HAS_EVENT: Self = Self(0b0010);
    const HAS_RETRY: Self = Self(0b0100);
    const HAS_ID: Self = Self(0b1000);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// A single Server-Sent Event.
///
/// Build one with the fluent setters and yield it from the stream passed to [`Sse::new`].
/// Multi-line `data` values are automatically split across multiple wire-format lines, per the
/// SSE spec. Construction *is* serialization — each setter writes straight into the event's
/// wire-format buffer, matching `axum::response::sse::Event`.
///
/// *Axum compatibility: drop-in replacement for `axum::response::sse::Event`.*
#[derive(Debug, Clone)]
#[must_use]
pub struct Event {
    buffer: Buffer,
    flags: EventFlags,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            buffer: Buffer::Active(BytesMut::new()),
            flags: EventFlags(0),
        }
    }
}

/// A [`std::fmt::Write`] adapter for incrementally writing an event's `data` field(s), one
/// `data: <line>` per line. Matches `axum::response::sse::EventDataWriter`.
///
/// # Panics
///
/// Panics if any `data` has already been written on the underlying [`Event`] prior to the
/// first write through this instance.
///
/// *Axum compatibility: drop-in replacement for `axum::response::sse::EventDataWriter`.*
#[derive(Debug)]
#[must_use]
pub struct EventDataWriter {
    event: Event,
    // Whether *this* writer instance has written data yet — distinct from whether `event`
    // already has a `data` field, which is tracked by `event.flags`.
    data_written: bool,
}

impl Event {
    /// The default keep-alive ping: an empty comment line.
    pub const DEFAULT_KEEP_ALIVE: Self = Self::finalized(Bytes::from_static(b":\n\n"));

    const fn finalized(bytes: Bytes) -> Self {
        Self {
            buffer: Buffer::Finalized(bytes),
            flags: EventFlags(0),
        }
    }

    /// Creates an empty event — add fields with the setters below.
    pub fn new() -> Self {
        Self::default()
    }

    /// Turns this event into an [`EventDataWriter`] for writing custom `data` content, e.g. from
    /// a [`std::fmt::Write`] or [`std::io::Write`] source. Turn it back into an `Event` with
    /// [`EventDataWriter::into_event`].
    pub const fn into_data_writer(self) -> EventDataWriter {
        EventDataWriter {
            event: self,
            data_written: false,
        }
    }

    /// Sets the event's `data` field (the `data: ...` line(s)).
    ///
    /// # Panics
    /// Panics if `data`/`json_data` has already been called on this event.
    pub fn data<T: AsRef<str>>(self, data: T) -> Self {
        let mut writer = self.into_data_writer();
        let _ = writer.write_str(data.as_ref());
        writer.into_event()
    }

    /// JSON-encodes `data` and sets it as the event's `data` field, matching
    /// `axum::response::sse::Event::json_data`.
    ///
    /// # Errors
    /// Returns an error if `data` cannot be serialized to JSON.
    ///
    /// # Panics
    /// Panics if `data`/`json_data` has already been called on this event.
    pub fn json_data<T: serde::Serialize>(
        self,
        data: T,
    ) -> Result<Self, crate::http::error::Error> {
        struct JsonWriter<'a>(&'a mut EventDataWriter);
        impl std::io::Write for JsonWriter<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(self.0.write_buf(buf))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = self.into_data_writer();
        serde_json::to_writer(JsonWriter(&mut writer), &data)
            .map_err(crate::http::error::Error::new)?;
        Ok(writer.into_event())
    }

    /// Sets the event's `event` field (the event type/name).
    ///
    /// # Panics
    /// Panics if `event` contains `\r`/`\n`, or if this has already been called on this event.
    pub fn event<T: AsRef<str>>(mut self, event: T) -> Self {
        assert!(
            !self.flags.contains(EventFlags::HAS_EVENT),
            "Called `Event::event` multiple times"
        );
        self.flags.insert(EventFlags::HAS_EVENT);
        self.field("event", event.as_ref());
        self
    }

    /// Sets the event's `id` field.
    ///
    /// # Panics
    /// Panics if `id` contains `\r`/`\n`, or if this has already been called on this event.
    pub fn id<T: AsRef<str>>(mut self, id: T) -> Self {
        assert!(
            !self.flags.contains(EventFlags::HAS_ID),
            "Called `Event::id` multiple times"
        );
        self.flags.insert(EventFlags::HAS_ID);
        self.field("id", id.as_ref());
        self
    }

    /// Sets the client's reconnection delay (the `retry: <ms>` line).
    ///
    /// # Panics
    /// Panics if this has already been called on this event.
    pub fn retry(mut self, duration: std::time::Duration) -> Self {
        assert!(
            !self.flags.contains(EventFlags::HAS_RETRY),
            "Called `Event::retry` multiple times"
        );
        self.flags.insert(EventFlags::HAS_RETRY);

        let mut ms = String::with_capacity(20);
        let _ = write!(ms, "{}", duration.as_millis());
        let buffer = self.buffer.as_mut();
        buffer.extend_from_slice(b"retry: ");
        buffer.extend_from_slice(ms.as_bytes());
        buffer.put_u8(b'\n');
        self
    }

    /// Sets a comment line (`: ...`), ignored by clients but useful as a keep-alive ping to stop
    /// idle proxies from closing the connection.
    ///
    /// Unlike the other setters, this can be called multiple times to add several comment lines.
    ///
    /// # Panics
    /// Panics if `comment` contains `\r`/`\n`.
    pub fn comment<T: AsRef<str>>(mut self, comment: T) -> Self {
        self.field("", comment.as_ref());
        self
    }

    /// Writes a `<name>: <value>\n` line (or `: <value>\n` when `name` is empty, for comments)
    /// directly into the wire-format buffer.
    fn field(&mut self, name: &str, value: &str) {
        assert!(
            !value.contains(['\r', '\n']),
            "SSE field value cannot contain newlines or carriage returns"
        );
        let buffer = self.buffer.as_mut();
        buffer.extend_from_slice(name.as_bytes());
        buffer.put_u8(b':');
        buffer.put_u8(b' ');
        buffer.extend_from_slice(value.as_bytes());
        buffer.put_u8(b'\n');
    }

    /// Serializes this event into its final SSE wire-format bytes, terminated by a blank line.
    fn finalize(self) -> Bytes {
        match self.buffer {
            Buffer::Finalized(bytes) => bytes,
            Buffer::Active(mut bytes_mut) => {
                bytes_mut.put_u8(b'\n');
                bytes_mut.freeze()
            }
        }
    }
}

impl EventDataWriter {
    /// Consumes this writer and returns the [`Event`] again. If this writer instance wrote any
    /// data, appends the trailing `\n` that closes the `data:` field.
    pub fn into_event(self) -> Event {
        let mut event = self.event;
        if self.data_written {
            event.buffer.as_mut().put_u8(b'\n');
        }
        event
    }

    /// Writes raw bytes into the event's `data` field, splitting on `\n`/`\r` into further
    /// `data: ` lines.
    ///
    /// # Panics
    /// Panics if the underlying event already had `data` written by a previous writer instance.
    fn write_buf(&mut self, buf: &[u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }

        if !std::mem::replace(&mut self.data_written, true) {
            assert!(
                !self.event.flags.contains(EventFlags::HAS_DATA),
                "Called `Event::data`/`Event::json_data` multiple times"
            );
            self.event.buffer.as_mut().extend_from_slice(b"data: ");
            self.event.flags.insert(EventFlags::HAS_DATA);
        }

        let mut last_split = 0;
        for (i, byte) in buf.iter().enumerate() {
            if *byte == b'\n' || *byte == b'\r' {
                let split_at = i.saturating_add(1);
                if let Some(line) = buf.get(last_split..split_at) {
                    let buffer = self.event.buffer.as_mut();
                    buffer.extend_from_slice(line);
                    buffer.extend_from_slice(b"data: ");
                }
                last_split = split_at;
            }
        }
        if let Some(rest) = buf.get(last_split..) {
            self.event.buffer.as_mut().extend_from_slice(rest);
        }
        buf.len()
    }
}

impl std::fmt::Write for EventDataWriter {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let _ = self.write_buf(value.as_bytes());
        Ok(())
    }
}

/// Configures periodic keep-alive comment pings for an otherwise-idle
/// [`Sse`] stream, matching `axum::response::sse::KeepAlive`.
///
/// Some intermediary proxies/load balancers close connections that go quiet
/// for too long; interleaving a harmless `: <text>` comment line (ignored by
/// SSE clients) at a regular interval keeps the connection alive without the
/// caller's own stream needing to know about it.
///
/// *Axum compatibility: drop-in replacement for `axum::response::sse::KeepAlive`.*
#[derive(Debug, Clone)]
pub struct KeepAlive {
    event: Event,
    interval: std::time::Duration,
}

impl Default for KeepAlive {
    fn default() -> Self {
        Self {
            event: Event::DEFAULT_KEEP_ALIVE,
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
    pub fn text<T: AsRef<str>>(self, text: T) -> Self {
        self.event(Event::default().comment(text))
    }

    /// Sets the exact [`Event`] sent as the keep-alive ping, for cases where
    /// a comment alone isn't enough (e.g. clients that key off `event:`).
    #[must_use]
    pub fn event(mut self, event: Event) -> Self {
        self.event = Event::finalized(event.finalize());
        self
    }
}

pin_project_lite::pin_project! {
    /// Wraps a stream, injecting `keep_alive.event` whenever the inner stream
    /// hasn't produced an item for `keep_alive.interval`. Returned internally by
    /// [`Sse::keep_alive`]. Matches `axum::response::sse::KeepAliveStream`.
    ///
    /// *Axum compatibility: drop-in replacement for `axum::response::sse::KeepAliveStream`.*
    pub struct KeepAliveStream<S> {
        #[pin]
        stream: S,
        interval: tokio::time::Interval,
        comment_event: Event,
    }
}

impl<S> std::fmt::Debug for KeepAliveStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeepAliveStream").finish_non_exhaustive()
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
            Poll::Ready(Some(Ok(event))) => Poll::Ready(Some(Ok(Frame::data(event.finalize())))),
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
///
/// *Axum compatibility: drop-in replacement for `axum::response::Sse`.*
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
                        tokio::time::Instant::now()
                            .checked_add(keep_alive.interval)
                            .unwrap_or_else(tokio::time::Instant::now),
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

    fn wire_format(event: Event) -> Bytes {
        event.finalize()
    }

    #[test]
    fn test_simple_data_event() {
        let s = wire_format(Event::new().data("hello"));
        assert_eq!(&s[..], b"data: hello\n\n");
    }

    #[test]
    fn test_event_with_name_and_id() {
        let s = wire_format(Event::new().event("update").data("payload").id("42"));
        assert_eq!(&s[..], b"event: update\ndata: payload\nid: 42\n\n");
    }

    #[test]
    fn test_multiline_data_split_across_lines() {
        let s = wire_format(Event::new().data("line1\nline2"));
        assert_eq!(&s[..], b"data: line1\ndata: line2\n\n");
    }

    #[test]
    fn test_comment_only_event() {
        let s = wire_format(Event::new().comment("keep-alive"));
        assert_eq!(&s[..], b": keep-alive\n\n");
    }

    #[test]
    fn test_multiple_comments_append() {
        let s = wire_format(Event::new().comment("one").comment("two"));
        assert_eq!(&s[..], b": one\n: two\n\n");
    }

    #[test]
    fn test_retry_field() {
        let s = wire_format(Event::new().retry(std::time::Duration::from_secs(5)));
        assert_eq!(&s[..], b"retry: 5000\n\n");
    }

    /// A newline in `event`/`id`/`comment` must not be able to end the line and inject further
    /// fields — matching axum, this now panics instead of silently stripping.
    #[test]
    #[should_panic(expected = "cannot contain newlines")]
    fn test_id_with_newline_panics() {
        let _ = Event::new().id("42\ndata: injected");
    }

    #[test]
    #[should_panic(expected = "cannot contain newlines")]
    fn test_event_with_newline_panics() {
        let _ = Event::new().event("up\r\ndata: injected");
    }

    /// `data` splits into a new `data: ` line at *every* `\r` or `\n` byte independently
    /// (matching axum exactly) rather than treating `\r\n` as one line break — so a `\r\n`
    /// pair produces an extra empty `data: ` line between the two splits. `comment`/`event`/
    /// `id` instead reject line breaks outright (see the panic tests above).
    #[test]
    fn test_multiline_data_splits_on_every_cr_or_lf_byte() {
        assert_eq!(
            &wire_format(Event::new().data("a\r\nb\rc\nd"))[..],
            b"data: a\rdata: \ndata: b\rdata: c\ndata: d\n\n"
        );
    }

    #[test]
    #[should_panic(expected = "cannot contain newlines")]
    fn test_comment_with_newline_panics() {
        let _ = Event::new().comment("x\r\ny");
    }

    #[test]
    #[should_panic(expected = "multiple times")]
    fn test_data_twice_panics() {
        let _ = Event::new().data("first").data("second");
    }

    #[test]
    #[should_panic(expected = "multiple times")]
    fn test_event_field_twice_panics() {
        let _ = Event::new().event("a").event("b");
    }

    #[test]
    fn test_json_data() {
        #[derive(serde::Serialize)]
        struct Payload {
            n: u32,
        }
        let event = Event::new().json_data(Payload { n: 7 }).unwrap();
        assert_eq!(&wire_format(event)[..], b"data: {\"n\":7}\n\n");
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
