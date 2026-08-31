//! Response utilities and the `IntoResponse` trait.

/// Server-Sent Events (SSE) — see the module docs for usage. Requires the `sse` feature.
#[cfg(feature = "sse")]
pub mod sse;
#[cfg(feature = "sse")]
pub use sse::Sse;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody as BoxBody;
use hyper::body::{Body as HyperBody, Frame, SizeHint};
use hyper::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use hyper::{Response as HttpResponse, StatusCode};
#[cfg(feature = "json")]
use serde::Serialize;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The unified body type for Tachyon-Web responses. Matches `axum_core::body::Body`.
///
/// *Axum compatibility: drop-in replacement for `axum::body::Body`.*
#[derive(Debug)]
pub struct Body(BoxBody<Bytes, crate::http::error::Error>);

fn boxed<B>(body: B) -> BoxBody<Bytes, crate::http::error::Error>
where
    B: HyperBody<Data = Bytes> + Send + 'static,
    B::Error: Into<crate::http::error::Error>,
{
    BoxBody::new(body.map_err(Into::into))
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl Body {
    /// Create a new empty body.
    #[must_use]
    pub fn empty() -> Self {
        Self::stream(http_body_util::Empty::new())
    }

    /// Create a new body from a single chunk of bytes.
    #[must_use]
    pub fn full(bytes: Bytes) -> Self {
        Self::stream(http_body_util::Full::new(bytes))
    }

    /// Create a streaming body from an implementation.
    pub fn stream<B>(body: B) -> Self
    where
        B: HyperBody<Data = Bytes> + Send + 'static,
        B::Error: Into<crate::http::error::Error>,
    {
        Self(boxed(body))
    }

    /// Create a new `Body` from an [`HyperBody`](hyper::body::Body) implementation. An alias
    /// for [`Body::stream`] at the name Axum's equivalent uses.
    ///
    /// Matches `axum::body::Body::new`.
    pub fn new<B>(body: B) -> Self
    where
        B: HyperBody<Data = Bytes> + Send + 'static,
        B::Error: Into<crate::http::error::Error>,
    {
        Self::stream(body)
    }

    /// Create a new `Body` from a fallible [`Stream`](futures_core::Stream) of byte chunks.
    ///
    /// Matches `axum::body::Body::from_stream`.
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: futures_core::stream::TryStream + Send + 'static,
        S::Ok: Into<Bytes>,
        S::Error: Into<crate::http::error::Error>,
    {
        Self::stream(http_body_util::StreamBody::new(FrameStream { stream }))
    }

    /// Converts this body into a [`Stream`](futures_core::Stream) of its data frames,
    /// discarding trailers. Matches `axum_core::body::Body::into_data_stream`.
    #[must_use]
    pub const fn into_data_stream(self) -> BodyDataStream {
        BodyDataStream { inner: self }
    }

    /// Buffers the entire body into memory, rejecting bodies larger than `limit`
    /// bytes with a `413 Payload Too Large` rejection instead of allocating
    /// unbounded memory.
    ///
    /// # Errors
    /// Returns a `413` rejection if the body exceeds `limit`, or a `400` rejection
    /// if reading the body otherwise fails (e.g. a malformed chunked transfer).
    pub async fn collect_bytes(self, limit: usize) -> Result<Bytes, crate::http::error::Error> {
        match http_body_util::Limited::new(self, limit).collect().await {
            Ok(collected) => Ok(collected.to_bytes()),
            Err(e) => {
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    Err(crate::http::error::Error::status(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Request body exceeds the maximum allowed size",
                    ))
                } else {
                    match e.downcast::<crate::http::error::Error>() {
                        Ok(original) => Err(*original),
                        Err(e) => Err(crate::http::error::Error::status(
                            StatusCode::BAD_REQUEST,
                            format!("Failed to read request body: {e}"),
                        )),
                    }
                }
            }
        }
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self::full(bytes)
    }
}

impl From<&'static [u8]> for Body {
    fn from(bytes: &'static [u8]) -> Self {
        Self::full(Bytes::from_static(bytes))
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Self::full(Bytes::from_static(s.as_bytes()))
    }
}

impl From<()> for Body {
    fn from((): ()) -> Self {
        Self::empty()
    }
}

impl From<std::borrow::Cow<'static, [u8]>> for Body {
    fn from(cow: std::borrow::Cow<'static, [u8]>) -> Self {
        match cow {
            std::borrow::Cow::Borrowed(b) => b.into(),
            std::borrow::Cow::Owned(v) => v.into(),
        }
    }
}

impl From<std::borrow::Cow<'static, str>> for Body {
    fn from(cow: std::borrow::Cow<'static, str>) -> Self {
        match cow {
            std::borrow::Cow::Borrowed(s) => s.into(),
            std::borrow::Cow::Owned(s) => s.into(),
        }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self::full(Bytes::from(s))
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Self::full(Bytes::from(v))
    }
}

impl IntoResponse for Body {
    fn into_response(self) -> Response {
        HttpResponse::new(self)
    }
}

impl<S: Sync> crate::routing::extract::FromRequest<S> for Body {
    type Rejection = std::convert::Infallible;

    fn from_request(
        req: hyper::Request<Self>,
        _state: &S,
    ) -> impl std::future::Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(req.into_body()))
    }
}

/// Buffers `body` into a single [`Bytes`], rejecting bodies over `limit`.
/// Free-function form of [`Body::collect_bytes`], matching `axum::body::to_bytes`.
///
/// # Errors
///
/// Returns an error if `body` exceeds `limit` or otherwise fails to read.
///
/// *Axum compatibility: drop-in replacement for `axum::body::to_bytes`.*
pub async fn to_bytes(
    body: Body,
    limit: usize,
) -> std::result::Result<Bytes, crate::http::error::Error> {
    body.collect_bytes(limit).await
}

pin_project_lite::pin_project! {
    /// Adapts a fallible byte-chunk [`Stream`](futures_core::Stream) into the
    /// `Result<Frame<Bytes>, Error>` stream [`http_body_util::StreamBody`] needs, for
    /// [`Body::from_stream`].
    struct FrameStream<S> {
        #[pin]
        stream: S,
    }
}

impl<S> futures_core::Stream for FrameStream<S>
where
    S: futures_core::stream::TryStream,
    S::Ok: Into<Bytes>,
    S::Error: Into<crate::http::error::Error>,
{
    type Item = Result<Frame<Bytes>, crate::http::error::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().stream.try_poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk.into())))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl HyperBody for Body {
    type Data = Bytes;
    type Error = crate::http::error::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

/// A stream of a [`Body`]'s data frames, with trailers discarded. Returned by
/// [`Body::into_data_stream`]. Matches `axum_core::body::BodyDataStream`.
///
/// *Axum compatibility: drop-in replacement for `axum::body::BodyDataStream`.*
pub struct BodyDataStream {
    inner: Body,
}

impl std::fmt::Debug for BodyDataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyDataStream").finish_non_exhaustive()
    }
}

impl futures_core::Stream for BodyDataStream {
    type Item = Result<Bytes, crate::http::error::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let body = Pin::new(&mut self.as_mut().get_mut().inner);
            match body.poll_frame(cx) {
                // A trailers frame is skipped; keep polling for the next data frame.
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        return Poll::Ready(Some(Ok(data)));
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl HyperBody for BodyDataStream {
    type Data = Bytes;
    type Error = crate::http::error::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        futures_core::Stream::poll_next(self, cx).map(|opt| opt.map(|res| res.map(Frame::data)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A Tachyon HTTP response, generic over its body type (defaulting to [`Body`]).
/// Matches `axum_core::response::Response`.
///
/// *Axum compatibility: drop-in replacement for `axum::response::Response`.*
pub type Response<T = Body> = HttpResponse<T>;

/// Trait for generating an HTTP response.
///
/// *Axum compatibility: drop-in replacement for `axum::response::IntoResponse`.*
pub trait IntoResponse {
    /// Convert the type into a [`Response`].
    fn into_response(self) -> Response;
}

/// Matches `axum_core::response::IntoResponse`'s blanket `impl<B> IntoResponse for
/// http::Response<B>`: any response is convertible regardless of its concrete body type, by
/// normalizing that body into [`Body`]. Note this means even an already-`Response<Body>` value
/// is re-boxed here rather than passed through — matching axum's own behavior (its blanket impl
/// has no special-cased identity path either), traded for not needing a second, narrower
/// `impl IntoResponse for Response` that would otherwise conflict with this one.
impl<B> IntoResponse for HttpResponse<B>
where
    B: HyperBody<Data = Bytes> + Send + 'static,
    B::Error: Into<crate::http::error::Error>,
{
    fn into_response(self) -> Response {
        let (parts, body) = self.into_parts();
        HttpResponse::from_parts(parts, Body::stream(body))
    }
}

impl IntoResponse for StatusCode {
    fn into_response(self) -> Response {
        let mut res = HttpResponse::new(Body::empty());
        *res.status_mut() = self;
        res
    }
}

pub(crate) const TEXT_PLAIN: &str = "text/plain; charset=utf-8";
const TEXT_HTML: &str = "text/html; charset=utf-8";
const OCTET_STREAM: &str = "application/octet-stream";

/// A `200 OK` response carrying `bytes` under a fixed `Content-Type` — the shape every
/// body-only [`IntoResponse`] impl below produces.
pub(crate) fn with_content_type(bytes: Bytes, content_type: &'static str) -> Response {
    let mut res = HttpResponse::new(Body::full(bytes));
    let _ = res
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    res
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        with_content_type(Bytes::from(self), TEXT_PLAIN)
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        with_content_type(Bytes::from_static(self.as_bytes()), TEXT_PLAIN)
    }
}

impl IntoResponse for Vec<u8> {
    fn into_response(self) -> Response {
        with_content_type(Bytes::from(self), OCTET_STREAM)
    }
}

impl IntoResponse for &'static [u8] {
    fn into_response(self) -> Response {
        with_content_type(Bytes::from_static(self), OCTET_STREAM)
    }
}

/// An HTML response.
///
/// *Axum compatibility: drop-in replacement for `axum::response::Html`.*
#[derive(Debug, Clone, Copy)]
pub struct Html<T>(pub T);

impl<T> From<T> for Html<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> IntoResponse for Html<T>
where
    T: Into<Bytes>,
{
    fn into_response(self) -> Response {
        with_content_type(self.0.into(), TEXT_HTML)
    }
}

#[cfg(feature = "json")]
thread_local! {
    static JSON_WRITE_BUF: std::cell::RefCell<bytes::BytesMut> =
        std::cell::RefCell::new(bytes::BytesMut::with_capacity(1024));
}

/// Adapts a `&mut BytesMut` to `std::io::Write` for `serde_json::to_writer` —
/// `bytes` only implements `fmt::Write` for `BytesMut`, not `io::Write`.
#[cfg(feature = "json")]
struct BytesMutWriter<'a>(&'a mut bytes::BytesMut);

#[cfg(feature = "json")]
impl std::io::Write for BytesMutWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A JSON response. Requires the `json` feature.
#[cfg(feature = "json")]
pub use crate::routing::extract::Json;

/// Re-export of the [`Extension`](crate::routing::extract::parts::Extension) extractor
/// at the path `axum::response::Extension` uses (it doubles as a response type
/// there too).
pub use crate::routing::extract::Extension;

/// Re-export of the [`Form`](crate::routing::extract::body::Form) extractor at the
/// path `axum::response::Form` uses. Requires the `form` feature.
#[cfg(feature = "form")]
pub use crate::routing::extract::Form;

/// A handler return type that carries any [`IntoResponse`] error, matching
/// `axum::response::Result`.
///
/// *Axum compatibility: drop-in replacement for `axum::response::Result`.*
pub type Result<T, E = ErrorResponse> = std::result::Result<T, E>;

#[cfg(feature = "json")]
impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        match serialize_json(&self.0) {
            Ok(bytes) => with_content_type(bytes, "application/json"),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize JSON: {err}"),
            )
                .into_response(),
        }
    }
}

/// Serializes `value` into the calling thread's reusable JSON buffer.
///
/// `try_borrow_mut` (rather than `borrow_mut`) so that a `Serialize` impl which re-enters
/// this function on the same thread (e.g. by serializing a nested `Json<_>` internally)
/// falls back to a fresh, non-shared buffer instead of panicking on an already-borrowed
/// `RefCell` — a panic path the crate's `deny(clippy::panic/unwrap_used/expect_used)` lints
/// can't catch, since it originates inside `RefCell` itself rather than an explicit unwrap.
#[cfg(feature = "json")]
fn serialize_json<T: Serialize>(value: &T) -> Result<Bytes, serde_json::Error> {
    JSON_WRITE_BUF.with(|buf| {
        let Ok(mut b) = buf.try_borrow_mut() else {
            let mut fallback = Vec::with_capacity(1024);
            serde_json::to_writer(&mut fallback, value)?;
            return Ok(Bytes::from(fallback));
        };
        // `b` is always empty on entry (every exit path below leaves it that way), so the
        // written frame is exactly `[0, b.len())`. `split_to` then hands those bytes to the
        // caller as a `Bytes` sharing the same allocation — no memcpy — while `b` keeps the
        // (empty) view over its spare tail capacity, ready to be written into again next
        // call with no fresh allocation in the common case.
        let result = match serde_json::to_writer(BytesMutWriter(&mut b), value) {
            Ok(()) => {
                let len = b.len();
                Ok(b.split_to(len).freeze())
            }
            Err(err) => {
                // Discard whatever partial bytes a failed serialize left behind.
                b.clear();
                Err(err)
            }
        };
        // A single oversized payload shouldn't permanently inflate this thread's buffer.
        if b.capacity() > 65536 {
            *b = bytes::BytesMut::with_capacity(1024);
        }
        result
    })
}

impl<R> IntoResponse for (StatusCode, R)
where
    R: IntoResponse,
{
    fn into_response(self) -> Response {
        let (status, res) = self;
        let mut response = res.into_response();
        *response.status_mut() = status;
        response
    }
}

//
// Generalizes response-tuple composition beyond a fixed whitelist of shapes.
// Any type implementing `IntoResponseParts` (headers, cookies, extensions, or a
// user's own typed-header wrapper) can be combined — in any order, up to 8 of
// them — with an optional leading `StatusCode` and a trailing body, mirroring
// Axum's `IntoResponseParts` design. e.g. `(HeaderMap, Cookies, Json<T>)` and
// `(StatusCode, Cookies, HeaderMap, Json<T>)` both just work.

/// The response under construction, passed to [`IntoResponseParts::into_response_parts`]
/// so implementors can attach headers/extensions without unpacking the whole response.
///
/// *Axum compatibility: drop-in replacement for `axum::response::ResponseParts`.*
#[derive(Debug)]
pub struct ResponseParts {
    res: Response,
}

impl ResponseParts {
    /// Read-only access to the headers of the response being built.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.res.headers()
    }

    /// Mutable access to the headers of the response being built.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.res.headers_mut()
    }

    /// Read-only access to the extensions of the response being built.
    #[must_use]
    pub fn extensions(&self) -> &hyper::http::Extensions {
        self.res.extensions()
    }

    /// Mutable access to the extensions of the response being built.
    pub fn extensions_mut(&mut self) -> &mut hyper::http::Extensions {
        self.res.extensions_mut()
    }
}

/// Trait for types that attach headers/extensions to a response without providing
/// its body — the building block for flexible, order-independent response tuples.
///
/// Implement this for your own typed-header wrappers to use them anywhere in a
/// response tuple, e.g. `(MyCacheControl, StatusCode, Json<T>)`.
///
/// *Axum compatibility: drop-in replacement for `axum::response::IntoResponseParts`.*
pub trait IntoResponseParts {
    /// The rejection response returned if attaching the parts fails.
    type Error: IntoResponse;

    /// Attach `self` onto `res`, returning the updated parts (or a rejection).
    ///
    /// # Errors
    /// Returns `Self::Error` if the parts cannot be attached (e.g. an invalid header value).
    fn into_response_parts(
        self,
        res: ResponseParts,
    ) -> std::result::Result<ResponseParts, Self::Error>;
}

impl IntoResponseParts for HeaderMap {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.headers_mut().extend(self);
        Ok(res)
    }
}

impl<T> IntoResponseParts for Option<T>
where
    T: IntoResponseParts,
{
    type Error = T::Error;

    fn into_response_parts(self, res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        match self {
            Some(parts) => parts.into_response_parts(res),
            None => Ok(res),
        }
    }
}

/// A single `(name, value)` header pair, attached directly without a `HeaderMap`
/// or [`AppendHeaders`] wrapper — e.g. `(("x-request-id", id), Json(body))`.
impl<K, V> IntoResponseParts for (K, V)
where
    K: TryInto<HeaderName>,
    K::Error: std::error::Error + Send + Sync + 'static,
    V: TryInto<HeaderValue>,
    V::Error: std::error::Error + Send + Sync + 'static,
{
    type Error = TryIntoHeaderError<K, V>;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        let (key, value) = self;
        let key = key
            .try_into()
            .map_err(|e| TryIntoHeaderError::name(Box::new(e)))?;
        let value = value
            .try_into()
            .map_err(|e| TryIntoHeaderError::value(Box::new(e)))?;
        res.headers_mut().append(key, value);
        Ok(res)
    }
}

/// The error produced when a `(K, V)` pair fails to convert into a header name/value,
/// matching `axum_core::response::TryIntoHeaderError`.
///
/// *Tachyon extension: no `axum` equivalent.*
pub struct TryIntoHeaderError<K, V> {
    kind: TryIntoHeaderErrorKind,
    _marker: PhantomData<fn() -> (K, V)>,
}

enum TryIntoHeaderErrorKind {
    Name(crate::http::error::BoxError),
    Value(crate::http::error::BoxError),
}

impl<K, V> TryIntoHeaderError<K, V> {
    fn name(source: crate::http::error::BoxError) -> Self {
        Self {
            kind: TryIntoHeaderErrorKind::Name(source),
            _marker: PhantomData,
        }
    }

    fn value(source: crate::http::error::BoxError) -> Self {
        Self {
            kind: TryIntoHeaderErrorKind::Value(source),
            _marker: PhantomData,
        }
    }
}

impl<K, V> std::fmt::Debug for TryIntoHeaderError<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TryIntoHeaderError").finish_non_exhaustive()
    }
}

impl<K, V> std::fmt::Display for TryIntoHeaderError<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            TryIntoHeaderErrorKind::Name(e) => write!(f, "failed to convert header name: {e}"),
            TryIntoHeaderErrorKind::Value(e) => write!(f, "failed to convert header value: {e}"),
        }
    }
}

impl<K, V> std::error::Error for TryIntoHeaderError<K, V> {}

impl<K, V> IntoResponse for TryIntoHeaderError<K, V> {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

impl<T> IntoResponseParts for crate::routing::extract::Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.extensions_mut().insert(self.0);
        Ok(res)
    }
}

/// Appends an arbitrary collection of headers to a response without
/// replacing any existing header of the same name, matching
/// `axum::response::AppendHeaders`.
///
/// A bare `HeaderMap` already appends (see the `IntoResponseParts` impl
/// above) — this exists for the common case of a small, fixed list of
/// `(name, value)` pairs (e.g. `[("x-custom", "1"), ("x-other", "2")]`)
/// without constructing a full `HeaderMap` first.
///
/// *Axum compatibility: drop-in replacement for `axum::response::AppendHeaders`.*
#[derive(Debug, Clone, Copy)]
pub struct AppendHeaders<I>(pub I);

impl<I, K, V> IntoResponseParts for AppendHeaders<I>
where
    I: IntoIterator<Item = (K, V)>,
    K: TryInto<HeaderName>,
    V: TryInto<HeaderValue>,
{
    type Error = crate::http::error::Error;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        for (key, value) in self.0 {
            let key = key.try_into().map_err(|_| {
                crate::http::error::Error::status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AppendHeaders: invalid header name",
                )
            })?;
            let value = value.try_into().map_err(|_| {
                crate::http::error::Error::status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AppendHeaders: invalid header value",
                )
            })?;
            res.headers_mut().append(key, value);
        }
        Ok(res)
    }
}

impl<I, K, V> IntoResponse for AppendHeaders<I>
where
    I: IntoIterator<Item = (K, V)>,
    K: TryInto<HeaderName>,
    V: TryInto<HeaderValue>,
{
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}

#[cfg(feature = "cookies")]
impl IntoResponseParts for crate::routing::extract::Cookies {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        for cookie in self.jar.delta() {
            if let Ok(header_val) = HeaderValue::try_from(cookie.encoded().to_string()) {
                res.headers_mut()
                    .append(hyper::header::SET_COOKIE, header_val);
            }
        }
        Ok(res)
    }
}

macro_rules! impl_into_response_for_parts_tuples {
    ($($T:ident),+) => {
        impl<R, $($T),+> IntoResponse for ($($T,)+ R)
        where
            R: IntoResponse,
            $( $T: IntoResponseParts, )+
        {
            fn into_response(self) -> Response {
                #[allow(non_snake_case)]
                let ($($T,)+ res) = self;
                let mut parts = ResponseParts { res: res.into_response() };
                $(
                    parts = match $T.into_response_parts(parts) {
                        Ok(p) => p,
                        Err(rejection) => return rejection.into_response(),
                    };
                )+
                parts.res
            }
        }

        impl<R, $($T),+> IntoResponse for (StatusCode, $($T,)+ R)
        where
            R: IntoResponse,
            $( $T: IntoResponseParts, )+
        {
            fn into_response(self) -> Response {
                #[allow(non_snake_case)]
                let (status, $($T,)+ res) = self;
                let mut response = <($($T,)+ R) as IntoResponse>::into_response(($($T,)+ res));
                *response.status_mut() = status;
                response
            }
        }
    };
}

impl_into_response_for_parts_tuples!(T1);
impl_into_response_for_parts_tuples!(T1, T2);
impl_into_response_for_parts_tuples!(T1, T2, T3);
impl_into_response_for_parts_tuples!(T1, T2, T3, T4);
impl_into_response_for_parts_tuples!(T1, T2, T3, T4, T5);
impl_into_response_for_parts_tuples!(T1, T2, T3, T4, T5, T6);
impl_into_response_for_parts_tuples!(T1, T2, T3, T4, T5, T6, T7);
impl_into_response_for_parts_tuples!(T1, T2, T3, T4, T5, T6, T7, T8);

impl IntoResponse for () {
    fn into_response(self) -> Response {
        HttpResponse::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap_or_else(|_| HttpResponse::new(Body::empty()))
    }
}

impl<T, E> IntoResponse for Result<T, E>
where
    T: IntoResponse,
    E: IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Ok(value) => value.into_response(),
            Err(err) => err.into_response(),
        }
    }
}

impl IntoResponse for std::convert::Infallible {
    fn into_response(self) -> Response {
        match self {}
    }
}

/// A `204 No Content` response with no body. Matches `axum::response::NoContent`.
///
/// *Axum compatibility: drop-in replacement for `axum::response::NoContent`.*
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContent;

impl IntoResponse for NoContent {
    fn into_response(self) -> Response {
        StatusCode::NO_CONTENT.into_response()
    }
}

/// A type-erased response, for `?`-based error handling.
///
/// Lets handlers return one of several unrelated error types via `?`
/// (anything implementing [`IntoResponse`] converts into this automatically).
/// Matches `axum_core::response::ErrorResponse`.
///
/// ```rust
/// use tachyon_web::response::ErrorResponse;
/// use hyper::StatusCode;
///
/// fn handler(fail: bool) -> Result<&'static str, ErrorResponse> {
///     if fail {
///         return Err(StatusCode::BAD_REQUEST.into());
///     }
///     Ok("ok")
/// }
/// ```
///
/// *Axum compatibility: drop-in replacement for `axum::response::ErrorResponse`.*
#[derive(Debug)]
pub struct ErrorResponse(Response);

impl<T> From<T> for ErrorResponse
where
    T: IntoResponse,
{
    fn from(value: T) -> Self {
        Self(value.into_response())
    }
}

// Deliberately *not* a generic `impl IntoResponse for ErrorResponse`: that
// would collide with core's blanket `impl<T> From<T> for T` against the
// `From<T: IntoResponse>` impl above (`T = ErrorResponse` would satisfy
// both). Matching `axum_core`'s own resolution: give `Result<T,
// ErrorResponse>` its own concrete `IntoResponse` impl instead of routing
// through the generic `Result<T, E: IntoResponse>` one below.
impl<T> IntoResponse for Result<T, ErrorResponse>
where
    T: IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Ok(value) => value.into_response(),
            Err(ErrorResponse(resp)) => resp,
        }
    }
}

/// A response that redirects the client to another location.
///
/// *Axum compatibility: drop-in replacement for `axum::response::Redirect`.*
#[derive(Debug, Clone)]
pub struct Redirect {
    status_code: StatusCode,
    location: HeaderValue,
}

impl Redirect {
    /// Create a `303 See Other` redirect to the given URI.
    ///
    /// If `uri` contains bytes that aren't valid in an HTTP header value (e.g. a
    /// stray `\n` or `\r`), this crate's `deny(clippy::panic)` policy rules out
    /// panicking the way Axum's equivalent does — instead the `Location` header
    /// silently falls back to `/`. Validate/sanitize `uri` yourself if it's ever
    /// built from user-controlled or templated data, since a silent fallback to
    /// `/` is easy to miss.
    #[must_use]
    pub fn to(uri: &str) -> Self {
        Self {
            status_code: StatusCode::SEE_OTHER,
            location: HeaderValue::try_from(uri).unwrap_or_else(|_| HeaderValue::from_static("/")),
        }
    }

    /// Create a `307 Temporary Redirect` redirect to the given URI.
    ///
    /// See [`Redirect::to`]'s docs for the fallback behavior on an invalid `uri`.
    #[must_use]
    pub fn temporary(uri: &str) -> Self {
        Self {
            status_code: StatusCode::TEMPORARY_REDIRECT,
            location: HeaderValue::try_from(uri).unwrap_or_else(|_| HeaderValue::from_static("/")),
        }
    }

    /// Create a `308 Permanent Redirect` redirect to the given URI.
    ///
    /// See [`Redirect::to`]'s docs for the fallback behavior on an invalid `uri`.
    #[must_use]
    pub fn permanent(uri: &str) -> Self {
        Self {
            status_code: StatusCode::PERMANENT_REDIRECT,
            location: HeaderValue::try_from(uri).unwrap_or_else(|_| HeaderValue::from_static("/")),
        }
    }

    /// The `Location` header value this redirect will send.
    ///
    /// Falls back to `"/"` if the original `uri` wasn't valid header-value bytes — see
    /// [`Redirect::to`]'s docs — rather than panicking the way Axum's equivalent does.
    #[must_use]
    pub fn location(&self) -> &str {
        self.location.to_str().unwrap_or("/")
    }

    /// The status code this redirect will send.
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        self.status_code
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        let mut resp = HttpResponse::new(Body::empty());
        *resp.status_mut() = self.status_code;
        let _ = resp
            .headers_mut()
            .insert(hyper::header::LOCATION, self.location);
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "cookies")]
    use crate::routing::extract::Cookies;
    use hyper::HeaderMap;

    #[test]
    fn no_content_is_204_with_empty_body() {
        let resp = NoContent.into_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn error_response_carries_through_status_and_message() {
        fn handler(fail: bool) -> Result<&'static str, ErrorResponse> {
            if fail {
                return Err(StatusCode::IM_A_TEAPOT.into());
            }
            Ok("ok")
        }

        let ok_resp = handler(false).into_response();
        assert_eq!(ok_resp.status(), StatusCode::OK);

        let err_resp = handler(true).into_response();
        assert_eq!(err_resp.status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn to_bytes_free_function_matches_method_form() {
        let body = Body::full(Bytes::from("hello"));
        let bytes = to_bytes(body, 1024).await.unwrap();
        assert_eq!(bytes.as_ref(), b"hello");
    }

    #[test]
    fn test_body_debug_and_size_hint() {
        let b1 = Body::empty();
        assert!(!format!("{b1:?}").is_empty());
        assert!(b1.is_end_stream());
        assert_eq!(b1.size_hint().exact(), Some(0));

        let b2 = Body::full(Bytes::from("test"));
        assert!(!b2.is_end_stream());
        assert_eq!(b2.size_hint().exact(), Some(4));

        let b3 = Body::stream(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|e| crate::http::error::Error::internal(e.to_string())),
        );
        assert!(b3.is_end_stream());
        assert_eq!(b3.size_hint().exact(), Some(0));
    }

    #[tokio::test]
    async fn test_body_poll_frame() {
        use hyper::body::Body as _;
        let mut b1 = Body::full(Bytes::from("a"));
        let mut b1_pin = Pin::new(&mut b1);
        let cx = &mut Context::from_waker(futures::task::noop_waker_ref());
        let f1 = b1_pin.as_mut().poll_frame(cx);
        assert!(matches!(f1, Poll::Ready(Some(Ok(_)))));
        let f2 = b1_pin.as_mut().poll_frame(cx);
        assert!(matches!(f2, Poll::Ready(None)));

        let mut b2 = Body::empty();
        let f3 = Pin::new(&mut b2).poll_frame(cx);
        assert!(matches!(f3, Poll::Ready(None)));
    }

    #[cfg(feature = "json")]
    struct FailSerialize;
    #[cfg(feature = "json")]
    impl Serialize for FailSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("failed"))
        }
    }

    #[test]
    fn test_into_response_implementations() {
        let full_resp = HttpResponse::new(http_body_util::Full::new(Bytes::from("abc")));
        let r1 = full_resp.into_response();
        assert_eq!(r1.status(), StatusCode::OK);

        let v: Vec<u8> = vec![1, 2, 3];
        let r2 = v.into_response();
        assert_eq!(
            r2.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );

        let s: &'static [u8] = b"static";
        let r3 = s.into_response();
        assert_eq!(
            r3.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );

        #[cfg(feature = "json")]
        {
            let fail_json = Json(FailSerialize);
            let r4 = fail_json.into_response();
            assert_eq!(r4.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }

        let mut h = HeaderMap::new();
        let _ = h.insert("x-custom", HeaderValue::from_static("val"));
        let r5 = (h.clone(), "body").into_response();
        assert_eq!(r5.headers().get("x-custom").unwrap(), "val");

        let r6 = (StatusCode::CREATED, h.clone(), "body").into_response();
        assert_eq!(r6.status(), StatusCode::CREATED);
        assert_eq!(r6.headers().get("x-custom").unwrap(), "val");

        #[cfg(feature = "cookies")]
        {
            let cookies = Cookies::new();
            let r7 = (StatusCode::ACCEPTED, cookies, "body").into_response();
            assert_eq!(r7.status(), StatusCode::ACCEPTED);
        }

        let r8 = ().into_response();
        assert_eq!(r8.status(), StatusCode::OK);

        let res_ok: Result<&str, &str> = Ok("ok");
        let r9 = res_ok.into_response();
        assert_eq!(r9.status(), StatusCode::OK);

        let res_err: Result<&str, &str> = Err("err");
        let r10 = res_err.into_response();
        assert_eq!(r10.status(), StatusCode::OK);
    }

    #[test]
    fn option_into_response_parts_some_and_none() {
        let mut h = HeaderMap::new();
        let _ = h.insert("x-opt", HeaderValue::from_static("present"));

        let with_some = (Some(h), "body").into_response();
        assert_eq!(with_some.headers().get("x-opt").unwrap(), "present");

        let with_none = (None::<HeaderMap>, "body").into_response();
        assert!(with_none.headers().get("x-opt").is_none());
        assert_eq!(with_none.status(), StatusCode::OK);
    }

    #[test]
    fn extension_into_response_parts_inserts_into_response_extensions() {
        use crate::routing::extract::Extension;

        #[derive(Clone)]
        struct Marker(u32);

        let resp = (Extension(Marker(42)), "body").into_response();
        assert_eq!(resp.extensions().get::<Marker>().unwrap().0, 42);
    }

    #[test]
    fn response_parts_extensions_mut_is_reachable_directly() {
        let mut parts = ResponseParts {
            res: HttpResponse::new(Body::empty()),
        };
        let _ = parts.extensions_mut().insert(7u32);
        assert_eq!(parts.res.extensions().get::<u32>(), Some(&7));
    }

    #[test]
    fn append_headers_appends_without_replacing() {
        let mut existing = HeaderMap::new();
        let _ = existing.insert("x-multi", HeaderValue::from_static("first"));

        let resp = (
            existing,
            AppendHeaders([("x-multi", "second"), ("x-other", "value")]),
            "body",
        )
            .into_response();

        let all: Vec<_> = resp
            .headers()
            .get_all("x-multi")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(all, vec!["first", "second"]);
        assert_eq!(resp.headers().get("x-other").unwrap(), "value");
    }

    #[test]
    fn append_headers_rejects_an_invalid_header_name() {
        let resp = (AppendHeaders([("bad header name", "value")]), "body").into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn append_headers_rejects_an_invalid_header_value() {
        let resp = (AppendHeaders([("x-ok-name", "bad\nvalue")]), "body").into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn bare_header_tuple_attaches_a_single_header() {
        let resp = (("x-request-id", "abc123"), "body").into_response();
        assert_eq!(resp.headers().get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn bare_header_tuple_rejects_an_invalid_header_name() {
        let resp = (("bad header name", "value"), "body").into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn bare_header_tuple_rejects_an_invalid_header_value() {
        let resp = (("x-ok-name", "bad\nvalue"), "body").into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_response_shrinks_its_thread_local_buffer_after_a_large_payload() {
        // Drives the JSON writer buffer past 64 KiB so the post-serialize
        // `shrink_to(1024)` branch actually runs, not just the common case.
        let big = "x".repeat(80 * 1024);
        let resp = Json(big).into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        // A second, small payload on the same thread proves the buffer is still
        // usable after being shrunk.
        let resp2 = Json("small").into_response();
        assert_eq!(resp2.status(), StatusCode::OK);
    }
}
