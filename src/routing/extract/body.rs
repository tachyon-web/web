//! Body-consuming extractors: [`Json`], [`Form`]/[`RawForm`], [`Bytes`], [`String`],
//! [`BodyStream`], and the [`DefaultBodyLimit`] layer that configures them.

use crate::http::error::Error;
use crate::http::response::Body;
use bytes::Bytes;
#[cfg(any(feature = "json", feature = "form"))]
use serde::de::DeserializeOwned;
use std::convert::Infallible;
use std::future::Future;

#[cfg(feature = "form")]
use crate::routing::extract::FromRequestParts;
#[cfg(feature = "form")]
use crate::routing::extract::query::QueryIter;
use crate::routing::extract::{FromRequest, rejection};

/// The maximum request-body size assumed by body-buffering extractors
/// (`Bytes`, `String`, `Json`, `Form`) when no [`MaxBodySize`] extension is
/// present on the request — e.g. when calling [`crate::routing::CompiledRouter::handle_request`]
/// directly rather than through [`crate::server::Server`], which always sets it
/// from `Server::max_body_size`.
///
/// 2 MiB, matching Axum's `DefaultBodyLimit` default exactly (Axum: "for
/// security reasons, `Bytes` will, by default, not accept bodies larger than
/// 2MB"). Override per-deployment via [`crate::server::Server::max_body_size`].
pub(crate) const DEFAULT_MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Internal: the configured maximum request-body size, threaded through request
/// extensions (by the connection layer) so body-buffering extractors can enforce
/// it without needing direct access to the `Server` that's handling the request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MaxBodySize(pub usize);

pub(crate) fn max_body_size(extensions: &hyper::http::Extensions) -> usize {
    extensions
        .get::<MaxBodySize>()
        .map_or(DEFAULT_MAX_BODY_SIZE, |m| m.0)
}

/// Overrides the request-body size limit enforced by the `Bytes`/`String`/
/// `Json`/`Form` extractors, for a specific set of routes.
///
/// Mirrors `axum::extract::DefaultBodyLimit`, including how it's applied —
/// as a real `tower::Layer`:
///
/// ```rust,no_run
/// use tachyon_web::extract::DefaultBodyLimit;
/// use tachyon_web::{Router, get};
///
/// async fn upload() -> &'static str { "ok" }
///
/// let _app: Router<()> = Router::new()
///     .route("/upload", get(upload))
///     .layer(DefaultBodyLimit::max(50 * 1024 * 1024));
/// ```
///
/// Unlike a foreign Tower body-limit layer, this never buffers the body
/// itself — it only sets an extension the `Bytes`/`String`/`Json`/`Form`
/// extractors read lazily, when (and if) they actually buffer the body
/// themselves — so layering order relative to *this* layer doesn't matter.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::DefaultBodyLimit`.*
#[derive(Debug, Clone, Copy)]
pub struct DefaultBodyLimit {
    /// `None` means disabled (`usize::MAX`).
    limit: Option<usize>,
}

impl DefaultBodyLimit {
    /// Sets the maximum accepted request-body size, in bytes, for the routes
    /// this is applied to.
    #[must_use]
    pub const fn max(limit: usize) -> Self {
        Self { limit: Some(limit) }
    }

    /// Disables the body-size limit entirely for the routes this is applied
    /// to. Matches `axum::extract::DefaultBodyLimit::disable`.
    #[must_use]
    pub const fn disable() -> Self {
        Self { limit: None }
    }

    /// Sets this limit directly on `req`'s extensions, for callers driving extractors
    /// without going through the `tower::Layer` chain this type also implements.
    /// Matches `axum::extract::DefaultBodyLimit::apply`.
    pub fn apply<B>(self, req: &mut hyper::Request<B>) {
        req.extensions_mut()
            .insert(MaxBodySize(self.limit.unwrap_or(usize::MAX)));
    }
}

impl<S> tower::Layer<S> for DefaultBodyLimit {
    type Service = DefaultBodyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DefaultBodyLimitService {
            limit: self.limit.unwrap_or(usize::MAX),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`DefaultBodyLimit`]'s `tower::Layer` impl.
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Debug, Clone)]
pub struct DefaultBodyLimitService<S> {
    limit: usize,
    inner: S,
}

impl<S> tower::Service<hyper::Request<Body>> for DefaultBodyLimitService<S>
where
    S: tower::Service<hyper::Request<Body>, Response = hyper::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = hyper::Response<Body>;
    type Error = Infallible;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<hyper::Response<Body>, Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: hyper::Request<Body>) -> Self::Future {
        let _ = req.extensions_mut().insert(MaxBodySize(self.limit));
        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}

/// Returns `true` if `content_type` denotes a JSON media type, matching Axum's check:
/// the type must be `application` and the subtype must be `json` or end in `+json`
/// (e.g. `application/json`, `application/json; charset=utf-8`, `application/vnd.api+json`).
#[cfg(feature = "json")]
pub(crate) fn is_json_content_type(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or("").trim();
    let Some((ty, subtype)) = essence.split_once('/') else {
        return false;
    };
    if !ty.eq_ignore_ascii_case("application") {
        return false;
    }
    // `get` rather than an index: a split landing mid-codepoint yields `None`, which is the
    // right answer anyway since `+json` is ASCII.
    subtype.eq_ignore_ascii_case("json")
        || subtype
            .len()
            .checked_sub("+json".len())
            .and_then(|split| subtype.get(split..))
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+json"))
}

/// Extractor for JSON payloads. Requires the `json` feature.
///
/// *Axum compatibility: drop-in replacement for `axum::Json`.*
#[cfg(feature = "json")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

#[cfg(feature = "json")]
impl<T> std::ops::Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "json")]
impl<T> std::ops::DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "json")]
impl<T> From<T> for Json<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[cfg(feature = "json")]
impl<T> Json<T>
where
    T: DeserializeOwned,
{
    /// Deserializes `bytes` directly as JSON, bypassing the `Content-Type` check and
    /// request-body machinery `FromRequest` uses. Matches `axum::Json::from_bytes`.
    ///
    /// # Errors
    /// Returns a rejection if `bytes` isn't valid JSON, or doesn't match `T`'s shape.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rejection::JsonRejection> {
        serde_json::from_slice::<T>(bytes).map(Self).map_err(|e| {
            // See the `FromRequest` impl below for why this splits on `e.classify()`.
            let message = format!("Failed to deserialize JSON payload: {e}");
            match e.classify() {
                serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                    rejection::JsonSyntaxError(message).into()
                }
                serde_json::error::Category::Data | serde_json::error::Category::Io => {
                    rejection::JsonDataError(message).into()
                }
            }
        })
    }
}

#[cfg(feature = "json")]
impl<S, T> FromRequest<S> for Json<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::JsonRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        // Validate Content-Type: must be a JSON media type (`application/json`, optionally
        // with parameters, or any `application/*+json` vendor/suffix type).
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_json_content_type(ct) {
            return Err(rejection::MissingJsonContentType.into());
        }
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::BytesRejection::from)?;
        Self::from_bytes(&body)
    }
}
#[cfg(feature = "json")]
impl<S, T> super::OptionalFromRequest<S> for Json<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::JsonRejection;

    async fn from_request(
        req: hyper::Request<Body>,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        if req.headers().get(hyper::header::CONTENT_TYPE).is_none() {
            return Ok(None);
        }
        <Self as FromRequest<S>>::from_request(req, state)
            .await
            .map(Some)
    }
}

impl<S: Sync> FromRequest<S> for Bytes {
    type Rejection = rejection::BytesRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        req.into_body()
            .collect_bytes(limit)
            .await
            .map_err(Into::into)
    }
}

impl<S: Sync> FromRequest<S> for String {
    type Rejection = rejection::StringRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::FailedToBufferBody::from)?;
        Self::from_utf8(body.to_vec()).map_err(|e| {
            rejection::InvalidUtf8(format!("Request body is not valid UTF-8: {e}")).into()
        })
    }
}
/// Extractor for form-urlencoded payloads. Requires the `form` feature.
///
/// *Axum compatibility: drop-in replacement for `axum::Form`.*
#[cfg(feature = "form")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Form<T>(pub T);

#[cfg(feature = "form")]
impl<T> std::ops::Deref for Form<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "form")]
impl<T> std::ops::DerefMut for Form<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "form")]
impl<S: Sync, T> FromRequestParts<S> for Form<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::FormRejection;

    /// Deserializes from the URL query string — matches Axum's `Form` extractor,
    /// which reads `GET`/`HEAD` requests from the query string rather than the
    /// (typically absent) body. See [`FromRequest`] for the `POST`/body path.
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            let query_str = parts.uri.query().unwrap_or("");
            let iter = QueryIter { input: query_str };
            let map_de = serde::de::value::MapDeserializer::new(iter);
            T::deserialize(map_de)
                .map(Form)
                .map_err(|e: serde::de::value::Error| {
                    rejection::FailedToDeserializeForm(format!(
                        "Failed to deserialize form payload: {e}"
                    ))
                    .into()
                })
        })
    }
}

#[cfg(feature = "form")]
impl<S, T> FromRequest<S> for Form<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::FormRejection;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        // Matches Axum: `GET`/`HEAD` requests are read from the query string (no
        // body/Content-Type expected — this is the common "search form" pattern);
        // every other method reads and deserializes the request body.
        if req.method() == hyper::Method::GET || req.method() == hyper::Method::HEAD {
            let (mut parts, _body) = req.into_parts();
            return Self::from_request_parts(&mut parts, state).await;
        }

        // Validate Content-Type: must be application/x-www-form-urlencoded.
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let essence = ct.split(';').next().unwrap_or("").trim();
        if !essence.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            return Err(rejection::InvalidFormContentType.into());
        }
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::BytesRejection::from)?;
        let body_str = std::str::from_utf8(&body).map_err(|_| {
            rejection::FailedToDeserializeFormBody("Form body is not valid UTF-8".to_string())
        })?;
        let iter = QueryIter { input: body_str };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        T::deserialize(map_de)
            .map(Form)
            .map_err(|e: serde::de::value::Error| {
                rejection::FailedToDeserializeFormBody(format!(
                    "Failed to deserialize form payload: {e}"
                ))
                .into()
            })
    }
}

/// Extractor for the raw, un-deserialized form payload, bypassing [`Form`]'s
/// `serde` deserialization step entirely. Matches `axum::extract::RawForm`.
///
/// For `GET`/`HEAD` requests this is the raw query string; for other methods
/// it's the raw `application/x-www-form-urlencoded` request body. Requires
/// the `form` feature.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::RawForm`.*
#[cfg(feature = "form")]
#[derive(Debug, Clone)]
pub struct RawForm(pub Bytes);

#[cfg(feature = "form")]
impl<S> FromRequest<S> for RawForm
where
    S: Sync,
{
    type Rejection = rejection::RawFormRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        if req.method() == hyper::Method::GET || req.method() == hyper::Method::HEAD {
            return Ok(Self(req.uri().query().map_or_else(Bytes::new, |q| {
                Bytes::copy_from_slice(q.as_bytes())
            })));
        }

        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let essence = ct.split(';').next().unwrap_or("").trim();
        if !essence.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            return Err(rejection::InvalidFormContentType.into());
        }
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::BytesRejection::from)?;
        Ok(Self(body))
    }
}
impl<S: Sync> FromRequest<S> for hyper::Request<Bytes> {
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        let (parts, body) = req.into_parts();
        let bytes = body.collect_bytes(limit).await?;
        Ok(Self::from_parts(parts, bytes))
    }
}

/// Extractor providing direct, un-buffered access to the request body as a
/// stream — for handlers that want to process large uploads incrementally
/// instead of buffering the whole body into memory first.
///
/// Unlike `Bytes`, `String`, `Json`, and `Form`, this never allocates a single
/// contiguous buffer for the body and is not subject to [`crate::server::Server::max_body_size`]
/// — callers reading from the stream are responsible for enforcing their own limits.
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Debug)]
pub struct BodyStream(pub Body);

impl<S: Sync> FromRequest<S> for BodyStream {
    type Rejection = Infallible;

    fn from_request(
        req: hyper::Request<Body>,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(req.into_body())))
    }
}

impl<S: Sync> FromRequest<S> for hyper::Request<Body> {
    type Rejection = Infallible;

    fn from_request(
        req: hyper::Request<Body>,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(req))
    }
}
