//! Metadata-only extractors: [`State`], [`FromRef`], header/method/URI types,
//! [`Extension`], [`Cookies`], [`Host`], [`OriginalUri`], [`MatchedPath`],
//! [`NestedPath`], and [`ConnectInfo`].

use crate::http::error::Error;
#[cfg(feature = "cookies")]
use cookie::{Cookie, CookieJar};
use hyper::header::HeaderMap;
use hyper::{Method, StatusCode, Uri};
use std::convert::Infallible;
use std::future::Future;

use crate::routing::extract::{FromRequestParts, rejection};

/// Derives sub-state from the app state, matching `axum::extract::FromRef`.
pub trait FromRef<S> {
    /// Extract a reference/clone from the parent state.
    fn from_ref(state: &S) -> Self;
}

impl<T: Clone> FromRef<T> for T {
    fn from_ref(state: &T) -> Self {
        state.clone()
    }
}

/// Extractor for application state.
#[derive(Debug, Clone, Copy)]
pub struct State<T>(pub T);

impl<S: Sync, T> FromRequestParts<S> for State<T>
where
    T: FromRef<S> + Send + Sync + 'static,
{
    type Rejection = Infallible;

    fn from_request_parts(
        _parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(T::from_ref(state))))
    }
}

impl<S: Sync> FromRequestParts<S> for HeaderMap {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.headers.clone()))
    }
}

impl<S: Sync> FromRequestParts<S> for Method {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.method.clone()))
    }
}

impl<S: Sync> FromRequestParts<S> for Uri {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.uri.clone()))
    }
}

/// Extractor for request-local extensions.
#[derive(Debug, Clone, Copy)]
pub struct Extension<T>(pub T);

impl<S: Sync, T> FromRequestParts<S> for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Rejection = rejection::ExtensionRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            parts
                .extensions
                .get::<T>()
                .cloned()
                .map(Extension)
                .ok_or_else(|| {
                    rejection::MissingExtension(format!(
                        "Missing extension: {}",
                        std::any::type_name::<T>()
                    ))
                    .into()
                })
        })
    }
}

impl<T> crate::http::response::IntoResponse for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn into_response(self) -> crate::http::response::Response {
        let mut res = crate::http::response::IntoResponse::into_response(());
        res.extensions_mut().insert(self.0);
        res
    }
}

impl<S: Sync, T> super::OptionalFromRequestParts<S> for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.extensions.get::<T>().cloned().map(Extension)))
    }
}

/// A `tower::Layer` inserting a fixed, cloneable value into every incoming
/// request's extensions. Matches `Extension<T>`'s `tower::Layer` impl in axum
/// — the layer form of the [`Extension`] extractor above, for a value bound
/// once at `.layer()` time rather than read from somewhere else per request.
impl<S, T> tower::Layer<S> for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Service = AddExtension<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        AddExtension {
            inner,
            value: self.0.clone(),
        }
    }
}

/// The `tower::Service` produced by [`Extension`]'s `tower::Layer` impl.
/// Matches `axum::extension::AddExtension`.
#[derive(Clone, Copy, Debug)]
pub struct AddExtension<S, T> {
    pub(crate) inner: S,
    pub(crate) value: T,
}

impl<ResBody, S, T> tower::Service<hyper::Request<ResBody>> for AddExtension<S, T>
where
    S: tower::Service<hyper::Request<ResBody>>,
    T: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: hyper::Request<ResBody>) -> Self::Future {
        req.extensions_mut().insert(self.value.clone());
        self.inner.call(req)
    }
}

/// Extractor for reading and managing Cookies.
#[cfg(feature = "cookies")]
#[derive(Debug, Clone)]
pub struct Cookies {
    /// The internal cookie jar
    pub jar: CookieJar,
}

#[cfg(feature = "cookies")]
impl Cookies {
    /// Create a new empty Cookies jar.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jar: CookieJar::new(),
        }
    }

    /// Get a cookie by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Cookie<'static>> {
        self.jar.get(name)
    }

    /// Adds `cookie` to the jar, returning `Self` for chaining — the request handler pattern is
    /// `async fn handler(jar: Cookies) -> (Cookies, T) { (jar.add(...), body) }`, matching
    /// `axum-extra`'s `CookieJar`. Returning the jar from a handler (anywhere in an
    /// [`IntoResponseParts`](crate::http::response::IntoResponseParts) tuple) is what actually
    /// applies it — only the cookies that changed (added or removed) are serialized into
    /// `Set-Cookie` headers, via [`cookie::CookieJar::delta`], not the whole jar.
    // Named to match `axum-extra`'s `CookieJar::add` exactly (the point of this method), not
    // `std::ops::Add` — the two aren't actually confusable in practice (different arity/purpose).
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn add(mut self, cookie: Cookie<'static>) -> Self {
        self.jar.add(cookie);
        self
    }

    /// Removes `cookie` from the jar (queuing a `Set-Cookie` that expires it immediately once
    /// this jar is returned from a handler), returning `Self` for chaining — see [`add`](Self::add).
    #[must_use]
    pub fn remove(mut self, cookie: Cookie<'static>) -> Self {
        self.jar.remove(cookie);
        self
    }
}

#[cfg(feature = "cookies")]
impl Default for Cookies {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "cookies")]
impl<S: Sync> FromRequestParts<S> for Cookies {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            let mut jar = CookieJar::new();
            if let Some(cookie_header) = parts.headers.get(hyper::header::COOKIE)
                && let Ok(cookie_str) = cookie_header.to_str()
            {
                for c in Cookie::split_parse_encoded(cookie_str).flatten() {
                    jar.add_original(c.into_owned());
                }
            }
            Ok(Self { jar })
        })
    }
}

/// Extractor for host header or authority.
#[derive(Debug, Clone)]
pub struct Host(pub String);

impl<S: Sync> FromRequestParts<S> for Host {
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            if let Some(host) = parts
                .headers
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
            {
                Ok(Self(host.to_string()))
            } else if let Some(host) = parts.uri.host() {
                Ok(Self(host.to_string()))
            } else {
                Err(Error::status(
                    StatusCode::BAD_REQUEST,
                    "Missing Host header or authority in URI",
                ))
            }
        })
    }
}

/// Extractor for the original URI. Requires the `original-uri` feature.
#[cfg(feature = "original-uri")]
#[derive(Debug, Clone)]
pub struct OriginalUri(pub Uri);

#[cfg(feature = "original-uri")]
impl<S: Sync> FromRequestParts<S> for OriginalUri {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            let uri = parts
                .extensions
                .get::<Self>()
                .map_or_else(|| parts.uri.clone(), |ou| ou.0.clone());
            Ok(Self(uri))
        })
    }
}

/// Extractor for the matched route pattern (e.g. `/users/{id}`), as registered
/// via `Router::route`, rather than the literal request path (`/users/1`).
///
/// Matches `axum::extract::MatchedPath` — commonly used to label metrics/traces
/// by route template instead of by concrete path (which would otherwise create
/// one time series per distinct resource ID). Only available for requests that
/// matched a registered route; unmatched requests (404s) have no `MatchedPath`.
/// Requires the `matched-path` feature.
#[cfg(feature = "matched-path")]
#[derive(Debug, Clone)]
pub struct MatchedPath(pub(crate) std::sync::Arc<str>);

#[cfg(feature = "matched-path")]
impl MatchedPath {
    /// The matched route pattern, e.g. `/users/{id}`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "matched-path")]
impl<S: Sync> FromRequestParts<S> for MatchedPath {
    type Rejection = rejection::MatchedPathRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            parts.extensions.get::<Self>().cloned().ok_or_else(|| {
                rejection::MatchedPathMissing(
                    "No matched path found in request extensions".to_string(),
                )
                .into()
            })
        })
    }
}

#[cfg(feature = "matched-path")]
impl<S: Sync> super::OptionalFromRequestParts<S> for MatchedPath {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.extensions.get::<Self>().cloned()))
    }
}

/// Extractor for the path prefix a matched route was nested under, e.g. `/api`
/// for a route mounted via `Router::nest("/api", ...)`. Matches
/// `axum::extract::NestedPath`.
///
/// Only available for requests that matched a route reached through at least
/// one level of nesting — a non-nested route has no [`NestedPath`].
#[derive(Debug, Clone)]
pub struct NestedPath(pub(crate) std::sync::Arc<str>);

impl NestedPath {
    /// Returns a `str` representation of the path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S: Sync> FromRequestParts<S> for NestedPath {
    type Rejection = rejection::NestedPathRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Self>()
                .cloned()
                .ok_or(rejection::NestedPathRejection),
        )
    }
}

/// Extractor for network connection info.
#[derive(Debug, Clone, Copy)]
pub struct ConnectInfo<T>(pub T);

impl<S: Sync, T> FromRequestParts<S> for ConnectInfo<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            parts.extensions.get::<Self>().cloned().ok_or_else(|| {
                Error::status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Missing ConnectInfo<{}> extension",
                        std::any::type_name::<T>()
                    ),
                )
            })
        })
    }
}
