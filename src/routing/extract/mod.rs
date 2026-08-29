//! Type-safe request extractors.
//!
//! Split by concern: [`path`] (URI path parameters), [`query`] (query strings,
//! shared with [`body::Form`]), [`body`] (body-consuming extractors and the
//! body-size-limit machinery), [`parts`] (metadata-only extractors), and
//! [`ext`] (the [`RequestPartsExt`]/[`RequestExt`] sugar traits). Every public
//! item from those submodules is re-exported here, at the same
//! `tachyon_web::extract::X` path Axum uses.

/// Per-extractor rejection types, matching `axum::extract::rejection`.
pub mod rejection;

/// WebSocket upgrade extractor and connection types (`WebSocketUpgrade`,
/// `WebSocket`, `Message`, ...) — re-exported here at the same path Axum uses
/// (`axum::extract::ws`), so `use tachyon_web::extract::ws::*;` matches
/// `use axum::extract::ws::*;` verbatim. See [`crate::ws`] for the full docs.
/// Requires the `ws` feature.
#[cfg(feature = "ws")]
pub use crate::ws;
/// Flattened re-export matching `axum::extract::WebSocketUpgrade`.
#[cfg(feature = "ws")]
pub use crate::ws::WebSocketUpgrade;

/// Structured-field typed-header extractor, re-exported at the extractor path.
/// See [`crate::http::sfv`] for the data model and the `sfv_dictionary!` macro.
/// Requires the `sfv` feature.
#[cfg(feature = "sfv")]
pub use crate::http::sfv::StructuredHeader;

/// `multipart/form-data` extractor (`Multipart`, `Field`, `MultipartError`).
///
/// Matches `axum::extract::multipart`. Requires the `multipart` feature.
#[cfg(feature = "multipart")]
pub mod multipart;
/// Flattened re-export matching `axum::extract::Multipart`.
#[cfg(feature = "multipart")]
pub use multipart::Multipart;

pub mod body;
pub mod ext;
pub mod parts;
pub mod path;
pub mod query;

pub use body::*;
pub use ext::*;
pub use parts::*;
pub use path::*;
pub use query::*;

use crate::http::response::Body;
use std::future::Future;

/// Trait for extracting data from request parts (metadata).
///
/// `async fn`, matching `axum::extract::FromRequestParts` exactly — most built-in
/// impls here don't need to await anything and resolve immediately, but a user
/// extractor that needs to (e.g. a database round trip keyed off a header) can.
pub trait FromRequestParts<S: Sync>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse;

    /// Extract this type from the request parts and state.
    ///
    /// # Errors
    ///
    /// Returns a rejection if the extraction from the request parts fails.
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

/// Trait for extracting data from a request (possibly consuming the body).
///
/// This is `async` so extractors can await the body being streamed in — the
/// request body is not necessarily fully buffered before your handler runs (see
/// [`crate::routing::extract::BodyStream`]). Extractors that only need the parts
/// (headers, method, URI, state) should implement [`FromRequestParts`] instead,
/// which stays synchronous and is cheaper to call.
pub trait FromRequest<S: Sync>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse;

    /// Extract this type from the request and state.
    ///
    /// # Errors
    ///
    /// Returns a rejection if the extraction from the request body/parts fails.
    fn from_request(
        req: hyper::Request<Body>,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

/// Derives an extractor's [`FromRequest`] impl from its [`FromRequestParts`] one: discard the
/// body, run the parts extractor, forward its rejection type unchanged. Every extractor that
/// only reads request metadata (headers, method, URI, extensions, state) works this way, so
/// each would otherwise repeat the same five-line body verbatim.
///
/// The second form is for generic extractors (`State<T>`, `Path<T>`, …), whose forwarded impl
/// has to restate the same `T` bounds its `FromRequestParts` impl carries.
macro_rules! impl_from_request_via_parts {
    ($ty:ty) => {
        impl_from_request_via_parts!(@imp $ty, [], []);
    };
    ($ty:ty, T: $($bound:tt)+) => {
        impl_from_request_via_parts!(@imp $ty, [T], [T: $($bound)+]);
    };
    (@imp $ty:ty, [$($generic:ident)?], [$($bounds:tt)*]) => {
        impl<S: Sync, $($generic)?> FromRequest<S> for $ty
        where
            $($bounds)*
        {
            type Rejection = <Self as FromRequestParts<S>>::Rejection;

            async fn from_request(
                req: hyper::Request<Body>,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                let (mut parts, _) = req.into_parts();
                <Self as FromRequestParts<S>>::from_request_parts(&mut parts, state).await
            }
        }
    };
}

impl_from_request_via_parts!(RawQuery);
#[cfg(feature = "early-hints")]
impl_from_request_via_parts!(crate::http::early_hints::EarlyHints);
impl_from_request_via_parts!(hyper::header::HeaderMap);
impl_from_request_via_parts!(hyper::Method);
impl_from_request_via_parts!(hyper::Uri);
#[cfg(feature = "cookies")]
impl_from_request_via_parts!(Cookies);
impl_from_request_via_parts!(Host);
#[cfg(feature = "original-uri")]
impl_from_request_via_parts!(OriginalUri);
#[cfg(feature = "matched-path")]
impl_from_request_via_parts!(MatchedPath);
impl_from_request_via_parts!(NestedPath);

impl_from_request_via_parts!(State<T>, T: FromRef<S> + Send + Sync + 'static);
impl_from_request_via_parts!(Path<T>, T: serde::de::DeserializeOwned + Send + Sync + 'static);
impl_from_request_via_parts!(RawPathParams);
#[cfg(feature = "query")]
impl_from_request_via_parts!(Query<T>, T: serde::de::DeserializeOwned + Send + Sync + 'static);
impl_from_request_via_parts!(Extension<T>, T: Clone + Send + Sync + 'static);
impl_from_request_via_parts!(ConnectInfo<T>, T: Clone + Send + Sync + 'static);

/// `Option<T>` succeeds with `None` wherever `T` would fail, for any
/// extractor. Matches the effect of Axum's `OptionalFromRequestParts`/
/// `OptionalFromRequest` blanket impls, simplified: Axum lets an individual
/// extractor override *which* rejections become `None` versus a real error
/// (e.g. `Query`'s override still hard-errors on malformed query strings,
/// only treating "no query string at all" as `None`). This collapses every
/// rejection to `None` uniformly instead, which is simpler but less precise —
/// most consumers of `Option<Extractor>` just want "was it there or not"
/// and don't rely on the distinction.
impl<S: Sync, T> FromRequestParts<S> for Option<T>
where
    T: FromRequestParts<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(T::from_request_parts(parts, state).await.ok())
    }
}

/// See [`FromRequestParts` for `Option<T>`](#impl-FromRequestParts%3CS%3E-for-Option%3CT%3E)
/// — same simplification relative to Axum's real `OptionalFromRequest`.
impl<S: Sync, T> FromRequest<S> for Option<T>
where
    T: FromRequest<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        Ok(T::from_request(req, state).await.ok())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
