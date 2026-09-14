//! Type-safe request extractors.
//!
//! Internally split by concern — path parameters, query strings, request
//! bodies, metadata-only extractors, and the [`RequestPartsExt`]/[`RequestExt`]
//! sugar traits — but every item is re-exported flat here, at the same
//! `tachyon_web::extract::X` path Axum uses. [`path`] is the one submodule
//! kept public, matching `axum::extract::path`.

/// Per-extractor rejection types, matching `axum::extract::rejection`.
pub mod rejection;

/// WebSocket upgrade extractor and connection types.
///
/// `WebSocketUpgrade`, `WebSocket`, `Message`, ... — re-exported here at the
/// same path Axum uses (`axum::extract::ws`), so
/// `use tachyon_web::extract::ws::*;` matches `use axum::extract::ws::*;`
/// verbatim. Requires the `ws` feature.
#[cfg(feature = "ws")]
pub mod ws {
    pub use crate::ws::close_code;
    pub use crate::ws::rejection;
    pub use crate::ws::{
        CloseCode, CloseFrame, DEFAULT_MAX_WRITE_BUFFER_SIZE, DefaultOnFailedUpgrade,
        DeflateConfig, Message, OnFailedUpgrade, Utf8Bytes, WebSocket, WebSocketConfig,
        WebSocketUpgrade,
    };
}
/// Flattened re-export matching `axum::extract::WebSocketUpgrade`.
#[cfg(feature = "ws")]
pub use crate::ws::WebSocketUpgrade;

/// `multipart/form-data` extractor (`Multipart`, `Field`, `MultipartError`).
///
/// Matches `axum::extract::multipart`. Requires the `multipart` feature.
#[cfg(feature = "multipart")]
pub mod multipart;
/// Flattened re-export matching `axum::extract::Multipart`.
#[cfg(feature = "multipart")]
pub use multipart::Multipart;

mod body;
mod ext;
mod parts;
pub mod path;
mod query;

#[cfg(feature = "json")]
pub use body::Json;
pub(crate) use body::MaxBodySize;
pub use body::{BodyStream, DefaultBodyLimit, DefaultBodyLimitService};
#[cfg(feature = "form")]
pub use body::{Form, RawForm};
pub use ext::{RequestExt, RequestPartsExt};
#[cfg(feature = "cookies")]
pub use parts::Cookies;
#[cfg(feature = "matched-path")]
pub use parts::MatchedPath;
#[cfg(feature = "original-uri")]
pub use parts::OriginalUri;
pub use parts::{AddExtension, ConnectInfo, Extension, FromRef, Host, NestedPath, State};
pub use path::*;
#[cfg(feature = "query")]
pub use query::Query;
pub use query::RawQuery;

/// The request type extractors receive, matching `axum::extract::Request`.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::Request`.*
pub type Request<T = crate::http::response::Body> = hyper::Request<T>;

/// Extractors and helpers for the client's socket address, matching
/// `axum::extract::connect_info`.
pub mod connect_info {
    pub use crate::routing::extract::parts::ConnectInfo;
    pub use crate::routing::tower_compat::MockConnectInfo;
    pub use crate::routing::tower_compat::{
        Connected, IntoMakeServiceWithConnectInfo, ResponseFuture,
    };
}

use crate::http::response::Body;
use std::future::Future;

/// Trait for extracting data from request parts (metadata).
///
/// `async fn`, matching `axum::extract::FromRequestParts` exactly — most built-in
/// impls here don't need to await anything and resolve immediately, but a user
/// extractor that needs to (e.g. a database round trip keyed off a header) can.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::FromRequestParts`.*
pub trait FromRequestParts<S>: Sized + Send {
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
///
/// `M` is a phantom marker occupying the same generic slot Axum uses to let a single type
/// implement both [`FromRequestParts`] and `FromRequest` without a coherence conflict — this
/// crate achieves the same result via per-type macro-generated impls instead, so `M` exists here
/// purely for signature parity.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::FromRequest`.*
pub trait FromRequest<S, M = ()>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse;

    /// Extract this type from the request and state.
    ///
    /// # Errors
    ///
    /// Returns a rejection if the extraction from the request body/parts fails.
    fn from_request(
        req: crate::http::Request,
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

/// Customizes the behavior of `Option<Self>` as a [`FromRequestParts`] extractor.
///
/// Lets an individual extractor decide which of its own rejections collapse to
/// `None` versus stay a real error. Matches `axum_core::extract::OptionalFromRequestParts`.
///
/// Only implemented for the extractors Axum itself implements it for
/// ([`Extension`], [`MatchedPath`], [`Path`]) — an extractor with no impl of this
/// trait has no `Option<T>` support at all, matching Axum exactly.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::OptionalFromRequestParts`.*
pub trait OptionalFromRequestParts<S>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse;

    /// Extract this type from the request parts and state, or `None` if genuinely absent.
    ///
    /// # Errors
    ///
    /// Returns a rejection for a failure that shouldn't collapse to `None` (e.g. a
    /// malformed value, as opposed to the value simply being missing).
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send;
}

/// Customizes the behavior of `Option<Self>` as a [`FromRequest`] extractor. Matches
/// `axum_core::extract::OptionalFromRequest`.
///
/// Only implemented for the extractors Axum itself implements it for ([`Json`],
/// [`Multipart`]) — an extractor with no impl of this trait has no `Option<T>`
/// support at all, matching Axum exactly.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::OptionalFromRequest`.*
pub trait OptionalFromRequest<S>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse;

    /// Extract this type from the request and state, or `None` if genuinely absent.
    ///
    /// # Errors
    ///
    /// Returns a rejection for a failure that shouldn't collapse to `None` (e.g. a
    /// malformed value, as opposed to the value simply being missing).
    fn from_request(
        req: crate::http::Request,
        state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send;
}

impl<S: Sync, T> FromRequestParts<S> for Option<T>
where
    T: OptionalFromRequestParts<S>,
{
    type Rejection = T::Rejection;

    async fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        T::from_request_parts(parts, state).await
    }
}

impl<S: Sync, T> FromRequest<S> for Option<T>
where
    T: OptionalFromRequest<S>,
{
    type Rejection = T::Rejection;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        T::from_request(req, state).await
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
