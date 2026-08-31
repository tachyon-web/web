//! [`RequestPartsExt`]/[`RequestExt`]: sugar for running an extractor outside
//! of a handler's argument list.

use std::future::Future;

use crate::http::response::Body;
use crate::routing::extract::body::max_body_size;
use crate::routing::extract::{FromRequest, FromRequestParts};

/// Sugar for running an extractor against request *parts* (headers, method,
/// URI, extensions — no body) outside of a handler's argument list. Matches
/// `axum_core::RequestPartsExt`.
///
/// *Axum compatibility: drop-in replacement for `axum::RequestPartsExt`.*
pub trait RequestPartsExt: Sized {
    /// Runs `E::from_request_parts` against unit state (`S = ()`).
    fn extract<E>(&mut self) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequestParts<()> + 'static;

    /// Runs `E::from_request_parts` against `state`.
    fn extract_with_state<'a, E, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<E, E::Rejection>> + Send + 'a
    where
        E: FromRequestParts<S> + 'static,
        S: Send + Sync;
}

impl RequestPartsExt for hyper::http::request::Parts {
    fn extract<E>(&mut self) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequestParts<()> + 'static,
    {
        E::from_request_parts(self, &())
    }

    fn extract_with_state<'a, E, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<E, E::Rejection>> + Send + 'a
    where
        E: FromRequestParts<S> + 'static,
        S: Send + Sync,
    {
        E::from_request_parts(self, state)
    }
}

/// Sugar for running an extractor against an owned [`hyper::Request`]
/// outside of a handler's argument list. Matches `axum_core::RequestExt`.
///
/// *Axum compatibility: drop-in replacement for `axum::RequestExt`.*
pub trait RequestExt: Sized {
    /// Runs `E::from_request` against unit state (`S = ()`), consuming `self`.
    fn extract<E, M>(self) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequest<(), M> + 'static,
        M: 'static;

    /// Runs `E::from_request` against `state`, consuming `self`.
    fn extract_with_state<E, S, M>(
        self,
        state: &S,
    ) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequest<S, M> + 'static,
        S: Send + Sync;

    /// Runs `E::from_request_parts` against unit state, without consuming the body.
    fn extract_parts<E>(&mut self) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequestParts<()> + 'static;

    /// Runs `E::from_request_parts` against `state`, without consuming the body.
    fn extract_parts_with_state<'a, E, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<E, E::Rejection>> + Send + 'a
    where
        E: FromRequestParts<S> + 'static,
        S: Send + Sync;

    /// Returns `self` with its body wrapped to enforce
    /// [`DefaultBodyLimit`](crate::routing::extract::DefaultBodyLimit), matching
    /// `axum_core::RequestExt::with_limited_body`.
    ///
    /// Unlike Axum's version (which reads a request-extension flag set by a
    /// `DefaultBodyLimit` *extractor*), this reads the extension
    /// [`DefaultBodyLimit`](crate::routing::extract::DefaultBodyLimit)'s `tower::Layer` impl
    /// sets — the same one every body-buffering extractor (`Bytes`, `String`, `Json`, `Form`)
    /// already consults via [`crate::routing::extract::body::max_body_size`].
    #[must_use]
    fn with_limited_body(self) -> crate::http::Request;

    /// Equivalent to `self.with_limited_body().into_body()`, matching
    /// `axum_core::RequestExt::into_limited_body`.
    #[must_use]
    fn into_limited_body(self) -> Body;
}

impl RequestExt for hyper::Request<Body> {
    fn extract<E, M>(self) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequest<(), M> + 'static,
        M: 'static,
    {
        self.extract_with_state(&())
    }

    fn extract_with_state<E, S, M>(
        self,
        state: &S,
    ) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequest<S, M> + 'static,
        S: Send + Sync,
    {
        E::from_request(self, state)
    }

    fn extract_parts<E>(&mut self) -> impl Future<Output = Result<E, E::Rejection>> + Send
    where
        E: FromRequestParts<()> + 'static,
    {
        let (mut parts, body) = std::mem::replace(self, Self::new(Body::empty())).into_parts();
        async move {
            let result = E::from_request_parts(&mut parts, &()).await;
            *self = Self::from_parts(parts, body);
            result
        }
    }

    fn extract_parts_with_state<'a, E, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<E, E::Rejection>> + Send + 'a
    where
        E: FromRequestParts<S> + 'static,
        S: Send + Sync,
    {
        let (mut parts, body) = std::mem::replace(self, Self::new(Body::empty())).into_parts();
        async move {
            let result = E::from_request_parts(&mut parts, state).await;
            *self = Self::from_parts(parts, body);
            result
        }
    }

    fn with_limited_body(self) -> crate::http::Request {
        use http_body_util::BodyExt;

        let limit = max_body_size(self.extensions());
        let (parts, body) = self.into_parts();
        let limited =
            http_body_util::Limited::new(body, limit).map_err(crate::http::error::Error::new);
        Self::from_parts(parts, Body::stream(limited))
    }

    fn into_limited_body(self) -> Body {
        self.with_limited_body().into_body()
    }
}
