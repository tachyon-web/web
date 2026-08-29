//! [`RequestPartsExt`]/[`RequestExt`]: sugar for running an extractor outside
//! of a handler's argument list.

use std::future::Future;

use crate::http::response::Body;
use crate::routing::extract::{FromRequest, FromRequestParts};

/// Sugar for running an extractor against request *parts* (headers, method,
/// URI, extensions — no body) outside of a handler's argument list. Matches
/// `axum_core::RequestPartsExt`.
pub trait RequestPartsExt {
    /// Runs `T::from_request_parts` against unit state (`S = ()`).
    fn extract<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>;

    /// Runs `T::from_request_parts` against `state`.
    fn extract_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync;
}

impl RequestPartsExt for hyper::http::request::Parts {
    fn extract<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>,
    {
        T::from_request_parts(self, &())
    }

    fn extract_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync,
    {
        T::from_request_parts(self, state)
    }
}

/// Sugar for running an extractor against an owned [`hyper::Request`]
/// outside of a handler's argument list. Matches `axum_core::RequestExt`.
pub trait RequestExt: Sized {
    /// Runs `T::from_request` against unit state (`S = ()`), consuming `self`.
    fn extract<T>(self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<()>;

    /// Runs `T::from_request` against `state`, consuming `self`.
    fn extract_with_state<T, S>(
        self,
        state: &S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<S>,
        S: Sync;

    /// Runs `T::from_request_parts` against unit state, without consuming the body.
    fn extract_parts<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>;

    /// Runs `T::from_request_parts` against `state`, without consuming the body.
    fn extract_parts_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync;
}

impl RequestExt for hyper::Request<Body> {
    fn extract<T>(self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<()>,
    {
        T::from_request(self, &())
    }

    fn extract_with_state<T, S>(
        self,
        state: &S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<S>,
        S: Sync,
    {
        T::from_request(self, state)
    }

    fn extract_parts<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>,
    {
        let (mut parts, body) = std::mem::replace(self, Self::new(Body::empty())).into_parts();
        async move {
            let result = T::from_request_parts(&mut parts, &()).await;
            *self = Self::from_parts(parts, body);
            result
        }
    }

    fn extract_parts_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync,
    {
        let (mut parts, body) = std::mem::replace(self, Self::new(Body::empty())).into_parts();
        async move {
            let result = T::from_request_parts(&mut parts, state).await;
            *self = Self::from_parts(parts, body);
            result
        }
    }
}
