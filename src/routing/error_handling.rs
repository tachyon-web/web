//! Converts a fallible `tower::Service` into an infallible one by running a
//! user-supplied closure over its error. Matches `axum::error_handling`.
//!
//! This operates entirely in `tower::Service` space, wrapping whatever
//! `Service` a `tower::Layer` chain produces before it's applied via
//! [`crate::routing::Router::layer`]. [`crate::routing::tower_compat::Route`]
//! (what every layer chain ultimately gets boxed back into) already converts
//! any layered service's error into a response automatically using a fixed,
//! non-customizable conversion (`Into<Error>::into(e).into_response()`);
//! `HandleErrorLayer` exists for callers who want to customize *how* that
//! conversion happens, matching Axum's `.layer(HandleErrorLayer::new(f))`
//! call site exactly.

use crate::http::error::Error;
use crate::http::response::{Body, IntoResponse, Response};
use bytes::Bytes;
use hyper::Request;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// A `tower::Layer` that turns any fallible inner `Service` into an
/// infallible one, converting `Err` values via a user-supplied closure.
/// Matches `axum::error_handling::HandleErrorLayer`.
///
/// `T` matches axum's shape (it's `PhantomData`-only there too, in the base case) but isn't
/// yet load-bearing here: axum uses it to let `f` additionally take `FromRequestParts`
/// extractors ahead of the error (`|State(s), err| ...`) via a family of tuple impls this
/// crate hasn't ported — `f` must be a plain `FnOnce(Error) -> Fut` for now.
///
/// *Axum compatibility: drop-in replacement for `axum::error_handling::HandleErrorLayer`.*
pub struct HandleErrorLayer<F, T = ()> {
    f: F,
    _extractor: PhantomData<fn() -> T>,
}

impl<F, T> HandleErrorLayer<F, T> {
    /// Wraps `f`, which is called with the inner service's error whenever it
    /// fails, to produce the response returned in its place.
    pub const fn new(f: F) -> Self {
        Self {
            f,
            _extractor: PhantomData,
        }
    }
}

impl<F: Clone, T> Clone for HandleErrorLayer<F, T> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            _extractor: PhantomData,
        }
    }
}

impl<F, T> std::fmt::Debug for HandleErrorLayer<F, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleErrorLayer").finish_non_exhaustive()
    }
}

impl<S, F, T> Layer<S> for HandleErrorLayer<F, T>
where
    F: Clone,
{
    type Service = HandleError<S, F, T>;

    fn layer(&self, inner: S) -> Self::Service {
        HandleError::new(inner, self.f.clone())
    }
}

/// The `tower::Service` produced by [`HandleErrorLayer`]. Matches
/// `axum::error_handling::HandleError`. See [`HandleErrorLayer`]'s docs for the current
/// scope of the phantom `T` parameter.
///
/// *Axum compatibility: drop-in replacement for `axum::error_handling::HandleError`.*
pub struct HandleError<S, F, T = ()> {
    inner: S,
    f: F,
    _extractor: PhantomData<fn() -> T>,
}

impl<S, F, T> HandleError<S, F, T> {
    /// Wraps `inner`, converting its errors via `f`. Matches
    /// `axum::error_handling::HandleError::new`.
    pub const fn new(inner: S, f: F) -> Self {
        Self {
            inner,
            f,
            _extractor: PhantomData,
        }
    }
}

impl<S: Clone, F: Clone, T> Clone for HandleError<S, F, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            f: self.f.clone(),
            _extractor: PhantomData,
        }
    }
}

impl<S, F, T> std::fmt::Debug for HandleError<S, F, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleError").finish_non_exhaustive()
    }
}

/// The future returned by [`HandleError`]'s `Service::call`. Matches
/// `axum::error_handling::future::HandleErrorFuture`.
///
/// *Axum compatibility: drop-in replacement for `axum::error_handling::future::HandleErrorFuture`.*
pub struct HandleErrorFuture {
    future: Pin<Box<dyn Future<Output = Result<Response, std::convert::Infallible>> + Send>>,
}

/// Re-export of [`HandleErrorFuture`] at the path `axum::error_handling::future` uses.
pub mod future {
    pub use super::HandleErrorFuture;
}

impl std::fmt::Debug for HandleErrorFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleErrorFuture").finish_non_exhaustive()
    }
}

impl Unpin for HandleErrorFuture {}

impl Future for HandleErrorFuture {
    type Output = Result<Response, std::convert::Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

impl<S, F, Fut, Res, RespBody> Service<Request<Body>> for HandleError<S, F, ()>
where
    S: Service<Request<Body>, Response = hyper::Response<RespBody>> + Clone + Send + Sync + 'static,
    S::Error: Into<Error> + Send,
    S::Future: Send + 'static,
    F: FnOnce(Error) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
    RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
    RespBody::Error: Into<Error>,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = HandleErrorFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Matches Axum: readiness is deferred into `call` (via `Service::ready`
        // just before use below) rather than tracked here, since the wrapped
        // closure may need a fresh inner clone per call regardless.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        use tower::ServiceExt;

        let f = self.f.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        HandleErrorFuture {
            future: Box::pin(async move {
                let result = match inner.ready().await {
                    Ok(ready) => ready.call(req).await,
                    Err(e) => Err(e),
                };
                match result {
                    Ok(resp) => {
                        let (parts, body) = resp.into_parts();
                        Ok(hyper::Response::from_parts(parts, Body::stream(body)))
                    }
                    Err(e) => Ok(f(e.into()).await.into_response()),
                }
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hyper::StatusCode;
    use std::convert::Infallible as StdInfallible;
    use std::task::{Context, Poll};

    #[derive(Clone)]
    struct AlwaysFails;

    impl Service<Request<Body>> for AlwaysFails {
        type Response = hyper::Response<Body>;
        type Error = Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            Box::pin(async { Err(Error::internal("boom".to_string())) })
        }
    }

    #[derive(Clone)]
    struct AlwaysSucceeds;

    impl Service<Request<Body>> for AlwaysSucceeds {
        type Response = hyper::Response<Body>;
        type Error = Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            Box::pin(async { Ok(hyper::Response::new(Body::full(Bytes::from("ok")))) })
        }
    }

    async fn to_teapot(_err: Error) -> StatusCode {
        StatusCode::IM_A_TEAPOT
    }

    #[tokio::test]
    async fn maps_inner_service_errors_via_the_closure() {
        let layer = HandleErrorLayer::new(to_teapot);
        let mut svc = layer.layer(AlwaysFails);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp: Result<Response, StdInfallible> = Service::call(&mut svc, req).await;
        assert_eq!(resp.unwrap().status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn passes_through_successful_responses_unchanged() {
        let layer = HandleErrorLayer::new(to_teapot);
        let mut svc = layer.layer(AlwaysSucceeds);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = Service::call(&mut svc, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
