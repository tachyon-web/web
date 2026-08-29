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
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// A `tower::Layer` that turns any fallible inner `Service` into an
/// infallible one, converting `Err` values via a user-supplied closure.
/// Matches `axum::error_handling::HandleErrorLayer`.
pub struct HandleErrorLayer<F> {
    f: F,
}

impl<F> HandleErrorLayer<F> {
    /// Wraps `f`, which is called with the inner service's error whenever it
    /// fails, to produce the response returned in its place.
    pub const fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F: Clone> Clone for HandleErrorLayer<F> {
    fn clone(&self) -> Self {
        Self { f: self.f.clone() }
    }
}

impl<F> std::fmt::Debug for HandleErrorLayer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleErrorLayer").finish_non_exhaustive()
    }
}

impl<S, F> Layer<S> for HandleErrorLayer<F>
where
    F: Clone,
{
    type Service = HandleError<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        HandleError {
            inner,
            f: self.f.clone(),
        }
    }
}

/// The `tower::Service` produced by [`HandleErrorLayer`]. Matches
/// `axum::error_handling::HandleError`.
pub struct HandleError<S, F> {
    inner: S,
    f: F,
}

impl<S: Clone, F: Clone> Clone for HandleError<S, F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            f: self.f.clone(),
        }
    }
}

impl<S, F> std::fmt::Debug for HandleError<S, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleError").finish_non_exhaustive()
    }
}

/// The future returned by [`HandleError`]'s `Service::call`. Matches
/// `axum::error_handling::future::HandleErrorFuture`.
pub type HandleErrorFuture =
    Pin<Box<dyn Future<Output = Result<Response, std::convert::Infallible>> + Send>>;

impl<S, F, Fut, Res, RespBody> Service<Request<Body>> for HandleError<S, F>
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
        Box::pin(async move {
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
        })
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
