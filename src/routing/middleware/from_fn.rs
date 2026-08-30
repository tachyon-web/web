//! `axum::middleware::from_fn` and friends, as real `tower::Layer`/`tower::Service`
//! pairs wrapping an arbitrary inner `tower::Service` — the same mechanism
//! `Router::layer` itself uses, not a separate bespoke system.
//!
//! Axum's real `from_fn` lets middleware take extractor arguments before
//! `Next` (`async fn mw(State(s): State<AppState>, req: Request, next: Next)
//! -> Response`), resolved the same variadic way `Handler` resolves route
//! handler arguments.
//!
//! These are plain functions over `Fn(Request<Body>, Next) -> Fut`
//! (`from_fn`) or the state/request/response-only shapes
//! (`from_fn_with_state`, `map_request*`, `map_response*`, `from_extractor*`)
//! rather than a full re-implementation of Axum's extractor-arity dispatch —
//! `Next` itself carries no state (matching Axum's real, state-erased
//! `Next` now that this crate's own state-erasure decision has been made),
//! so a middleware needing state either closes over it directly or uses the
//! `_with_state` variant below.
//!
//! `from_fn`/`map_request` support the same 0-to-16-extractor arity `Handler` does: `T`
//! (`FromFnLayer<F, S, T>`/`MapRequestLayer<F, S, T>`'s otherwise-unused generic slot) is the
//! tuple of leading `FromRequestParts` extractor types plus the trailing `FromRequest` one,
//! matching axum's own generics exactly — resolved the same variadic way `Handler` resolves
//! route handler arguments, via a macro-generated `Service` impl per arity.

use crate::http::response::{Body, IntoResponse, Response};
use crate::routing::extract::{FromRequest, FromRequestParts};
use crate::routing::middleware::Next;
use crate::routing::tower_compat::Route;
use hyper::Request;
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service, ServiceExt};

/// Runs `svc` to completion, converting its (infallible) result into a
/// boxed future — the one place `map_request`/`map_response`/`from_extractor`
/// funnel their final dispatch through.
fn drive<I>(mut svc: I, req: Request<Body>) -> Pin<Box<dyn Future<Output = Response> + Send>>
where
    I: Service<Request<Body>, Response = Response, Error = Infallible> + Send + 'static,
    I::Future: Send + 'static,
{
    Box::pin(async move {
        match svc.ready().await {
            Ok(ready) => match ready.call(req).await {
                Ok(resp) => resp,
                Err(never) => match never {},
            },
            Err(never) => match never {},
        }
    })
}

// --- from_fn -----------------------------------------------------------

/// `tower::Layer` wrapping an `async fn(..extractors, Request<Body>, Next) -> impl IntoResponse`.
///
/// Optionally with a bound state argument first. Matches `axum::middleware::from_fn`.
/// Built via [`from_fn`]/[`from_fn_with_state`].
pub struct FromFnLayer<F, S = (), T = ()> {
    f: F,
    state: S,
    _extractor: PhantomData<fn() -> T>,
}

impl<F, S, T> std::fmt::Debug for FromFnLayer<F, S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromFnLayer").finish_non_exhaustive()
    }
}

impl<F: Clone, S: Clone, T> Clone for FromFnLayer<F, S, T> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            _extractor: PhantomData,
        }
    }
}

/// Wraps `f` for use with `.layer()`/`.route_layer()`.
pub const fn from_fn<F, T>(f: F) -> FromFnLayer<F, (), T> {
    from_fn_with_state((), f)
}

/// Wraps `f`, binding `state` as its first argument.
pub const fn from_fn_with_state<F, S, T>(state: S, f: F) -> FromFnLayer<F, S, T> {
    FromFnLayer {
        f,
        state,
        _extractor: PhantomData,
    }
}

impl<F: Clone, S: Clone, T, I> Layer<I> for FromFnLayer<F, S, T> {
    type Service = FromFn<F, S, I, T>;

    fn layer(&self, inner: I) -> Self::Service {
        FromFn {
            f: self.f.clone(),
            state: self.state.clone(),
            inner,
            _extractor: PhantomData,
        }
    }
}

/// The `tower::Service` produced by [`FromFnLayer`].
pub struct FromFn<F, S, I, T> {
    f: F,
    state: S,
    inner: I,
    _extractor: PhantomData<fn() -> T>,
}

impl<F, S, I, T> std::fmt::Debug for FromFn<F, S, I, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromFn").finish_non_exhaustive()
    }
}

impl<F: Clone, S: Clone, I: Clone, T> Clone for FromFn<F, S, I, T> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            inner: self.inner.clone(),
            _extractor: PhantomData,
        }
    }
}

/// Generates one `Service<Request<Body>>` impl per extractor arity for [`FromFn`], mirroring
/// [`crate::routing::handler::impl_handler`]'s arity dispatch: zero or more leading
/// [`FromRequestParts`] extractors, then exactly one trailing [`FromRequest`] extractor
/// (typically `Request<Body>` itself, whose identity `FromRequest` impl covers the plain
/// `Fn(Request<Body>, Next)` shape), then [`Next`].
macro_rules! impl_from_fn {
    ( $($ty:ident),* ; $last:ident ) => {
        #[allow(non_snake_case, unused_mut)]
        impl<F, Fut, Res, S, I, $($ty,)* $last> Service<Request<Body>>
            for FromFn<F, S, I, ( $($ty,)* $last, )>
        where
            F: Fn($($ty,)* $last, Next) -> Fut + Clone + Send + Sync + 'static,
            $( $ty: FromRequestParts<S> + Send + 'static, )*
            $last: FromRequest<S> + Send + 'static,
            Fut: Future<Output = Res> + Send + 'static,
            Res: IntoResponse + Send + 'static,
            I: Service<Request<Body>, Response = Response, Error = Infallible>
                + Clone
                + Send
                + Sync
                + 'static,
            I::Future: Send + 'static,
            S: Clone + Send + Sync + 'static,
        {
            type Response = Response;
            type Error = Infallible;
            type Future = FromFnResponseFuture;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: Request<Body>) -> Self::Future {
                let f = self.f.clone();
                let state = self.state.clone();
                let next = Next {
                    inner: Route::new(self.inner.clone()),
                };
                let (mut parts, body) = req.into_parts();
                FromFnResponseFuture {
                    inner: Box::pin(async move {
                        $(
                            let $ty = match <$ty as FromRequestParts<S>>::from_request_parts(&mut parts, &state).await {
                                Ok(v) => v,
                                Err(r) => return Ok(r.into_response()),
                            };
                        )*
                        let req = Request::from_parts(parts, body);
                        let $last = match <$last as FromRequest<S>>::from_request(req, &state).await {
                            Ok(v) => v,
                            Err(r) => return Ok(r.into_response()),
                        };
                        Ok(f($($ty,)* $last, next).await.into_response())
                    }),
                }
            }
        }
    };
}

impl_from_fn!(; A1);
impl_from_fn!(A1; A2);
impl_from_fn!(A1, A2; A3);
impl_from_fn!(A1, A2, A3; A4);
impl_from_fn!(A1, A2, A3, A4; A5);
impl_from_fn!(A1, A2, A3, A4, A5; A6);
impl_from_fn!(A1, A2, A3, A4, A5, A6; A7);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7; A8);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8; A9);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8, A9; A10);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10; A11);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11; A12);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12; A13);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13; A14);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14; A15);
impl_from_fn!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15; A16);

/// Houses [`FromFn`]'s response future under the local name `ResponseFuture` — matching
/// `axum::middleware::future::ResponseFuture`'s own declared name exactly, in its own module so
/// it doesn't collide with the other middleware families' identically-named future structs
/// below, all publicly re-exported under their Axum-matching aliases.
mod from_fn_future {
    use super::{Context, Future, Infallible, Pin, Poll, Response};

    /// Response future for [`super::FromFn`]. Matches `axum::middleware::future::ResponseFuture`
    /// (re-exported here as [`super::FromFnResponseFuture`]).
    pub struct ResponseFuture {
        pub(super) inner: Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>,
    }

    impl std::fmt::Debug for ResponseFuture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ResponseFuture").finish_non_exhaustive()
        }
    }

    impl Future for ResponseFuture {
        type Output = Result<Response, Infallible>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().inner.as_mut().poll(cx)
        }
    }
}
pub use from_fn_future::ResponseFuture as FromFnResponseFuture;

// --- map_request / map_request_with_state ---------------------------------

/// Transforms the request before running the rest of the pipeline
/// (optionally with a bound state argument first).
///
/// Matches `axum::middleware::map_request`/`map_request_with_state`. `f` may
/// return either a bare `Request<Body>` or a `Result<Request<Body>, R>` to
/// short-circuit the pipeline with `R`'s response on `Err` — see
/// [`IntoMapRequestResult`]. Built via [`map_request`]/[`map_request_with_state`].
pub struct MapRequestLayer<F, S = (), T = ()> {
    f: F,
    state: S,
    _extractor: PhantomData<fn() -> T>,
}

impl<F, S, T> std::fmt::Debug for MapRequestLayer<F, S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapRequestLayer").finish_non_exhaustive()
    }
}

impl<F: Clone, S: Clone, T> Clone for MapRequestLayer<F, S, T> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            _extractor: PhantomData,
        }
    }
}

/// Wraps `f` for use with `.layer()`/`.route_layer()`.
pub const fn map_request<F, T>(f: F) -> MapRequestLayer<F, (), T> {
    map_request_with_state((), f)
}

/// Wraps `f`, binding `state` as its first argument.
pub const fn map_request_with_state<F, S, T>(state: S, f: F) -> MapRequestLayer<F, S, T> {
    MapRequestLayer {
        f,
        state,
        _extractor: PhantomData,
    }
}

impl<F: Clone, S: Clone, T, I> Layer<I> for MapRequestLayer<F, S, T> {
    type Service = MapRequest<F, S, I, T>;

    fn layer(&self, inner: I) -> Self::Service {
        MapRequest {
            f: self.f.clone(),
            state: self.state.clone(),
            inner,
            _extractor: PhantomData,
        }
    }
}

/// The `tower::Service` produced by [`MapRequestLayer`].
pub struct MapRequest<F, S, I, T> {
    f: F,
    state: S,
    inner: I,
    _extractor: PhantomData<fn() -> T>,
}

impl<F, S, I, T> std::fmt::Debug for MapRequest<F, S, I, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapRequest").finish_non_exhaustive()
    }
}

impl<F: Clone, S: Clone, I: Clone, T> Clone for MapRequest<F, S, I, T> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            inner: self.inner.clone(),
            _extractor: PhantomData,
        }
    }
}

/// Generates one `Service<Request<Body>>` impl per extractor arity for [`MapRequest`], mirroring
/// [`impl_from_fn`]'s arity dispatch, minus the trailing [`Next`] argument: `f`'s last argument
/// is instead the mapped `Request<Body>` itself.
macro_rules! impl_map_request {
    ( $($ty:ident),* ; $last:ident ) => {
        #[allow(non_snake_case, unused_mut)]
        impl<F, Fut, O, S, I, $($ty,)* $last> Service<Request<Body>>
            for MapRequest<F, S, I, ( $($ty,)* $last, )>
        where
            F: Fn($($ty,)* $last) -> Fut + Clone + Send + Sync + 'static,
            $( $ty: FromRequestParts<S> + Send + 'static, )*
            $last: FromRequest<S> + Send + 'static,
            Fut: Future<Output = O> + Send + 'static,
            O: IntoMapRequestResult + Send + 'static,
            I: Service<Request<Body>, Response = Response, Error = Infallible>
                + Clone
                + Send
                + Sync
                + 'static,
            I::Future: Send + 'static,
            S: Clone + Send + Sync + 'static,
        {
            type Response = Response;
            type Error = Infallible;
            type Future = MapRequestResponseFuture;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: Request<Body>) -> Self::Future {
                let f = self.f.clone();
                let state = self.state.clone();
                let inner = self.inner.clone();
                let (mut parts, body) = req.into_parts();
                MapRequestResponseFuture {
                    inner: Box::pin(async move {
                        $(
                            let $ty = match <$ty as FromRequestParts<S>>::from_request_parts(&mut parts, &state).await {
                                Ok(v) => v,
                                Err(r) => return Ok(r.into_response()),
                            };
                        )*
                        let req = Request::from_parts(parts, body);
                        let $last = match <$last as FromRequest<S>>::from_request(req, &state).await {
                            Ok(v) => v,
                            Err(r) => return Ok(r.into_response()),
                        };
                        match f($($ty,)* $last).await.into_map_request_result() {
                            Ok(req) => Ok(drive(inner, req).await),
                            Err(resp) => Ok(resp),
                        }
                    }),
                }
            }
        }
    };
}

impl_map_request!(; A1);
impl_map_request!(A1; A2);
impl_map_request!(A1, A2; A3);
impl_map_request!(A1, A2, A3; A4);
impl_map_request!(A1, A2, A3, A4; A5);
impl_map_request!(A1, A2, A3, A4, A5; A6);
impl_map_request!(A1, A2, A3, A4, A5, A6; A7);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7; A8);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8; A9);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8, A9; A10);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10; A11);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11; A12);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12; A13);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13; A14);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14; A15);
impl_map_request!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15; A16);

/// Houses [`MapRequest`]'s response future under the local name `ResponseFuture` — see
/// [`from_fn_future`] for why each middleware family gets its own module.
mod map_request_future {
    use super::{Context, Future, Infallible, Pin, Poll, Response};

    /// Response future for [`super::MapRequest`]. Matches
    /// `axum::middleware::future::ResponseFuture` (re-exported here as
    /// [`super::MapRequestResponseFuture`]).
    pub struct ResponseFuture {
        pub(super) inner: Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>,
    }

    impl std::fmt::Debug for ResponseFuture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ResponseFuture").finish_non_exhaustive()
        }
    }

    impl Future for ResponseFuture {
        type Output = Result<Response, Infallible>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().inner.as_mut().poll(cx)
        }
    }
}
pub use map_request_future::ResponseFuture as MapRequestResponseFuture;

/// Lets a [`map_request`]/[`map_request_with_state`] closure return either a bare
/// `Request<Body>` or a `Result<Request<Body>, R>`.
///
/// A bare `Request<Body>` always continues the pipeline; `Result::Err(R)`
/// short-circuits it with `R`'s response instead. Matches
/// `axum::middleware::IntoMapRequestResult`.
pub trait IntoMapRequestResult<B = Body> {
    /// Normalizes into a `Result` so both return shapes can be handled uniformly.
    ///
    /// # Errors
    ///
    /// Returns the short-circuit response when the closure this was built from
    /// itself returned `Err`.
    #[allow(clippy::result_large_err)] // matches axum's own signature exactly
    fn into_map_request_result(self) -> Result<Request<B>, Response>;
}

impl IntoMapRequestResult<Body> for Request<Body> {
    #[allow(clippy::result_large_err)]
    fn into_map_request_result(self) -> Result<Self, Response> {
        Ok(self)
    }
}

impl<R> IntoMapRequestResult<Body> for Result<Request<Body>, R>
where
    R: IntoResponse,
{
    #[allow(clippy::result_large_err)]
    fn into_map_request_result(self) -> Result<Request<Body>, Response> {
        self.map_err(IntoResponse::into_response)
    }
}

// --- map_response / map_response_with_state --------------------------------

/// Transforms the response after the rest of the pipeline runs.
///
/// Optionally with a bound state argument first. Matches
/// `axum::middleware::map_response`/`map_response_with_state`. Built via
/// [`map_response`]/[`map_response_with_state`].
pub struct MapResponseLayer<F, S = (), T = ()> {
    f: F,
    state: S,
    _extractor: PhantomData<fn() -> T>,
}

impl<F, S, T> std::fmt::Debug for MapResponseLayer<F, S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapResponseLayer").finish_non_exhaustive()
    }
}

impl<F: Clone, S: Clone, T> Clone for MapResponseLayer<F, S, T> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            _extractor: PhantomData,
        }
    }
}

/// Wraps `f` for use with `.layer()`/`.route_layer()`.
pub const fn map_response<F, T>(f: F) -> MapResponseLayer<F, (), T> {
    map_response_with_state((), f)
}

/// Wraps `f`, binding `state` as its first argument.
pub const fn map_response_with_state<F, S, T>(state: S, f: F) -> MapResponseLayer<F, S, T> {
    MapResponseLayer {
        f,
        state,
        _extractor: PhantomData,
    }
}

impl<F: Clone, S: Clone, T, I> Layer<I> for MapResponseLayer<F, S, T> {
    type Service = MapResponse<F, S, I, T>;

    fn layer(&self, inner: I) -> Self::Service {
        MapResponse {
            f: self.f.clone(),
            state: self.state.clone(),
            inner,
            _extractor: PhantomData,
        }
    }
}

/// The `tower::Service` produced by [`MapResponseLayer`].
pub struct MapResponse<F, S, I, T> {
    f: F,
    state: S,
    inner: I,
    _extractor: PhantomData<fn() -> T>,
}

impl<F, S, I, T> std::fmt::Debug for MapResponse<F, S, I, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapResponse").finish_non_exhaustive()
    }
}

impl<F: Clone, S: Clone, I: Clone, T> Clone for MapResponse<F, S, I, T> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            inner: self.inner.clone(),
            _extractor: PhantomData,
        }
    }
}

/// Generates one `Service<Request<Body>>` impl per leading-extractor arity for [`MapResponse`]:
/// zero or more [`FromRequestParts`] extractors are run against the request before it's driven
/// through the inner service, and their values are handed to `f` alongside the resulting
/// [`Response`].
macro_rules! impl_map_response {
    ( $($ty:ident),* ) => {
        #[allow(non_snake_case, unused_mut, unused_variables)]
        impl<F, Fut, Res, S, I, $($ty,)*> Service<Request<Body>> for MapResponse<F, S, I, ( $($ty,)* )>
        where
            F: Fn($($ty,)* Response) -> Fut + Clone + Send + Sync + 'static,
            $( $ty: FromRequestParts<S> + Send + 'static, )*
            Fut: Future<Output = Res> + Send + 'static,
            Res: IntoResponse + Send + 'static,
            I: Service<Request<Body>, Response = Response, Error = Infallible>
                + Clone
                + Send
                + Sync
                + 'static,
            I::Future: Send + 'static,
            S: Clone + Send + Sync + 'static,
        {
            type Response = Response;
            type Error = Infallible;
            type Future = MapResponseResponseFuture;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: Request<Body>) -> Self::Future {
                let f = self.f.clone();
                let state = self.state.clone();
                let inner = self.inner.clone();
                let (mut parts, body) = req.into_parts();
                MapResponseResponseFuture {
                    inner: Box::pin(async move {
                        $(
                            let $ty = match <$ty as FromRequestParts<S>>::from_request_parts(&mut parts, &state).await {
                                Ok(v) => v,
                                Err(r) => return Ok(r.into_response()),
                            };
                        )*
                        let req = Request::from_parts(parts, body);
                        let resp = drive(inner, req).await;
                        Ok(f($($ty,)* resp).await.into_response())
                    }),
                }
            }
        }
    };
}

impl_map_response!();
impl_map_response!(A1);
impl_map_response!(A1, A2);
impl_map_response!(A1, A2, A3);
impl_map_response!(A1, A2, A3, A4);
impl_map_response!(A1, A2, A3, A4, A5);
impl_map_response!(A1, A2, A3, A4, A5, A6);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7, A8);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7, A8, A9);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13);
impl_map_response!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14);
impl_map_response!(
    A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15
);
impl_map_response!(
    A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16
);

/// Houses [`MapResponse`]'s response future under the local name `ResponseFuture` — see
/// [`from_fn_future`] for why each middleware family gets its own module.
mod map_response_future {
    use super::{Context, Future, Infallible, Pin, Poll, Response};

    /// Response future for [`super::MapResponse`]. Matches
    /// `axum::middleware::future::ResponseFuture` (re-exported here as
    /// [`super::MapResponseResponseFuture`]).
    pub struct ResponseFuture {
        pub(super) inner: Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>,
    }

    impl std::fmt::Debug for ResponseFuture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ResponseFuture").finish_non_exhaustive()
        }
    }

    impl Future for ResponseFuture {
        type Output = Result<Response, Infallible>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().inner.as_mut().poll(cx)
        }
    }
}
pub use map_response_future::ResponseFuture as MapResponseResponseFuture;

// --- from_extractor / from_extractor_with_state ----------------------------

/// Runs an extractor purely for its side effect, discarding the value.
///
/// Short-circuits with the extractor's rejection on failure — the "guard
/// middleware" pattern (auth checks, feature flags, ...). Matches
/// `axum::middleware::from_extractor`. Since `Next` no longer carries state,
/// this runs `E` against unit state (`()`) — use [`from_extractor_with_state`]
/// for an extractor that needs real state.
pub struct FromExtractorLayer<E, S = ()> {
    state: S,
    _marker: PhantomData<fn() -> E>,
}

impl<E, S> std::fmt::Debug for FromExtractorLayer<E, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromExtractorLayer").finish_non_exhaustive()
    }
}

/// Builds the layer for extractor `E`, matching `axum::middleware::from_extractor::<E>()`.
#[must_use]
pub const fn from_extractor<E>() -> FromExtractorLayer<E, ()> {
    FromExtractorLayer {
        state: (),
        _marker: PhantomData,
    }
}

impl<E, S: Clone> Clone for FromExtractorLayer<E, S> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, S: Clone + Sync, T> Layer<T> for FromExtractorLayer<E, S>
where
    E: FromRequestParts<S> + Send + 'static,
{
    type Service = FromExtractor<T, E, S>;

    fn layer(&self, inner: T) -> Self::Service {
        FromExtractor {
            inner,
            state: self.state.clone(),
            _extractor: PhantomData,
        }
    }
}

/// The `tower::Service` produced by [`FromExtractorLayer`].
pub struct FromExtractor<T, E, S> {
    inner: T,
    state: S,
    _extractor: PhantomData<fn() -> E>,
}

impl<T, E, S> std::fmt::Debug for FromExtractor<T, E, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromExtractor").finish_non_exhaustive()
    }
}

impl<T: Clone, E, S: Clone> Clone for FromExtractor<T, E, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: self.state.clone(),
            _extractor: PhantomData,
        }
    }
}

impl<T, E, S> Service<Request<Body>> for FromExtractor<T, E, S>
where
    E: FromRequestParts<S> + Send + 'static,
    E::Rejection: Send,
    S: Clone + Send + Sync + 'static,
    T: Service<Request<Body>, Response = Response, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    T::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = FromExtractorResponseFuture<Body, T, E, S>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        let state = self.state.clone();
        FromExtractorResponseFuture {
            inner: Box::pin(async move {
                let (mut parts, body) = req.into_parts();
                match E::from_request_parts(&mut parts, &state).await {
                    Ok(_) => Ok(drive(inner, Request::from_parts(parts, body)).await),
                    Err(rejection) => Ok(rejection.into_response()),
                }
            }),
            _marker: PhantomData,
        }
    }
}

/// Houses [`FromExtractor`]'s response future under the local name `ResponseFuture` — see
/// [`from_fn_future`] for why each middleware family gets its own module.
mod from_extractor_future {
    use super::{
        Context, FromRequestParts, Future, Infallible, PhantomData, Pin, Poll, Request, Response,
        Service,
    };

    /// The extractor-tuple marker `ResponseFuture` carries but never constructs.
    type ExtractorMarker<B, T, E, S> = fn() -> (B, T, E, S);

    /// Response future for [`super::FromExtractor`]. Matches
    /// `axum::middleware::future::ResponseFuture` (re-exported here as
    /// [`super::FromExtractorResponseFuture`]).
    pub struct ResponseFuture<B, T, E, S>
    where
        E: FromRequestParts<S>,
        T: Service<Request<B>>,
        S: Sync,
    {
        pub(super) inner: Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>,
        pub(super) _marker: PhantomData<ExtractorMarker<B, T, E, S>>,
    }

    impl<B, T, E, S> std::fmt::Debug for ResponseFuture<B, T, E, S>
    where
        E: FromRequestParts<S>,
        T: Service<Request<B>>,
        S: Sync,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ResponseFuture").finish_non_exhaustive()
        }
    }

    impl<B, T, E, S> Future for ResponseFuture<B, T, E, S>
    where
        E: FromRequestParts<S>,
        T: Service<Request<B>>,
        S: Sync,
    {
        type Output = Result<Response, Infallible>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().inner.as_mut().poll(cx)
        }
    }
}
pub use from_extractor_future::ResponseFuture as FromExtractorResponseFuture;

/// Builds the layer for extractor `E`, bound to `state`.
pub const fn from_extractor_with_state<E, S>(state: S) -> FromExtractorLayer<E, S> {
    FromExtractorLayer {
        state,
        _marker: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::extract::{Extension, RawQuery, State};
    use hyper::StatusCode;

    fn route_returning(body: &'static str) -> Route {
        Route::from_handler(move || async move { body }, &std::sync::Arc::new(()))
    }

    #[tokio::test]
    async fn from_fn_is_a_transparent_passthrough() {
        async fn tag(req: Request<Body>, next: Next) -> Response {
            let mut resp = next.run(req).await;
            resp.headers_mut().insert("x-tag", "hit".parse().unwrap());
            resp
        }

        let mut svc = from_fn::<_, (Request<Body>,)>(tag).layer(route_returning("hi"));
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-tag").unwrap(), "hit");
    }

    #[tokio::test]
    async fn from_fn_with_state_hands_state_to_the_closure() {
        use crate::routing::extract::State;

        async fn tag(
            State(state): State<std::sync::Arc<str>>,
            req: Request<Body>,
            next: Next,
        ) -> Response {
            let mut resp = next.run(req).await;
            resp.headers_mut().insert("x-state", state.parse().unwrap());
            resp
        }

        let mut svc = from_fn_with_state::<_, _, (State<std::sync::Arc<str>>, Request<Body>)>(
            std::sync::Arc::<str>::from("bound"),
            tag,
        )
        .layer(route_returning("hi"));
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-state").unwrap(), "bound");
    }

    #[tokio::test]
    async fn map_request_transforms_before_the_inner_route_runs() {
        async fn add_header(mut req: Request<Body>) -> Request<Body> {
            req.headers_mut().insert("x-added", "yes".parse().unwrap());
            req
        }

        let seen_header = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen = std::sync::Arc::clone(&seen_header);
        let route = Route::from_handler(
            move |req: Request<Body>| {
                let seen = std::sync::Arc::clone(&seen);
                async move {
                    *seen.lock().unwrap() = req.headers().get("x-added").cloned();
                    "ok"
                }
            },
            &std::sync::Arc::new(()),
        );

        let mut svc = map_request::<_, (Request<Body>,)>(add_header).layer(route);
        let req = Request::builder().body(Body::empty()).unwrap();
        svc.call(req).await.unwrap();
        assert_eq!(seen_header.lock().unwrap().as_ref().unwrap(), "yes");
    }

    #[tokio::test]
    async fn map_response_transforms_after_the_inner_route_runs() {
        async fn tag(mut resp: Response) -> Response {
            resp.headers_mut()
                .insert("x-mapped", "yes".parse().unwrap());
            resp
        }

        let mut svc = map_response::<_, ()>(tag).layer(route_returning("hi"));
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-mapped").unwrap(), "yes");
    }

    #[tokio::test]
    async fn from_extractor_passes_through_on_success_and_discards_the_value() {
        let mut svc = from_extractor::<RawQuery>().layer(route_returning("hi"));
        let req = Request::builder()
            .uri("/x?a=1")
            .body(Body::empty())
            .unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn from_extractor_short_circuits_on_rejection() {
        let mut svc = from_extractor::<Extension<u32>>().layer(route_returning("hi"));
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.call(req).await.unwrap();
        // `Extension<u32>` rejects with 500 when the extension isn't present.
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn from_extractor_with_state_uses_the_bound_state_not_unit_state() {
        let mut svc = from_extractor_with_state::<State<u32>, u32>(42).layer(route_returning("hi"));
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
