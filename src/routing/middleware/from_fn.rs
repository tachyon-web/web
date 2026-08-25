//! `axum::middleware::from_fn` and friends, as real `tower::Layer`/`tower::Service`
//! pairs wrapping [`Route`] — the same mechanism `Router::layer` itself uses,
//! not a separate bespoke system.
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

use crate::http::response::{Body, IntoResponse, Response};
use crate::routing::extract::FromRequestParts;
use crate::routing::middleware::Next;
use crate::routing::tower_compat::Route;
use hyper::Request;
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service, ServiceExt};

/// Runs `route` to completion, converting its (infallible) result into a
/// boxed future — the one place every `Service` below funnels its final
/// dispatch through.
fn drive(mut route: Route, req: Request<Body>) -> Pin<Box<dyn Future<Output = Response> + Send>> {
    Box::pin(async move {
        match route.ready().await {
            Ok(ready) => match ready.call(req).await {
                Ok(resp) => resp,
                Err(never) => match never {},
            },
            Err(never) => match never {},
        }
    })
}

// --- from_fn -----------------------------------------------------------

/// `tower::Layer` wrapping an `async fn(Request<Body>, Next) -> impl IntoResponse`.
///
/// Matches `axum::middleware::from_fn` in spirit; see the module docs for how
/// the signature differs. Built via [`from_fn`].
pub struct FromFnLayer<F>(F);

impl<F> std::fmt::Debug for FromFnLayer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromFnLayer").finish_non_exhaustive()
    }
}

/// Wraps `f` for use with `.layer()`/`.route_layer()`.
pub const fn from_fn<F, Fut, Res>(f: F) -> FromFnLayer<F>
where
    F: Fn(Request<Body>, Next) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
{
    FromFnLayer(f)
}

impl<F: Clone> Clone for FromFnLayer<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F, Fut, Res> Layer<Route> for FromFnLayer<F>
where
    F: Fn(Request<Body>, Next) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
{
    type Service = FromFn<F>;

    fn layer(&self, inner: Route) -> Self::Service {
        FromFn {
            f: self.0.clone(),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`FromFnLayer`].
pub struct FromFn<F> {
    f: F,
    inner: Route,
}

impl<F> std::fmt::Debug for FromFn<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromFn").finish_non_exhaustive()
    }
}

impl<F: Clone> Clone for FromFn<F> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<F, Fut, Res> Service<Request<Body>> for FromFn<F>
where
    F: Fn(Request<Body>, Next) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let f = self.f.clone();
        let next = Next(self.inner.clone());
        Box::pin(async move { Ok(f(req, next).await.into_response()) })
    }
}

// --- from_fn_with_state --------------------------------------------------

/// Like [`FromFnLayer`], but binds `state` and hands it to `f` as its first
/// argument (a plain `S2` clone, not an extractor).
///
/// Matches `axum::middleware::from_fn_with_state` — see the module docs for
/// how the signature differs. Built via [`from_fn_with_state`].
pub struct FromFnWithStateLayer<F, S2> {
    f: F,
    state: S2,
}

impl<F, S2> std::fmt::Debug for FromFnWithStateLayer<F, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromFnWithStateLayer").finish_non_exhaustive()
    }
}

/// Wraps `f`, binding `state` as its first argument.
pub const fn from_fn_with_state<F, Fut, Res, S2>(state: S2, f: F) -> FromFnWithStateLayer<F, S2>
where
    F: Fn(S2, Request<Body>, Next) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    FromFnWithStateLayer { f, state }
}

impl<F: Clone, S2: Clone> Clone for FromFnWithStateLayer<F, S2> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
        }
    }
}

impl<F, Fut, Res, S2> Layer<Route> for FromFnWithStateLayer<F, S2>
where
    F: Fn(S2, Request<Body>, Next) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    type Service = FromFnWithState<F, S2>;

    fn layer(&self, inner: Route) -> Self::Service {
        FromFnWithState {
            f: self.f.clone(),
            state: self.state.clone(),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`FromFnWithStateLayer`].
pub struct FromFnWithState<F, S2> {
    f: F,
    state: S2,
    inner: Route,
}

impl<F, S2> std::fmt::Debug for FromFnWithState<F, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromFnWithState").finish_non_exhaustive()
    }
}

impl<F: Clone, S2: Clone> Clone for FromFnWithState<F, S2> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<F, Fut, Res, S2> Service<Request<Body>> for FromFnWithState<F, S2>
where
    F: Fn(S2, Request<Body>, Next) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let f = self.f.clone();
        let state = self.state.clone();
        let next = Next(self.inner.clone());
        Box::pin(async move { Ok(f(state, req, next).await.into_response()) })
    }
}

// --- map_request / map_request_with_state ---------------------------------

/// Transforms the request before running the rest of the pipeline.
///
/// Matches `axum::middleware::map_request`, minus its
/// `Result<Request, Response>` short-circuiting return (return early from
/// `f` and drive the rest of the pipeline from inside your own
/// [`from_fn`] middleware directly if you need that).
pub struct MapRequestLayer<F>(F);

impl<F> std::fmt::Debug for MapRequestLayer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapRequestLayer").finish_non_exhaustive()
    }
}

/// Wraps `f` for use with `.layer()`/`.route_layer()`.
pub const fn map_request<F, Fut>(f: F) -> MapRequestLayer<F>
where
    F: Fn(Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Request<Body>> + Send + 'static,
{
    MapRequestLayer(f)
}

impl<F: Clone> Clone for MapRequestLayer<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F, Fut> Layer<Route> for MapRequestLayer<F>
where
    F: Fn(Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Request<Body>> + Send + 'static,
{
    type Service = MapRequest<F>;

    fn layer(&self, inner: Route) -> Self::Service {
        MapRequest {
            f: self.0.clone(),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`MapRequestLayer`].
pub struct MapRequest<F> {
    f: F,
    inner: Route,
}

impl<F> std::fmt::Debug for MapRequest<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapRequest").finish_non_exhaustive()
    }
}

impl<F: Clone> Clone for MapRequest<F> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<F, Fut> Service<Request<Body>> for MapRequest<F>
where
    F: Fn(Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Request<Body>> + Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let f = self.f.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            let req = f(req).await;
            Ok(drive(inner, req).await)
        })
    }
}

/// Like [`MapRequestLayer`], but with a bound `state` clone passed to `f`
/// first. Matches `axum::middleware::map_request_with_state`.
pub struct MapRequestWithStateLayer<F, S2> {
    f: F,
    state: S2,
}

impl<F, S2> std::fmt::Debug for MapRequestWithStateLayer<F, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapRequestWithStateLayer").finish_non_exhaustive()
    }
}

/// Wraps `f`, binding `state` as its first argument.
pub const fn map_request_with_state<F, Fut, S2>(state: S2, f: F) -> MapRequestWithStateLayer<F, S2>
where
    F: Fn(S2, Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Request<Body>> + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    MapRequestWithStateLayer { f, state }
}

impl<F: Clone, S2: Clone> Clone for MapRequestWithStateLayer<F, S2> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
        }
    }
}

impl<F, Fut, S2> Layer<Route> for MapRequestWithStateLayer<F, S2>
where
    F: Fn(S2, Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Request<Body>> + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    type Service = MapRequestWithState<F, S2>;

    fn layer(&self, inner: Route) -> Self::Service {
        MapRequestWithState {
            f: self.f.clone(),
            state: self.state.clone(),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`MapRequestWithStateLayer`].
pub struct MapRequestWithState<F, S2> {
    f: F,
    state: S2,
    inner: Route,
}

impl<F, S2> std::fmt::Debug for MapRequestWithState<F, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapRequestWithState").finish_non_exhaustive()
    }
}

impl<F: Clone, S2: Clone> Clone for MapRequestWithState<F, S2> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<F, Fut, S2> Service<Request<Body>> for MapRequestWithState<F, S2>
where
    F: Fn(S2, Request<Body>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Request<Body>> + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let f = self.f.clone();
        let state = self.state.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            let req = f(state, req).await;
            Ok(drive(inner, req).await)
        })
    }
}

// --- map_response / map_response_with_state --------------------------------

/// Transforms the response after the rest of the pipeline runs. Matches
/// `axum::middleware::map_response`.
pub struct MapResponseLayer<F>(F);

impl<F> std::fmt::Debug for MapResponseLayer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapResponseLayer").finish_non_exhaustive()
    }
}

/// Wraps `f` for use with `.layer()`/`.route_layer()`.
pub const fn map_response<F, Fut, Res>(f: F) -> MapResponseLayer<F>
where
    F: Fn(Response) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
{
    MapResponseLayer(f)
}

impl<F: Clone> Clone for MapResponseLayer<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F, Fut, Res> Layer<Route> for MapResponseLayer<F>
where
    F: Fn(Response) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
{
    type Service = MapResponse<F>;

    fn layer(&self, inner: Route) -> Self::Service {
        MapResponse {
            f: self.0.clone(),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`MapResponseLayer`].
pub struct MapResponse<F> {
    f: F,
    inner: Route,
}

impl<F> std::fmt::Debug for MapResponse<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapResponse").finish_non_exhaustive()
    }
}

impl<F: Clone> Clone for MapResponse<F> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<F, Fut, Res> Service<Request<Body>> for MapResponse<F>
where
    F: Fn(Response) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let f = self.f.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            let resp = drive(inner, req).await;
            Ok(f(resp).await.into_response())
        })
    }
}

/// Like [`MapResponseLayer`], but with a bound `state` clone passed to `f`
/// first. Matches `axum::middleware::map_response_with_state`.
pub struct MapResponseWithStateLayer<F, S2> {
    f: F,
    state: S2,
}

impl<F, S2> std::fmt::Debug for MapResponseWithStateLayer<F, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapResponseWithStateLayer").finish_non_exhaustive()
    }
}

/// Wraps `f`, binding `state` as its first argument.
pub const fn map_response_with_state<F, Fut, Res, S2>(
    state: S2,
    f: F,
) -> MapResponseWithStateLayer<F, S2>
where
    F: Fn(S2, Response) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    MapResponseWithStateLayer { f, state }
}

impl<F: Clone, S2: Clone> Clone for MapResponseWithStateLayer<F, S2> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
        }
    }
}

impl<F, Fut, Res, S2> Layer<Route> for MapResponseWithStateLayer<F, S2>
where
    F: Fn(S2, Response) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    type Service = MapResponseWithState<F, S2>;

    fn layer(&self, inner: Route) -> Self::Service {
        MapResponseWithState {
            f: self.f.clone(),
            state: self.state.clone(),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`MapResponseWithStateLayer`].
pub struct MapResponseWithState<F, S2> {
    f: F,
    state: S2,
    inner: Route,
}

impl<F, S2> std::fmt::Debug for MapResponseWithState<F, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapResponseWithState").finish_non_exhaustive()
    }
}

impl<F: Clone, S2: Clone> Clone for MapResponseWithState<F, S2> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            state: self.state.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<F, Fut, Res, S2> Service<Request<Body>> for MapResponseWithState<F, S2>
where
    F: Fn(S2, Response) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let f = self.f.clone();
        let state = self.state.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            let resp = drive(inner, req).await;
            Ok(f(state, resp).await.into_response())
        })
    }
}

// --- from_extractor / from_extractor_with_state ----------------------------

/// Runs an extractor purely for its side effect, discarding the value.
///
/// Short-circuits with the extractor's rejection on failure — the "guard
/// middleware" pattern (auth checks, feature flags, ...). Matches
/// `axum::middleware::from_extractor`. Since `Next` no longer carries state,
/// this runs `E` against unit state (`()`) — use [`from_extractor_with_state`]
/// for an extractor that needs real state.
pub struct FromExtractorLayer<E>(PhantomData<fn() -> E>);

impl<E> std::fmt::Debug for FromExtractorLayer<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromExtractorLayer").finish_non_exhaustive()
    }
}

/// Builds the layer for extractor `E`, matching `axum::middleware::from_extractor::<E>()`.
#[must_use]
pub fn from_extractor<E>() -> FromExtractorLayer<E>
where
    E: FromRequestParts<()> + Send + 'static,
{
    FromExtractorLayer(PhantomData)
}

impl<E> Clone for FromExtractorLayer<E> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<E> Layer<Route> for FromExtractorLayer<E>
where
    E: FromRequestParts<()> + Send + 'static,
{
    type Service = FromExtractor<E>;

    fn layer(&self, inner: Route) -> Self::Service {
        FromExtractor {
            inner,
            _marker: PhantomData,
        }
    }
}

/// The `tower::Service` produced by [`FromExtractorLayer`].
pub struct FromExtractor<E> {
    inner: Route,
    _marker: PhantomData<fn() -> E>,
}

impl<E> std::fmt::Debug for FromExtractor<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromExtractor").finish_non_exhaustive()
    }
}

impl<E> Clone for FromExtractor<E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E> Service<Request<Body>> for FromExtractor<E>
where
    E: FromRequestParts<()> + Send + 'static,
    E::Rejection: Send,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            match E::from_request_parts(&mut parts, &()).await {
                Ok(_) => Ok(drive(inner, Request::from_parts(parts, body)).await),
                Err(rejection) => Ok(rejection.into_response()),
            }
        })
    }
}

/// Like [`FromExtractorLayer`], but the extractor runs against a bound
/// `state` clone (`E: FromRequestParts<S2>`) rather than unit state. Matches
/// `axum::middleware::from_extractor_with_state`.
pub struct FromExtractorWithStateLayer<E, S2> {
    state: S2,
    _marker: PhantomData<fn() -> E>,
}

impl<E, S2> std::fmt::Debug for FromExtractorWithStateLayer<E, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromExtractorWithStateLayer").finish_non_exhaustive()
    }
}

/// Builds the layer for extractor `E`, bound to `state`.
pub fn from_extractor_with_state<E, S2>(state: S2) -> FromExtractorWithStateLayer<E, S2>
where
    E: FromRequestParts<S2> + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    FromExtractorWithStateLayer {
        state,
        _marker: PhantomData,
    }
}

impl<E, S2: Clone> Clone for FromExtractorWithStateLayer<E, S2> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, S2> Layer<Route> for FromExtractorWithStateLayer<E, S2>
where
    E: FromRequestParts<S2> + Send + 'static,
    S2: Clone + Send + Sync + 'static,
{
    type Service = FromExtractorWithState<E, S2>;

    fn layer(&self, inner: Route) -> Self::Service {
        FromExtractorWithState {
            state: self.state.clone(),
            inner,
            _marker: PhantomData,
        }
    }
}

/// The `tower::Service` produced by [`FromExtractorWithStateLayer`].
pub struct FromExtractorWithState<E, S2> {
    state: S2,
    inner: Route,
    _marker: PhantomData<fn() -> E>,
}

impl<E, S2> std::fmt::Debug for FromExtractorWithState<E, S2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromExtractorWithState").finish_non_exhaustive()
    }
}

impl<E, S2: Clone> Clone for FromExtractorWithState<E, S2> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, S2> Service<Request<Body>> for FromExtractorWithState<E, S2>
where
    E: FromRequestParts<S2> + Send + 'static,
    E::Rejection: Send,
    S2: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        let state = self.state.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            match E::from_request_parts(&mut parts, &state).await {
                Ok(_) => Ok(drive(inner, Request::from_parts(parts, body)).await),
                Err(rejection) => Ok(rejection.into_response()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::extract::{Extension, RawQuery, State};
    use hyper::StatusCode;

    fn route_returning(body: &'static str) -> Route {
        Route::from_handler(move || async move { body }, std::sync::Arc::new(()))
    }

    #[tokio::test]
    async fn from_fn_is_a_transparent_passthrough() {
        async fn tag(req: Request<Body>, next: Next) -> Response {
            let mut resp = next.run(req).await;
            resp.headers_mut().insert("x-tag", "hit".parse().unwrap());
            resp
        }

        let mut svc = from_fn(tag).layer(route_returning("hi"));
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-tag").unwrap(), "hit");
    }

    #[tokio::test]
    async fn from_fn_with_state_hands_state_to_the_closure() {
        async fn tag(state: std::sync::Arc<str>, req: Request<Body>, next: Next) -> Response {
            let mut resp = next.run(req).await;
            resp.headers_mut()
                .insert("x-state", state.parse().unwrap());
            resp
        }

        let mut svc =
            from_fn_with_state(std::sync::Arc::<str>::from("bound"), tag).layer(route_returning("hi"));
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
            std::sync::Arc::new(()),
        );

        let mut svc = map_request(add_header).layer(route);
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

        let mut svc = map_response(tag).layer(route_returning("hi"));
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
