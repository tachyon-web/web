//! `tower::Service`/`tower::Layer` as the real routing/middleware foundation.
//!
//! Matches Axum's own internals: every registered route boils down to a
//! type-erased, cloneable [`Route`], and middleware is applied by literally
//! calling `tower::Layer::layer()` on it — not a separate, bespoke closure
//! system. `tower` is a hard dependency of this crate for exactly that
//! reason (see `Cargo.toml`), the same as it is for Axum itself.

use crate::http::error::Error;
use crate::http::response::{Body, IntoResponse};
use crate::routing::handler::{BoxedFuture, Handler, HandlerResponseFuture};
use bytes::Bytes;
use hyper::{Request, Response};
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service, ServiceExt as _};

/// A type-erased, cheaply-cloneable `tower::Service` — the atomic unit every
/// compiled route, fallback, and nested router boils down to.
///
/// Matches `axum::routing::Route<E>`: `E` is a real, propagated error type — a raw
/// `tower::Service` handed to `get_service`/`on_service`/etc. keeps its own error all
/// the way up to [`crate::routing::Router::route`], which (like axum) only accepts it
/// once `E = Infallible`. `Handler`-based routes never carry a live `E` at all, since
/// [`Handler::call`](crate::routing::handler::Handler::call) has no `Error` type — it
/// always resolves to a `Response` via [`IntoResponse`] before it ever reaches a `Route`.
pub struct Route<E = Infallible>(
    tower::util::BoxCloneSyncService<Request<Body>, Response<Body>, E>,
);

impl<E> Clone for Route<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E> std::fmt::Debug for Route<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Route").finish()
    }
}

impl<E> Route<E> {
    pub(crate) fn new<Svc>(svc: Svc) -> Self
    where
        Svc: Service<Request<Body>, Error = E> + Clone + Send + Sync + 'static,
        Svc::Response: IntoResponse + 'static,
        Svc::Future: Send + 'static,
    {
        Self(tower::util::BoxCloneSyncService::new(
            tower::util::MapResponseLayer::new(IntoResponse::into_response).layer(svc),
        ))
    }

    /// Applies a `tower::Layer` to this route, matching `axum::routing::Route::layer`
    /// (and, transitively, `Router::layer`/`MethodRouter::layer`). The layered service's
    /// error is mapped into `NewError` via `Into` — it is never collapsed into a
    /// [`Response`] here; that only happens where a real `Handler` is built, or where the
    /// caller explicitly opts in via
    /// [`HandleErrorLayer`](crate::routing::error_handling::HandleErrorLayer).
    pub(crate) fn layer<L, NewError>(self, layer: &L) -> Route<NewError>
    where
        L: Layer<Self>,
        L::Service: Service<Request<Body>> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<Body>>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request<Body>>>::Error: Into<NewError> + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
        NewError: 'static,
    {
        let layered = layer.layer(self);
        Route::new(tower::util::MapErr::new(layered, Into::into))
    }
}

impl Route<Infallible> {
    /// Builds the base `Route` for a bare [`Handler`], bound to `state` —
    /// the starting point every `.layer()` call wraps further. Always infallible: a
    /// `Handler` has no error to propagate.
    pub(crate) fn from_handler<H, T, S>(handler: H, state: &Arc<S>) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: 'static,
        S: Clone + Send + Sync + 'static,
    {
        Self::new(HandlerService::new(handler, (**state).clone()))
    }
}

impl<E: 'static> Service<Request<Body>> for Route<E> {
    type Response = Response<Body>;
    type Error = E;
    type Future = RouteFuture<E>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        RouteFuture::new(self.0.call(req))
    }
}

/// Response future for [`Route`]. Matches `axum::routing::future::RouteFuture`.
pub struct RouteFuture<E> {
    inner: Pin<Box<dyn Future<Output = Result<Response<Body>, E>> + Send>>,
}

impl<E> std::fmt::Debug for RouteFuture<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteFuture").finish_non_exhaustive()
    }
}

impl<E> RouteFuture<E> {
    fn new(inner: impl Future<Output = Result<Response<Body>, E>> + Send + 'static) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<E> Future for RouteFuture<E> {
    type Output = Result<Response<Body>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// A [`RouteFuture`] that always yields a [`Response`], matching
/// `axum::routing::future::InfallibleRouteFuture`.
///
/// Not yet produced by anything in this crate (axum's only source is `MethodRouter`
/// implementing its own `Handler` trait, letting one router be nested as a handler in
/// another — not yet ported) — kept as a real, usable type for axum-ported code that
/// names it directly.
pub struct InfallibleRouteFuture {
    future: RouteFuture<Infallible>,
}

impl std::fmt::Debug for InfallibleRouteFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfallibleRouteFuture")
            .finish_non_exhaustive()
    }
}

impl InfallibleRouteFuture {
    #[allow(dead_code)]
    pub(crate) const fn new(future: RouteFuture<Infallible>) -> Self {
        Self { future }
    }
}

impl Future for InfallibleRouteFuture {
    type Output = Response<Body>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.future).poll(cx) {
            Poll::Ready(Ok(resp)) => Poll::Ready(resp),
            Poll::Ready(Err(never)) => match never {},
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Wraps an arbitrary `tower::Service` (typically a freshly-layered one) so its response
/// body and error type are normalized to what [`Route`] needs.
///
/// Normalizes to `Response<Body>`/`Error = Infallible` before being boxed back into a
/// `Route` — the one normalization point every layer application funnels through. Matches
/// `axum::middleware::ResponseAxumBody`. Built via [`ResponseAxumBodyLayer`].
pub struct ResponseAxumBody<S>(S);

impl<S: Clone> Clone for ResponseAxumBody<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S> std::fmt::Debug for ResponseAxumBody<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseAxumBody").finish_non_exhaustive()
    }
}

impl<S, RespBody> Service<Request<Body>> for ResponseAxumBody<S>
where
    S: Service<Request<Body>, Response = Response<RespBody>> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Error> + Send,
    RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
    RespBody::Error: Into<Error>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = ResponseAxumBodyFuture;

    /// Readiness failures are deferred into `call` (via `ServiceExt::ready` there) rather
    /// than surfaced here, matching the rest of this module: a `Route` must never itself
    /// report `Err`, so there is nowhere for a `poll_ready` failure to go except into the
    /// response the next `call` produces.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.0.clone();
        let mut inner = std::mem::replace(&mut self.0, clone);
        ResponseAxumBodyFuture {
            inner: Box::pin(async move {
                let result = match inner.ready().await {
                    Ok(ready) => ready.call(req).await,
                    Err(e) => Err(e),
                };
                Ok(match result {
                    Ok(resp) => {
                        let (parts, body) = resp.into_parts();
                        Response::from_parts(parts, Body::stream(body))
                    }
                    Err(e) => Into::<Error>::into(e).into_response(),
                })
            }),
            _marker: PhantomData,
        }
    }
}

/// Response future for [`ResponseAxumBody`]. Matches
/// `axum::middleware::ResponseAxumBodyFuture`.
pub struct ResponseAxumBodyFuture<Fut = ()> {
    inner: Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>,
    _marker: PhantomData<fn() -> Fut>,
}

impl<Fut> std::fmt::Debug for ResponseAxumBodyFuture<Fut> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseAxumBodyFuture")
            .finish_non_exhaustive()
    }
}

impl<Fut> Future for ResponseAxumBodyFuture<Fut> {
    type Output = Result<Response<Body>, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// `tower::Layer` producing [`ResponseAxumBody`]. Matches
/// `axum::middleware::ResponseAxumBodyLayer`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResponseAxumBodyLayer;

impl ResponseAxumBodyLayer {
    /// Builds the layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ResponseAxumBodyLayer {
    type Service = ResponseAxumBody<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseAxumBody(inner)
    }
}

/// Marker type parameter for [`Handler`] impls backed by a raw `tower::Service`.
#[derive(Debug)]
pub struct TowerServiceMarker;

/// Wraps a `tower::Service` so it can be registered as a route handler.
///
/// Used by [`Router::route_service`](crate::routing::Router::route_service),
/// [`Router::nest_service`](crate::routing::Router::nest_service), and
/// [`Router::fallback_service`](crate::routing::Router::fallback_service).
#[derive(Debug, Clone)]
pub struct ServiceHandler<Svc> {
    pub(crate) service: Svc,
    /// When `Some(prefix)`, the request URI's path is rewritten via
    /// [`crate::routing::strip_uri_prefix`] to strip this exact leading byte
    /// sequence (used by `nest_service`, matching Axum's nested-service path
    /// rewriting — see that function's docs for the percent-encoding caveat).
    pub(crate) strip_prefix: Option<Arc<str>>,
}

impl<Svc, RespBody, S> Handler<TowerServiceMarker, S> for ServiceHandler<Svc>
where
    S: Send + Sync + 'static,
    Svc: Service<Request<Body>, Response = Response<RespBody>> + Clone + Send + Sync + 'static,
    Svc::Future: Send + 'static,
    Svc::Error: Into<Error> + Send,
    RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
    RespBody::Error: Into<Error>,
{
    type Future = BoxedFuture;

    fn call(self, mut req: Request<Body>, _state: S) -> BoxedFuture {
        if let Some(prefix) = &self.strip_prefix {
            crate::routing::strip_uri_prefix(&mut req, prefix);
        }

        let mut service = self.service;
        HandlerResponseFuture::Boxed(Box::pin(async move {
            match service.ready().await {
                Ok(ready) => match ready.call(req).await {
                    Ok(resp) => {
                        let (parts, body) = resp.into_parts();
                        Response::from_parts(parts, Body::stream(body))
                    }
                    Err(e) => Into::<Error>::into(e).into_response(),
                },
                Err(e) => Into::<Error>::into(e).into_response(),
            }
        }))
    }
}

/// Lets a compiled router be driven directly as a `tower::Service` — the
/// idiomatic Axum testing pattern (`app.oneshot(request).await`, via
/// `tower::ServiceExt`) works unchanged against a `CompiledRouter`, and a
/// `CompiledRouter` can be handed to any other Tower/Hyper API expecting a
/// `Service<Request<B>>`.
///
/// Unlike Axum (which only implements this for `Router<()>`, since a
/// `Router<S>` for `S != ()` hasn't been given its state yet), this is
/// implemented for `CompiledRouter<S>` for **any** state type: a compiled
/// router is always fully self-contained (its state was bound at `compile()`
/// time), so there's no equivalent "not runnable yet" state to restrict this to.
impl<S, B> Service<Request<B>> for crate::routing::CompiledRouter<S>
where
    S: Send + Sync + 'static,
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, Body::stream(body));
        let this = self.clone();
        Box::pin(async move { Ok(this.handle_request(req).await) })
    }
}

/// A handler bound to `state`, matching `axum::handler::Handler::with_state`.
///
/// Lets a bare handler be served directly (no `Router`) or passed to any Tower/Hyper API
/// expecting a `Service<Request<Body>>`. Built via [`Handler::with_state`].
pub struct HandlerService<H, T, S> {
    handler: H,
    state: S,
    _marker: PhantomData<fn() -> T>,
}

impl<H, T, S> HandlerService<H, T, S> {
    pub(crate) const fn new(handler: H, state: S) -> Self {
        Self {
            handler,
            state,
            _marker: PhantomData,
        }
    }
}

impl<H: Clone, T, S: Clone> Clone for HandlerService<H, T, S> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            state: self.state.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H, T, S> std::fmt::Debug for HandlerService<H, T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerService").finish_non_exhaustive()
    }
}

impl<H, T, S> Service<Request<Body>> for HandlerService<H, T, S>
where
    H: Handler<T, S> + Clone,
    S: Clone + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = IntoServiceFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let handler = self.handler.clone();
        let state = self.state.clone();
        IntoServiceFuture {
            inner: Box::pin(async move { Ok(handler.call(req, state).await) }),
            _marker: PhantomData,
        }
    }
}

/// Response future for [`HandlerService`]'s `Service` impl. Matches
/// `axum::handler::future::IntoServiceFuture`.
pub struct IntoServiceFuture<F = ()> {
    inner: Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>,
    _marker: PhantomData<fn() -> F>,
}

impl<F> std::fmt::Debug for IntoServiceFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntoServiceFuture").finish_non_exhaustive()
    }
}

impl<F> Future for IntoServiceFuture<F> {
    type Output = Result<Response<Body>, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// A handler wrapped with a `tower::Layer`, matching `axum::handler::Handler::layer` —
/// produced by [`Handler::layer`].
pub struct Layered<L, H, T, S> {
    layer: L,
    handler: H,
    _marker: PhantomData<fn() -> (T, S)>,
}

impl<L, H, T, S> Layered<L, H, T, S> {
    pub(crate) const fn new(layer: L, handler: H) -> Self {
        Self {
            layer,
            handler,
            _marker: PhantomData,
        }
    }
}

impl<L: Clone, H: Clone, T, S> Clone for Layered<L, H, T, S> {
    fn clone(&self) -> Self {
        Self {
            layer: self.layer.clone(),
            handler: self.handler.clone(),
            _marker: PhantomData,
        }
    }
}

impl<L, H, T, S> std::fmt::Debug for Layered<L, H, T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layered").finish_non_exhaustive()
    }
}

impl<L, H, T, S, RespBody> Handler<T, S> for Layered<L, H, T, S>
where
    H: Handler<T, S> + Clone,
    S: Clone + Send + Sync + 'static,
    T: 'static,
    L: Layer<HandlerService<H, T, S>> + Clone + Send + Sync + 'static,
    L::Service: Service<Request<Body>, Response = Response<RespBody>> + Send + 'static,
    <L::Service as Service<Request<Body>>>::Future: Send + 'static,
    <L::Service as Service<Request<Body>>>::Error: Into<Error> + Send,
    RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
    RespBody::Error: Into<Error>,
{
    type Future = BoxedFuture;

    fn call(self, req: Request<Body>, state: S) -> BoxedFuture {
        let inner = HandlerService::new(self.handler, state);
        let mut layered = self.layer.layer(inner);
        let fut = LayeredFuture {
            inner: Box::pin(async move {
                match layered.ready().await {
                    Ok(ready) => match ready.call(req).await {
                        Ok(resp) => {
                            let (parts, body) = resp.into_parts();
                            Response::from_parts(parts, Body::stream(body))
                        }
                        Err(e) => Into::<Error>::into(e).into_response(),
                    },
                    Err(e) => Into::<Error>::into(e).into_response(),
                }
            }),
            _marker: PhantomData::<fn() -> L::Service>,
        };
        HandlerResponseFuture::Boxed(Box::pin(fut))
    }
}

/// The future backing [`Layered`]'s `Handler::call`, produced while awaiting its
/// wrapped `tower::Layer` pipeline. Matches `axum::handler::future::LayeredFuture`.
pub struct LayeredFuture<S>
where
    S: Service<crate::http::Request>,
{
    inner: Pin<Box<dyn Future<Output = Response<Body>> + Send>>,
    _marker: PhantomData<fn() -> S>,
}

impl<S> std::fmt::Debug for LayeredFuture<S>
where
    S: Service<crate::http::Request>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayeredFuture").finish_non_exhaustive()
    }
}

impl<S> Future for LayeredFuture<S>
where
    S: Service<crate::http::Request>,
{
    type Output = Response<Body>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// Adds `Handler::into_service`/`Handler::into_make_service` sugar for stateless handlers.
///
/// Applies to handlers already at `Handler<T, ()>`, skipping the explicit
/// `.with_state(())` call that [`Handler::with_state`] otherwise requires. Matches
/// `axum::handler::HandlerWithoutStateExt`.
pub trait HandlerWithoutStateExt<T>: Handler<T, ()> {
    /// Converts this handler directly into a `tower::Service`, matching
    /// `axum::handler::HandlerWithoutStateExt::into_service`.
    fn into_service(self) -> HandlerService<Self, T, ()> {
        self.with_state(())
    }

    /// Converts this handler directly into a `tower::make::MakeService`, matching
    /// `axum::handler::HandlerWithoutStateExt::into_make_service`.
    fn into_make_service(self) -> IntoMakeService<HandlerService<Self, T, ()>> {
        self.into_service().into_make_service()
    }

    /// Converts this handler directly into a `tower::make::MakeService` that also
    /// derives a [`ConnectInfo<C>`](crate::routing::extract::ConnectInfo) from each
    /// accepted [`IncomingStream`], matching
    /// `axum::handler::HandlerWithoutStateExt::into_make_service_with_connect_info`.
    fn into_make_service_with_connect_info<C>(
        self,
    ) -> IntoMakeServiceWithConnectInfo<HandlerService<Self, T, ()>, C> {
        self.into_service().into_make_service_with_connect_info()
    }
}

impl<H, T> HandlerWithoutStateExt<T> for H where H: Handler<T, ()> {}

/// Lets an uncompiled, stateless [`crate::routing::Router`] be driven
/// directly as a `tower::Service` — e.g. `Router::new().route(...).oneshot(req)`
/// — with no separate `.compile()` call, matching `axum::Router`'s drop-in
/// ergonomics exactly: build with `.route()`/`.nest()`/`.merge()`/`.layer()`/
/// etc., then hand the same value straight to `.oneshot()`, a `tower`
/// server, or anything else expecting a `Service`.
///
/// Internally this compiles the `matchit` route tree **once**, the first
/// time `call()` runs, and caches the result in `Router`'s private
/// `compiled` field — every builder method that mutates the route table
/// resets that cache, so it's impossible to silently dispatch against a
/// stale tree. Every call after the first is exactly as cheap as calling
/// the already-`CompiledRouter` directly; the split from `axum::Router`
/// (which has no separate compiled form at all) is now purely internal.
///
/// Deliberately restricted to `Router<()>`, matching Axum exactly (Axum only
/// implements `Service` for `Router<()>` too — a `Router<S>` for `S != ()`
/// hasn't been given its state yet, so there's nothing meaningful to serve).
/// This is what makes plain `Router::new().route(...).oneshot(req)` type-check
/// with no turbofish: `Service` has exactly one impl to unify against, same
/// as in Axum. A router built with real shared state (`State<T>` extractors)
/// still needs `.with_state(actual_state)` first, same as Axum — at that
/// point it's already a `Router<()>` too. For testing a still-generic
/// `Router<S>`/`CompiledRouter<S>` for `S != ()` directly, use
/// [`CompiledRouter`](crate::routing::CompiledRouter)'s broader impl above
/// via an explicit `.compile()`.
///
/// ```rust,no_run
/// use tachyon_web::{Router, get};
/// use tower::ServiceExt;
///
/// async fn handler() -> &'static str { "hi" }
///
/// # async fn build() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let app = Router::new().route("/", get(handler));
/// let req = hyper::Request::builder().uri("/").body(http_body_util::Full::new(bytes::Bytes::new()))?;
/// let resp = app.oneshot(req).await?;
/// # let _ = resp;
/// # Ok(())
/// # }
/// ```
impl<B> Service<Request<B>> for crate::routing::Router<()>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[allow(clippy::expect_used)]
    fn call(&mut self, req: Request<B>) -> Self::Future {
        if self.compiled.is_none() {
            let built = std::mem::take(self);
            self.compiled = Some(
                built
                    .compile()
                    .expect("Router compilation failed (e.g. an overlapping/duplicate route)"),
            );
        }
        let compiled = self.compiled.as_mut().expect("just populated above");
        Service::call(compiled, req)
    }
}

/// Lets a bare `Router` be passed directly to [`crate::server::serve`], matching axum's own
/// `impl<L> Service<serve::IncomingStream<'_, L>> for Router<()>`: the router is its own trivial
/// `MakeService`, cloning itself once per accepted connection rather than needing an explicit
/// `.into_make_service()` call.
impl<L> Service<IncomingStream<'_, L>> for crate::routing::Router<()>
where
    L: crate::server::Listener,
{
    type Response = Self;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: IncomingStream<'_, L>) -> Self::Future {
        std::future::ready(Ok(self.clone()))
    }
}

/// A [`Router`](crate::routing::Router) converted into a borrowed `tower::Service`.
///
/// Has a fixed body type. Matches `axum::routing::RouterAsService`. Built via
/// [`Router::as_service`](crate::routing::Router::as_service).
pub struct RouterAsService<'a, B, S = ()> {
    router: &'a mut crate::routing::Router<S>,
    _marker: PhantomData<fn(B)>,
}

impl<'a, B, S> RouterAsService<'a, B, S> {
    pub(crate) fn new(router: &'a mut crate::routing::Router<S>) -> Self {
        Self {
            router,
            _marker: PhantomData,
        }
    }
}

impl<B, S> std::fmt::Debug for RouterAsService<'_, B, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterAsService")
            .field("router", &self.router)
            .finish()
    }
}

impl<B> Service<Request<B>> for RouterAsService<'_, B, ()>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::<Request<B>>::poll_ready(self.router, cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        Service::call(self.router, req)
    }
}

/// A [`Router`](crate::routing::Router) converted into an owned `tower::Service`.
///
/// Has a fixed body type. Matches `axum::routing::RouterIntoService`. Built via
/// [`Router::into_service`](crate::routing::Router::into_service).
pub struct RouterIntoService<B, S = ()> {
    router: crate::routing::Router<S>,
    _marker: PhantomData<fn(B)>,
}

impl<B, S: Clone> Clone for RouterIntoService<B, S> {
    fn clone(&self) -> Self {
        Self {
            router: self.router.clone(),
            _marker: PhantomData,
        }
    }
}

impl<B, S> RouterIntoService<B, S> {
    pub(crate) fn new(router: crate::routing::Router<S>) -> Self {
        Self {
            router,
            _marker: PhantomData,
        }
    }
}

impl<B, S> std::fmt::Debug for RouterIntoService<B, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterIntoService")
            .field("router", &self.router)
            .finish()
    }
}

impl<B> Service<Request<B>> for RouterIntoService<B, ()>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::<Request<B>>::poll_ready(&mut self.router, cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        Service::call(&mut self.router, req)
    }
}

/// A `tower::make::MakeService` that clones out a fresh copy of the wrapped service.
///
/// One clone per connection. Matches `axum::routing::IntoMakeService`. Built via
/// [`Router::into_make_service`](crate::routing::Router::into_make_service) (or
/// [`ServiceExt::into_make_service`] for any other `tower::Service`).
#[derive(Debug, Clone)]
pub struct IntoMakeService<S> {
    svc: S,
}

impl<S> IntoMakeService<S> {
    pub(crate) const fn new(svc: S) -> Self {
        Self { svc }
    }
}

impl<S, T> Service<T> for IntoMakeService<S>
where
    S: Clone,
{
    type Response = S;
    type Error = Infallible;
    type Future = IntoMakeServiceFuture<S>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _target: T) -> Self::Future {
        IntoMakeServiceFuture::new(self.svc.clone())
    }
}

/// Response future for [`IntoMakeService`]. Matches
/// `axum::routing::future::IntoMakeServiceFuture`.
pub struct IntoMakeServiceFuture<S> {
    future: std::future::Ready<Result<S, Infallible>>,
}

impl<S> IntoMakeServiceFuture<S> {
    fn new(svc: S) -> Self {
        Self {
            future: std::future::ready(Ok(svc)),
        }
    }
}

impl<S> std::fmt::Debug for IntoMakeServiceFuture<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntoMakeServiceFuture")
            .finish_non_exhaustive()
    }
}

impl<S> Future for IntoMakeServiceFuture<S> {
    type Output = Result<S, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().future).poll(cx)
    }
}

/// Extension trait adding a couple of extra methods to any `tower::Service`.
/// Matches `axum::ServiceExt`.
pub trait ServiceExt<R>: Service<R> + Sized {
    /// Converts this service into a `tower::make::MakeService`. Matches
    /// `axum::ServiceExt::into_make_service`.
    fn into_make_service(self) -> IntoMakeService<Self>;

    /// Converts this service into a `tower::make::MakeService` that also derives a
    /// [`ConnectInfo<C>`](crate::routing::extract::ConnectInfo) from each accepted
    /// [`IncomingStream`] and inserts it into every request. Matches
    /// `axum::ServiceExt::into_make_service_with_connect_info`.
    ///
    /// [`Server`](crate::server::Server) doesn't need this — it injects `ConnectInfo`
    /// directly on every request as it accepts each connection. This exists for
    /// embedding a bare `tower::Service` (e.g. a [`Router`](crate::routing::Router))
    /// under a different accept loop that only hands you the raw socket addresses.
    fn into_make_service_with_connect_info<C>(self) -> IntoMakeServiceWithConnectInfo<Self, C> {
        IntoMakeServiceWithConnectInfo {
            svc: self,
            _marker: PhantomData,
        }
    }

    /// Converts this service into a [`crate::routing::error_handling::HandleError`], which
    /// handles its errors by converting them into responses. Matches
    /// `axum::ServiceExt::handle_error`.
    fn handle_error<F, T>(self, f: F) -> crate::routing::error_handling::HandleError<Self, F, T> {
        crate::routing::error_handling::HandleError::new(self, f)
    }
}

impl<S, R> ServiceExt<R> for S
where
    S: Service<R> + Sized,
{
    fn into_make_service(self) -> IntoMakeService<Self> {
        IntoMakeService::new(self)
    }
}

/// A connection accepted by [`crate::serve`]'s (or a caller's own) accept loop, before its
/// per-connection `tower::Service` is produced from it.
///
/// Matches `axum::serve::IncomingStream`: generic over the listener type `L`, giving a
/// `MakeService` access to the raw accepted IO (e.g. for TLS SNI inspection, peer certs,
/// Unix-socket credentials) as well as the address.
pub struct IncomingStream<'a, L>
where
    L: crate::server::Listener,
{
    io: &'a hyper_util::rt::TokioIo<L::Io>,
    remote_addr: L::Addr,
}

impl<'a, L: crate::server::Listener> IncomingStream<'a, L> {
    /// Builds an `IncomingStream` from an accepted connection's IO and address.
    pub(crate) const fn new(io: &'a hyper_util::rt::TokioIo<L::Io>, remote_addr: L::Addr) -> Self {
        Self { io, remote_addr }
    }

    /// The raw accepted IO.
    #[must_use]
    pub fn io(&self) -> &L::Io {
        self.io.inner()
    }

    /// The peer's address, in whatever shape `L::Addr` reports it.
    #[must_use]
    pub const fn remote_addr(&self) -> &L::Addr {
        &self.remote_addr
    }
}

impl<L: crate::server::Listener> std::fmt::Debug for IncomingStream<'_, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingStream").finish_non_exhaustive()
    }
}

/// Derives a [`ConnectInfo`](crate::routing::extract::ConnectInfo) payload from an
/// accepted connection. Matches `axum::extract::connect_info::Connected`.
pub trait Connected<T>: Clone + Send + Sync + 'static {
    /// Builds the connect-info value for this connection.
    fn connect_info(stream: T) -> Self;
}

impl Connected<IncomingStream<'_, tokio::net::TcpListener>> for std::net::SocketAddr {
    fn connect_info(stream: IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        stream.remote_addr
    }
}

/// A `tower::Service` that inserts a fixed connect-info value into every request.
///
/// Wraps the request with [`ConnectInfo<C>`](crate::routing::extract::ConnectInfo)
/// before forwarding it to the inner service. Built via
/// [`IntoMakeServiceWithConnectInfo`]'s `Service<IncomingStream>` impl, or directly via
/// [`MockConnectInfo`] for tests.
pub struct ConnectInfoService<S, C> {
    svc: S,
    connect_info: C,
}

impl<S: Clone, C: Clone> Clone for ConnectInfoService<S, C> {
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            connect_info: self.connect_info.clone(),
        }
    }
}

impl<S, C> std::fmt::Debug for ConnectInfoService<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectInfoService").finish_non_exhaustive()
    }
}

impl<S, C> Service<Request<Body>> for ConnectInfoService<S, C>
where
    S: Service<Request<Body>>,
    C: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.svc.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        req.extensions_mut()
            .insert(crate::routing::extract::ConnectInfo(
                self.connect_info.clone(),
            ));
        self.svc.call(req)
    }
}

/// A `tower::make::MakeService` that clones out a fresh copy of the wrapped service.
///
/// Tags each clone with `ConnectInfo<C>` derived from its accepted [`IncomingStream`].
/// Matches `axum::extract::connect_info::IntoMakeServiceWithConnectInfo`. Built via
/// [`ServiceExt::into_make_service_with_connect_info`].
pub struct IntoMakeServiceWithConnectInfo<S, C> {
    svc: S,
    _marker: PhantomData<fn() -> C>,
}

impl<S: Clone, C> Clone for IntoMakeServiceWithConnectInfo<S, C> {
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, C> std::fmt::Debug for IntoMakeServiceWithConnectInfo<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntoMakeServiceWithConnectInfo")
            .finish_non_exhaustive()
    }
}

impl<'a, S, C, L> Service<IncomingStream<'a, L>> for IntoMakeServiceWithConnectInfo<S, C>
where
    S: Clone,
    C: Connected<IncomingStream<'a, L>>,
    L: crate::server::Listener,
{
    type Response = ConnectInfoService<S, C>;
    type Error = Infallible;
    type Future = ResponseFuture<S, C>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: IncomingStream<'a, L>) -> Self::Future {
        let connect_info = C::connect_info(target);
        ResponseFuture {
            inner: std::future::ready(Ok(ConnectInfoService {
                svc: self.svc.clone(),
                connect_info,
            })),
        }
    }
}

/// Response future for [`IntoMakeServiceWithConnectInfo`]. Matches
/// `axum::extract::connect_info::ResponseFuture`.
pub struct ResponseFuture<S, C> {
    inner: std::future::Ready<Result<ConnectInfoService<S, C>, Infallible>>,
}

impl<S, C> std::fmt::Debug for ResponseFuture<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseFuture").finish_non_exhaustive()
    }
}

impl<S, C> Future for ResponseFuture<S, C> {
    type Output = Result<ConnectInfoService<S, C>, Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// A `tower::Layer` that unconditionally inserts a fixed connect-info value.
///
/// Wraps every request with a fixed
/// [`ConnectInfo<C>`](crate::routing::extract::ConnectInfo) — for testing handlers
/// that use `ConnectInfo` without going through a real accept loop. Matches
/// `axum::extract::connect_info::MockConnectInfo`.
#[derive(Debug, Clone, Copy)]
pub struct MockConnectInfo<T>(pub T);

impl<T: Clone, S> Layer<S> for MockConnectInfo<T> {
    type Service = ConnectInfoService<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectInfoService {
            svc: inner,
            connect_info: self.0.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[derive(Clone)]
    struct TagHeaderLayer;

    impl<S> Layer<S> for TagHeaderLayer {
        type Service = TagHeaderService<S>;
        fn layer(&self, inner: S) -> Self::Service {
            TagHeaderService(inner)
        }
    }

    #[derive(Clone)]
    struct TagHeaderService<S>(S);

    impl<S> Service<Request<Body>> for TagHeaderService<S>
    where
        S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Send,
    {
        type Response = Response<Body>;
        type Error = S::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, S::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.0.poll_ready(cx)
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            let fut = self.0.call(req);
            Box::pin(async move {
                let mut resp = fut.await?;
                let _ = resp
                    .headers_mut()
                    .insert("x-layered", hyper::header::HeaderValue::from_static("yes"));
                Ok(resp)
            })
        }
    }

    async fn hello() -> &'static str {
        "hi"
    }

    #[tokio::test]
    async fn handler_ext_layer_wraps_a_bare_handler_with_a_tower_layer() {
        let layered = hello.layer(TagHeaderLayer);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = Handler::call(layered, req, Arc::new(())).await;
        assert_eq!(resp.headers().get("x-layered").unwrap(), "yes");
    }

    #[tokio::test]
    async fn handler_ext_with_state_produces_a_tower_service() {
        let mut svc = hello.with_state(());
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn handler_ext_layer_and_with_state_compose() {
        let mut svc = hello.layer(TagHeaderLayer).with_state(());
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-layered").unwrap(), "yes");
    }

    #[tokio::test]
    async fn route_layer_wraps_and_normalizes_an_arbitrary_tower_layer() {
        let base = Route::<Infallible>::from_handler(hello, &Arc::new(()));
        let mut layered: Route<Infallible> = base.layer(&TagHeaderLayer);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = layered.call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-layered").unwrap(), "yes");
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn route_layer_composes_across_multiple_applications() {
        let base = Route::<Infallible>::from_handler(hello, &Arc::new(()));
        let once: Route<Infallible> = base.layer(&TagHeaderLayer);
        let twice: Route<Infallible> = once.layer(&TagHeaderLayer);
        let req = Request::builder().body(Body::empty()).unwrap();
        let mut twice = twice;
        let resp = twice.call(req).await.unwrap();
        // `insert` overwrites, so this only proves both layers ran without erroring.
        assert_eq!(resp.headers().get_all("x-layered").iter().count(), 1);
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }
}
