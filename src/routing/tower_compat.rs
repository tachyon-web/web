//! `tower::Service`/`tower::Layer` as the real routing/middleware foundation.
//!
//! Matches Axum's own internals: every registered route boils down to a
//! type-erased, cloneable [`Route`], and middleware is applied by literally
//! calling `tower::Layer::layer()` on it — not a separate, bespoke closure
//! system. `tower` is a hard dependency of this crate for exactly that
//! reason (see `Cargo.toml`), the same as it is for Axum itself.

use crate::http::error::Error;
use crate::http::response::{Body, IntoResponse};
use crate::routing::handler::{BoxedFuture, Handler, ResponseFuture};
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
/// compiled route, fallback, and nested router boils down to. Matches
/// `axum::routing::Route<E>`.
///
/// Unlike axum's `Route<E>` (which genuinely propagates a live `E`, forcing
/// callers to pre-collapse any fallible layer via `HandleErrorLayer` before
/// it can reach a `Router`), this `Route` is *always* infallible on the
/// inside: whatever a layered `tower::Service` actually returns as its error
/// is converted to a response (via `Into<Error>` + [`IntoResponse`]) the
/// moment it's boxed back into a `Route`, regardless of what `E` names. `E`
/// exists purely so this type's signature matches axum's — it's never
/// actually constructed, so any `E` (including axum's real, fallible ones)
/// works here with no `HandleErrorLayer` required. See the `E`-threading
/// note in `MethodRouter`'s docs for the same trade-off one level up.
pub struct Route<E = Infallible>(
    tower::util::BoxCloneSyncService<Request<Body>, Response<Body>, Infallible>,
    PhantomData<fn() -> E>,
);

impl<E> Clone for Route<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
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
        Svc: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        Svc::Future: Send + 'static,
    {
        Self(tower::util::BoxCloneSyncService::new(svc), PhantomData)
    }

    /// Builds the base `Route` for a bare [`Handler`], bound to `state` —
    /// the starting point every `.layer()` call wraps further.
    pub(crate) fn from_handler<H, T, S>(handler: H, state: Arc<S>) -> Self
    where
        H: Handler<T, S> + Clone + Send + Sync + 'static,
        T: Send + 'static,
        S: Send + Sync + 'static,
    {
        Self::new(HandlerService {
            handler,
            state,
            _marker: PhantomData,
        })
    }

    /// Applies a `tower::Layer` to this route, matching `axum::routing::Route::layer`
    /// (and, transitively, `Router::layer`/`MethodRouter::layer`).
    pub(crate) fn layer<L, RespBody, NewError>(self, layer: L) -> Route<NewError>
    where
        L: Layer<Self>,
        L::Service:
            Service<Request<Body>, Response = Response<RespBody>> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
        <L::Service as Service<Request<Body>>>::Error: Into<Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<Error>,
    {
        Route::new(Normalize(layer.layer(self)))
    }
}

impl<E> Service<Request<Body>> for Route<E> {
    type Response = Response<Body>;
    type Error = E;
    type Future = RouteFuture<E>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.0.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(never)) => match never {},
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        RouteFuture::new(self.0.call(req))
    }
}

/// Response future for [`Route`]. Matches `axum::routing::future::RouteFuture`.
///
/// Like `Route` itself, `E` is a phantom marker here rather than a type this future can
/// actually produce: the boxed inner future it drives is always infallible.
pub struct RouteFuture<E> {
    inner: Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>,
    _marker: PhantomData<fn() -> E>,
}

impl<E> std::fmt::Debug for RouteFuture<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteFuture").finish_non_exhaustive()
    }
}

impl<E> RouteFuture<E> {
    fn new(
        inner: impl Future<Output = Result<Response<Body>, Infallible>> + Send + 'static,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            _marker: PhantomData,
        }
    }
}

impl<E> Future for RouteFuture<E> {
    type Output = Result<Response<Body>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.inner.as_mut().poll(cx) {
            Poll::Ready(Ok(resp)) => Poll::Ready(Ok(resp)),
            Poll::Ready(Err(never)) => match never {},
            Poll::Pending => Poll::Pending,
        }
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

/// Wraps an arbitrary `tower::Service` (typically a freshly-layered one) so
/// its response body and error type are normalized to what [`Route`] needs
/// (`Response<Body>`, `Error = Infallible`) before being boxed back into one.
/// The one normalization point every layer application funnels through.
struct Normalize<S>(S);

impl<S: Clone> Clone for Normalize<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, RespBody> Service<Request<Body>> for Normalize<S>
where
    S: Service<Request<Body>, Response = Response<RespBody>> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Error> + Send,
    RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
    RespBody::Error: Into<Error>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

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
        Box::pin(async move {
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
        })
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
    fn call(self, mut req: Request<Body>, _state: Arc<S>) -> BoxedFuture {
        if let Some(prefix) = &self.strip_prefix {
            crate::routing::strip_uri_prefix(&mut req, prefix);
        }

        let mut service = self.service;
        ResponseFuture::Boxed(Box::pin(async move {
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
/// expecting a `Service<Request<Body>>`. Built via [`HandlerExt::with_state`].
pub struct HandlerService<H, T, S> {
    handler: H,
    state: Arc<S>,
    _marker: PhantomData<fn() -> T>,
}

impl<H: Clone, T, S> Clone for HandlerService<H, T, S> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            state: Arc::clone(&self.state),
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
    S: Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let handler = self.handler.clone();
        let state = Arc::clone(&self.state);
        Box::pin(async move { Ok(handler.call(req, state).await) })
    }
}

/// A handler wrapped with a `tower::Layer`, matching `axum::handler::Handler::layer` —
/// produced by [`HandlerExt::layer`].
pub struct LayeredHandler<L, H, T, S> {
    layer: L,
    handler: H,
    _marker: PhantomData<fn() -> (T, S)>,
}

impl<L: Clone, H: Clone, T, S> Clone for LayeredHandler<L, H, T, S> {
    fn clone(&self) -> Self {
        Self {
            layer: self.layer.clone(),
            handler: self.handler.clone(),
            _marker: PhantomData,
        }
    }
}

impl<L, H, T, S> std::fmt::Debug for LayeredHandler<L, H, T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayeredHandler").finish_non_exhaustive()
    }
}

impl<L, H, T, S, RespBody> Handler<T, S> for LayeredHandler<L, H, T, S>
where
    H: Handler<T, S> + Clone,
    S: Send + Sync + 'static,
    T: Send + 'static,
    L: Layer<HandlerService<H, T, S>> + Clone + Send + Sync + 'static,
    L::Service: Service<Request<Body>, Response = Response<RespBody>> + Send + 'static,
    <L::Service as Service<Request<Body>>>::Future: Send + 'static,
    <L::Service as Service<Request<Body>>>::Error: Into<Error> + Send,
    RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
    RespBody::Error: Into<Error>,
{
    fn call(self, req: Request<Body>, state: Arc<S>) -> BoxedFuture {
        let inner = HandlerService {
            handler: self.handler,
            state,
            _marker: PhantomData,
        };
        let mut layered = self.layer.layer(inner);
        ResponseFuture::Boxed(Box::pin(async move {
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
        }))
    }
}

/// Adds Axum's per-handler `Handler::layer`/`Handler::with_state` methods.
pub trait HandlerExt<T, S>: Handler<T, S> {
    /// Wraps this handler with a `tower::Layer`, matching
    /// `axum::handler::Handler::layer`.
    fn layer<L>(self, layer: L) -> LayeredHandler<L, Self, T, S>
    where
        Self: Sized,
        L: Layer<HandlerService<Self, T, S>> + Clone + Send + Sync + 'static,
    {
        LayeredHandler {
            layer,
            handler: self,
            _marker: PhantomData,
        }
    }

    /// Binds `state`, producing a `tower::Service` that no longer needs it supplied per
    /// call — matches `axum::handler::Handler::with_state`.
    fn with_state(self, state: S) -> HandlerService<Self, T, S>
    where
        Self: Sized,
    {
        HandlerService {
            handler: self,
            state: Arc::new(state),
            _marker: PhantomData,
        }
    }
}

impl<H, T, S> HandlerExt<T, S> for H where H: Handler<T, S> {}

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
///
/// Matches `axum::ServiceExt` (minus `into_make_service_with_connect_info`, which needs
/// the `ConnectInfo`/`Listener` genericization this crate hasn't ported yet).
pub trait ServiceExt<R>: Service<R> + Sized {
    /// Converts this service into a `tower::make::MakeService`. Matches
    /// `axum::ServiceExt::into_make_service`.
    fn into_make_service(self) -> IntoMakeService<Self>;

    /// Converts this service into a [`crate::routing::error_handling::HandleError`], which
    /// handles its errors by converting them into responses. Matches
    /// `axum::ServiceExt::handle_error`.
    fn handle_error<F>(self, f: F) -> crate::routing::error_handling::HandleError<Self, F> {
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
        let base = Route::<Infallible>::from_handler(hello, Arc::new(()));
        let mut layered: Route<Infallible> = base.layer(TagHeaderLayer);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = layered.call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-layered").unwrap(), "yes");
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn route_layer_composes_across_multiple_applications() {
        let base = Route::<Infallible>::from_handler(hello, Arc::new(()));
        let once: Route<Infallible> = base.layer(TagHeaderLayer);
        let twice: Route<Infallible> = once.layer(TagHeaderLayer);
        let req = Request::builder().body(Body::empty()).unwrap();
        let mut twice = twice;
        let resp = twice.call(req).await.unwrap();
        // `insert` overwrites, so this only proves both layers ran without erroring.
        assert_eq!(resp.headers().get_all("x-layered").iter().count(), 1);
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }
}
