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
use tower::{Layer, Service, ServiceExt};

/// A type-erased, cheaply-cloneable `tower::Service` — the atomic unit every
/// compiled route, fallback, and nested router boils down to. Matches
/// `axum::routing::Route`.
///
/// Always infallible from the outside (`Error = Infallible`): whatever a
/// layered `tower::Service` actually returns as its error is converted to a
/// response (via `Into<Error>` + [`IntoResponse`]) the moment it's boxed back
/// into a `Route`, so a `Route` can never itself fail to produce a response.
#[derive(Clone)]
pub struct Route(tower::util::BoxCloneSyncService<Request<Body>, Response<Body>, Infallible>);

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Route").finish()
    }
}

impl Route {
    fn new<Svc>(svc: Svc) -> Self
    where
        Svc: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        Svc::Future: Send + 'static,
    {
        Self(tower::util::BoxCloneSyncService::new(svc))
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
    pub(crate) fn layer<L, RespBody>(self, layer: L) -> Self
    where
        L: Layer<Self>,
        L::Service: Service<Request<Body>, Response = Response<RespBody>>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
        <L::Service as Service<Request<Body>>>::Error: Into<Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<Error>,
    {
        Self::new(Normalize(layer.layer(self)))
    }
}

impl Service<Request<Body>> for Route {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        self.0.call(req)
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
        let base = Route::from_handler(hello, Arc::new(()));
        let mut layered = base.layer(TagHeaderLayer);
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = layered.call(req).await.unwrap();
        assert_eq!(resp.headers().get("x-layered").unwrap(), "yes");
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn route_layer_composes_across_multiple_applications() {
        let base = Route::from_handler(hello, Arc::new(()));
        let once = base.layer(TagHeaderLayer);
        let twice = once.layer(TagHeaderLayer);
        let req = Request::builder().body(Body::empty()).unwrap();
        let mut twice = twice;
        let resp = twice.call(req).await.unwrap();
        // `insert` overwrites, so this only proves both layers ran without erroring.
        assert_eq!(resp.headers().get_all("x-layered").iter().count(), 1);
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }
}
