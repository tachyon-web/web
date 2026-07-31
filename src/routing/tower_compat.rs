//! Optional interop with the `tower` ecosystem (`tower::Service` / `tower::Layer`).
//!
//! This module exists so real Axum apps that mount a pre-built Tower service
//! (e.g. `tower_http::services::ServeDir`, a `tonic` gRPC service) or apply a
//! `tower::Layer` (tracing, compression, timeouts, concurrency limits) can still
//! be ported without a rewrite.
//!
//! **This is deliberately not the recommended path.** Every call into a Tower
//! `Service` goes through an extra `Box<dyn Future>` indirection and (for
//! layers) a fresh `Service` value per request — overhead the native
//! `.hoop()`/`.hoop_at()` middleware system is built to avoid. Prefer native
//! middleware; reach for this only to bridge in existing Tower/tower-http code.

use crate::http::error::Error;
use crate::http::response::{Body, IntoResponse};
use crate::routing::handler::{BoxedFuture, Handler, ResponseFuture};
use crate::routing::middleware::Next;
use bytes::Bytes;
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service, ServiceExt};

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
    Svc: Service<Request<Bytes>, Response = Response<RespBody>> + Clone + Send + Sync + 'static,
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
            // Tower services conventionally expect a fully-buffered body; only
            // native tachyon handlers (via `BodyStream`/`Request<Body>`) get the
            // option of true streaming.
            let limit = crate::routing::extract::max_body_size(req.extensions());
            let (parts, body) = req.into_parts();
            let bytes = match body.collect_bytes(limit).await {
                Ok(b) => b,
                Err(e) => return e.into_response(),
            };
            let req = Request::from_parts(parts, bytes);
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

/// A one-shot `tower::Service` adapter over a [`Next`] continuation — lets a
/// `tower::Layer` wrap "the rest of the tachyon pipeline" for this request.
pub struct NextService<S> {
    next: Option<Next<S>>,
}

impl<S> std::fmt::Debug for NextService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NextService").finish_non_exhaustive()
    }
}

impl<S> NextService<S> {
    pub(crate) const fn new(next: Next<S>) -> Self {
        Self { next: Some(next) }
    }
}

impl<S: Send + Sync + 'static> Service<Request<Bytes>> for NextService<S> {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Bytes>) -> Self::Future {
        let next = self.next.take();
        Box::pin(async move {
            let Some(next) = next else {
                unreachable!("NextService called more than once for the same request")
            };
            let (parts, bytes) = req.into_parts();
            Ok(next
                .run(Request::from_parts(parts, Body::full(bytes)))
                .await)
        })
    }
}

/// Adapts a `tower::Layer` into a native tachyon middleware closure, so it can
/// be installed via the same `.hoop_at()` machinery as any other middleware.
pub(crate) fn from_tower_layer<L, S, RespBody>(
    layer: L,
) -> impl Fn(Request<Body>, Next<S>) -> ResponseFuture + Clone + Send + Sync + 'static
where
    S: Send + Sync + 'static,
    L: Layer<NextService<S>> + Clone + Send + Sync + 'static,
    L::Service: Service<Request<Bytes>, Response = Response<RespBody>> + Send + 'static,
    <L::Service as Service<Request<Bytes>>>::Future: Send + 'static,
    <L::Service as Service<Request<Bytes>>>::Error: Into<Error> + Send,
    RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
    RespBody::Error: Into<Error>,
{
    move |req, next| {
        let layer = layer.clone();
        ResponseFuture::Boxed(Box::pin(async move {
            // As with `ServiceHandler`, the Tower side of the bridge always sees a
            // fully-buffered body.
            let limit = crate::routing::extract::max_body_size(req.extensions());
            let (parts, body) = req.into_parts();
            let bytes = match body.collect_bytes(limit).await {
                Ok(b) => b,
                Err(e) => return e.into_response(),
            };
            let req = Request::from_parts(parts, bytes);
            let mut layered = layer.layer(NextService::new(next));
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
    S: Clone + Send + Sync + 'static,
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

/// Lets an uncompiled, stateless [`crate::routing::Router`] be driven
/// directly as a `tower::Service` — e.g. `Router::new().route(...).oneshot(req)`
/// — with no separate `.compile()` call, matching `axum::Router`'s drop-in
/// ergonomics exactly: build with `.route()`/`.nest()`/`.merge()`/`.hoop()`/
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
