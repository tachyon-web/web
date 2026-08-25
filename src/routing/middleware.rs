//! Middleware primitives: the [`Next`] continuation.
//!
//! Middleware is applied via `tower::Layer` (`Router::layer`/`route_layer`,
//! `MethodRouter::layer`) — the same mechanism Axum itself is built on, not a
//! separate bespoke system. [`fn@from_fn`] and friends below are the one
//! Axum-shaped convenience most middleware functions actually want; anything
//! needing a real `tower::Layer`/`tower::Service` pair can be written
//! directly against those traits and passed to `.layer()` like any other.

/// `axum::middleware::from_fn` and friends.
///
/// See that module's docs for how closely this matches Axum's real,
/// extractor-arity-based version.
pub mod from_fn;
pub use from_fn::{
    from_extractor, from_extractor_with_state, from_fn, from_fn_with_state, map_request,
    map_request_with_state, map_response, map_response_with_state,
};

use crate::http::response::Body;
use crate::routing::tower_compat::Route;
use hyper::{Request, Response};
use tower::{Service, ServiceExt};

/// The continuation for the next middleware/handler in the chain, matching
/// `axum::middleware::Next` — including its state-erasure.
///
/// As in Axum, application state flows to a middleware function only
/// through extractor arguments (or a bound closure for
/// [`from_fn_with_state`]), never through `Next` itself.
pub struct Next(pub(crate) Route);

impl std::fmt::Debug for Next {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Next").finish_non_exhaustive()
    }
}

impl Next {
    /// Executes the next handler in the pipeline.
    #[inline]
    pub async fn run(self, req: Request<Body>) -> Response<Body> {
        let Self(mut route) = self;
        match route.ready().await {
            Ok(ready) => match ready.call(req).await {
                Ok(resp) => resp,
                Err(infallible) => match infallible {},
            },
            Err(infallible) => match infallible {},
        }
    }
}
