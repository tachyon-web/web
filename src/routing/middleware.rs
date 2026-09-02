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
mod from_fn;
/// The `tower::Service` [`Extension`](crate::routing::extract::Extension)'s `tower::Layer`
/// impl produces, at the path `axum::middleware` uses for it.
pub use crate::routing::extract::AddExtension;
/// The response-body-normalizing `tower::Service`/`tower::Layer` every `.layer()` call
/// funnels through, at the path `axum::middleware` uses for them.
pub use crate::routing::tower_compat::{
    ResponseAxumBody, ResponseAxumBodyFuture, ResponseAxumBodyLayer,
};
/// [`fn@map_request`]'s target-return-type sugar, at the path `axum::middleware` uses.
pub use from_fn::IntoMapRequestResult;
/// The `tower::Layer`/`tower::Service` types [`fn@from_fn`] and friends produce, at the
/// paths `axum::middleware` uses for them.
pub use from_fn::{
    FromExtractor, FromExtractorLayer, FromFn, FromFnLayer, MapRequest, MapRequestLayer,
    MapResponse, MapResponseLayer,
};
pub use from_fn::{
    from_extractor, from_extractor_with_state, from_fn, from_fn_with_state, map_request,
    map_request_with_state, map_response, map_response_with_state,
};

/// `Future` types returned by the `Service` impls above, matching `axum::middleware::future`.
pub mod future {
    pub use crate::routing::middleware::from_fn::{
        FromExtractorResponseFuture, FromFnResponseFuture, MapRequestResponseFuture,
        MapResponseResponseFuture,
    };
    pub use crate::routing::tower_compat::ResponseAxumBodyFuture;
}

use crate::routing::tower_compat::Route;
use tower::{Service, ServiceExt};

/// The continuation for the next middleware/handler in the chain, matching
/// `axum::middleware::Next` — including its state-erasure.
///
/// As in Axum, application state flows to a middleware function only
/// through extractor arguments (or a bound closure for
/// [`from_fn_with_state`]), never through `Next` itself.
///
/// *Axum compatibility: drop-in replacement for `axum::middleware::Next`.*
pub struct Next {
    pub(crate) inner: Route,
}

impl Clone for Next {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl std::fmt::Debug for Next {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Next").finish_non_exhaustive()
    }
}

impl Next {
    /// Executes the next handler in the pipeline.
    #[inline]
    pub async fn run(
        self,
        req: crate::routing::extract::Request,
    ) -> crate::http::response::Response {
        let Self { mut inner } = self;
        match inner.ready().await {
            Ok(ready) => match ready.call(req).await {
                Ok(resp) => resp,
                Err(infallible) => match infallible {},
            },
            Err(infallible) => match infallible {},
        }
    }
}
