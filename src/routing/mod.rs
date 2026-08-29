//! Axum-compatible routing: [`Router`], [`MethodRouter`], and the per-verb builders.
//!
//! Every registered route ultimately becomes a [`tower_compat::Route`] — a
//! type-erased, cloneable `tower::Service` — and middleware is applied by
//! calling real `tower::Layer::layer()` on it (`.layer()`/`.route_layer()`),
//! matching Axum's own internals rather than a separate bespoke system.
//!
//! Internally this module is split by concern: [`method_router`] is the
//! per-verb dispatch table, [`router`] is the route-table builder API, and
//! [`compiled`] is the `matchit`-backed request-dispatch hot path.

#[cfg(feature = "early-hints")]
use hyper::Request;

pub mod compiled;
pub mod error_handling;
pub mod extract;
pub mod handler;
pub mod method_router;
pub mod middleware;
pub mod router;
pub mod static_dir;
pub mod tower_compat;

#[cfg(feature = "early-hints")]
use crate::http::response::Body;

pub use compiled::CompiledRouter;
#[allow(unused_imports)]
pub(crate) use compiled::{RouteResolution, extract_param_names, percent_decode, strip_uri_prefix};
pub use handler::{BoxedFuture, BoxedHandler, Handler};
pub use method_router::{
    MethodFilter, MethodRouter, any, any_service, connect, connect_service, delete, delete_service,
    get, get_service, head, head_service, on, on_service, options, options_service, patch,
    patch_service, post, post_service, put, put_service, trace, trace_service,
};
pub use router::{Router, RouterError};
pub use tower_compat::Route;

/// Emits a pre-rendered `103 Early Hints` block for `req`, if the transport wired one up.
///
/// Shared by the [`MethodRouter`] and [`Router`] forms of `early_hints`, which differ only
/// in what they are attached to.
#[cfg(feature = "early-hints")]
pub(crate) fn fire_early_hints(req: &Request<Body>, headers: hyper::HeaderMap) {
    if let Some(hints) = req
        .extensions()
        .get::<crate::http::early_hints::EarlyHints>()
    {
        let _ = hints.send_headers(headers);
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
