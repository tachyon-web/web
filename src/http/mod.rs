//! HTTP constructs like error types and response helpers.

pub mod compression;
#[cfg(feature = "early-hints")]
pub mod early_hints;
pub mod error;
pub mod response;
pub mod sfv;

// Re-export standard HTTP types for convenience so users don't need to depend on `hyper` or `http` directly.
pub use hyper::header;
pub use hyper::{HeaderMap, Method, StatusCode, Uri};
pub use response::Response;

/// A Tachyon HTTP request, generic over its body type (defaulting to
/// [`response::Body`]). Matches `axum_core::extract::Request`.
///
/// *Tachyon extension: no `axum` equivalent.*
pub type Request<T = response::Body> = hyper::Request<T>;
