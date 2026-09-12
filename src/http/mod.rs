//! HTTP constructs like error types and response helpers.

pub mod compression;
pub mod error;
pub mod response;

// Re-export standard HTTP types for convenience so users don't need to depend on `hyper` or `http` directly.
pub use hyper::header;
pub use hyper::{HeaderMap, Method, StatusCode, Uri};
pub use response::Response;

/// A Tachyon HTTP request, generic over its body type (defaulting to
/// [`response::Body`]). Matches `axum_core::extract::Request`.
///
/// *Tachyon extension: no `axum` equivalent.*
pub type Request<T = response::Body> = hyper::Request<T>;
