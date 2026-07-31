//! HTTP constructs like error types and response helpers.

pub mod error;
pub mod response;

// Re-export standard HTTP types for convenience so users don't need to depend on `hyper` or `http` directly.
pub use hyper::header;
pub use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
