//! Response compression provided directly by `tower-http`.
//!
//! Apply [`CompressionLayer`] with [`crate::Router::layer`]. Because every Tachyon transport
//! dispatches through the router, the same layer covers HTTP/1.1, HTTP/2, HTTP/3, Tor, and I2P.

#[cfg(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
))]
pub use tower_http::compression::predicate;
#[cfg(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
))]
pub use tower_http::compression::{Compression, CompressionBody, CompressionLayer, ResponseFuture};
