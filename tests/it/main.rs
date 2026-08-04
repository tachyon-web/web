//! Single aggregated integration-test binary.
//!
//! Cargo compiles and links each `tests/*.rs` file as its own binary. With TLS/QUIC/Tor/I2P
//! enabled these suites statically link heavy crypto and native (`libi2pd`) code, so keeping
//! them as modules of one binary pays that link cost once rather than once per suite.

// Relaxations for the whole test binary.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::items_after_statements,
    clippy::use_self,
    clippy::semicolon_if_nothing_returned,
    clippy::similar_names,
    clippy::let_underscore_future,
    clippy::option_if_let_else
)]

mod common;

#[cfg(feature = "cookies")]
mod advanced_tests;
#[cfg(all(
    feature = "json",
    feature = "form",
    feature = "query",
    feature = "cookies"
))]
mod integration_tests;
mod server_tests;
#[cfg(any(
    feature = "compression-gzip",
    feature = "compression-br",
    feature = "compression-zstd",
))]
mod compression_tests;
// Its only test drives the server with an HTTP/1.1 client.
#[cfg(feature = "http1")]
mod static_dir_tests;

#[cfg(feature = "lets-encrypt")]
mod acme_tests;
#[cfg(feature = "i2p")]
mod i2p_tests;
#[cfg(all(feature = "cert-gen", feature = "http3"))]
mod tls_h3_tests;
#[cfg(feature = "tor")]
mod tor_tests;
#[cfg(feature = "tower")]
mod tower_tests;
#[cfg(feature = "ws")]
mod ws_tests;
