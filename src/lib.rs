//! # Tachyon-Web
//!
//! A multi-protocol web framework: HTTP/1.1, h2c, HTTP/2, HTTP/3, Tor and I2P, with
//! built-in Let's Encrypt certificate management.
//!
//! Routing, extraction, responses, middleware, and Tower integration are provided directly by
//! `axum`. Tachyon adds hardened multi-protocol serving without wrapping Axum's application API.
//!
//! ## Plain HTTP
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use axum::response::Html;
//! use tokio::net::TcpListener;
//!
//! async fn hello_world() -> Html<&'static str> {
//!     Html("<h1>Hello from Axum!</h1>")
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new()
//!         .route("/", get(hello_world));
//!
//!     let listener = TcpListener::bind("0.0.0.0:8080").await?;
//!     tachyon_web::Server::new(app).serve_http(listener).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## HTTPS with automatic Let's Encrypt certificates
//!
//! `Server::serve_all_acme` (`lets-encrypt`) issues the certificate on first startup, answers the HTTP-01
//! challenge in-process, caches account credentials and the certificate to disk, renews 30
//! days before expiry, and hot-swaps the result into the running TLS stack.
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//!
//! async fn hello() -> &'static str { "Hello, secure world!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     #[cfg(feature = "lets-encrypt")]
//!     {
//!         let app = Router::new().route("/", get(hello));
//!
//!         tachyon_web::Server::new(app)
//!             .serve_all_acme(
//!                 "0.0.0.0:443",                   // HTTPS / HTTP/2 / HTTP/3
//!                 "0.0.0.0:80",                    // HTTP redirect + ACME challenges
//!                 vec!["example.com".to_string()], // domains (must resolve to this server)
//!                 "admin@example.com".to_string(), // Let's Encrypt contact email
//!                 "/var/cache/tachyon/certs",      // persistent cert cache (survives restarts)
//!                 false,                           // false = production LE, true = staging
//!             )
//!             .await?;
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## HTTPS with a pre-loaded certificate (self-signed or CA-issued)
//!
//! For development or when you manage certificates externally:
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//!
//! async fn hello() -> &'static str { "secure hello" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     #[cfg(feature = "cert-gen")]
//!     {
//!         use tachyon_web::tls;
//!
//!         let app = Router::new().route("/", get(hello));
//!
//!         let cert = tls::generate_self_signed_cert(vec!["localhost".to_string()])?;
//!
//!         tachyon_web::Server::new(app)
//!             .start_all(
//!                 "0.0.0.0:443",
//!                 Some("0.0.0.0:80"), // optional HTTP → HTTPS redirect
//!                 cert.cert_pem,
//!                 cert.key_pem,
//!             )
//!             .await?;
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Native Tor `.onion` hidden services
//!
//! With the `tor` feature, `Server::serve_tor` publishes the app directly as a v3 Tor hidden
//! service — via [`arti-client`](https://docs.rs/arti-client)/[`tor-hsservice`](https://docs.rs/tor-hsservice) —
//! with no external `tor` daemon or reverse proxy required:
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//!
//! async fn hello() -> &'static str { "Hello from an onion service!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! #   #[cfg(feature = "tor")]
//! #   {
//!     let app = Router::new().route("/", get(hello));
//!     tachyon_web::Server::new(app).serve_tor("my-hidden-service").await?;
//! #   }
//!     Ok(())
//! }
//! ```
//!
//! ## Native I2P `.b32.i2p` eepsites
//!
//! With the `i2p` feature, `Server::serve_i2p` publishes the app directly as an I2P eepsite —
//! via the vendored, statically-linked [`libi2pd`](https://github.com/PurpleI2P/i2pd) router —
//! with no external `i2pd`/Java-I2P process required:
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//!
//! async fn hello() -> &'static str { "Hello from an eepsite!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! #   #[cfg(feature = "i2p")]
//! #   {
//!     let app = Router::new().route("/", get(hello));
//!     tachyon_web::Server::new(app).serve_i2p("my-eepsite").await?;
//! #   }
//!     Ok(())
//! }
//! ```
//!
//! Unlike every other feature, `i2p` links C++ through project-specific FFI bindings
//! ([`i2pd-sys`](https://docs.rs/i2pd-sys)/[`tachyon-i2p`](https://docs.rs/tachyon-i2p)).
//! This crate's own `#![forbid(unsafe_code)]` still holds, but says nothing about that boundary.
//! Read the `server::i2p` module docs before enabling it in anything security-sensitive.

#![forbid(unsafe_code, elided_lifetimes_in_paths)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

macro_rules! telemetry_debug {
    ($($arg:tt)*) => {{
        #[cfg(feature = "telemetry")]
        tracing::debug!($($arg)*);
        #[cfg(not(feature = "telemetry"))]
        let _ = format_args!($($arg)*);
    }};
}
#[cfg(any(feature = "lets-encrypt", feature = "tor", feature = "i2p"))]
macro_rules! telemetry_info {
    ($($arg:tt)*) => {{
        #[cfg(feature = "telemetry")]
        tracing::info!($($arg)*);
        #[cfg(not(feature = "telemetry"))]
        let _ = format_args!($($arg)*);
    }};
}
#[cfg(any(feature = "lets-encrypt", feature = "tor"))]
macro_rules! telemetry_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "telemetry")]
        tracing::warn!($($arg)*);
        #[cfg(not(feature = "telemetry"))]
        let _ = format_args!($($arg)*);
    }};
}
macro_rules! telemetry_error {
    ($($arg:tt)*) => {{
        #[cfg(feature = "telemetry")]
        tracing::error!($($arg)*);
        #[cfg(not(feature = "telemetry"))]
        let _ = format_args!($($arg)*);
    }};
}
#[cfg(any(feature = "lets-encrypt", feature = "tor", feature = "i2p"))]
pub(crate) use telemetry_info;
#[cfg(any(feature = "lets-encrypt", feature = "tor"))]
pub(crate) use telemetry_warn;
pub(crate) use {telemetry_debug, telemetry_error};

#[cfg(all(feature = "cnsa", feature = "lets-encrypt"))]
compile_error!(
    "the `cnsa` and `lets-encrypt` features are mutually exclusive: CNSA 2.0 requires an \
     ML-DSA-87 certificate, which public ACME services do not issue"
);

#[cfg(all(
    doctest,
    feature = "json",
    feature = "matched-path",
    feature = "original-uri",
    feature = "http1",
    feature = "http2",
    feature = "tower-log",
    feature = "ws",
    feature = "form",
    feature = "query",
    feature = "tls",
    feature = "cert-gen",
    feature = "http3",
    not(feature = "cnsa"),
    feature = "lets-encrypt",
    feature = "tor",
    feature = "i2p",
))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(not(any(feature = "http1", feature = "http2")))]
compile_error!(
    "tachyon-web requires at least one of the \"http1\" or \"http2\" features to serve anything"
);

pub mod server;
#[cfg(feature = "tls")]
pub mod tls;
pub use axum::*;
pub use server::{DeploymentProfile, Limits, MultiServer, Server};
#[cfg(feature = "tls")]
pub use server::{HttpsServer, RustlsConfig, bind_rustls};
