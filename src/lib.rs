//! # Tachyon-Web
//!
//! A hardened server for [Axum](https://docs.rs/axum) apps. Write the app with your own
//! `axum` 0.8 dependency, then publish it over any mix of plain HTTP, HTTPS, HTTP/3, a Tor
//! `.onion` service and an I2P eepsite — with in-process Let's Encrypt, several certificates per
//! endpoint, and one set of limits, security policy and graceful shutdown shared by all of them.
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use tachyon_web::Server;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), tachyon_web::Error> {
//!     let app = Router::new().route("/", get(|| async { "hello" }));
//!     Server::new(app).http("0.0.0.0:8080").serve().await
//! }
//! ```
//!
//! Compared with `axum::serve`, every connection gets read, handshake and write-stall
//! timeouts, body and concurrency limits, Slowloris and HTTP/2 flow-control mitigations, host
//! allow-listing, and forwarding-header hygiene — identically on every transport.
//!
//! ## HTTPS, several certificates, and the metadata handlers see
//!
//! ```rust,no_run
//! # #[cfg(feature = "acme")] {
//! use axum::{Router, routing::get};
//! use tachyon_web::tls::{Acme, KeyAlgorithm, Tls};
//! use tachyon_web::{Server, ServerInfo};
//!
//! async fn pins(info: ServerInfo) -> String {
//!     info.certificates()
//!         .iter()
//!         .map(|cert| format!("{:?} {}", cert.algorithm, cert.sha256_hex()))
//!         .collect::<Vec<_>>()
//!         .join("\n")
//! }
//!
//! # async fn run() -> Result<(), tachyon_web::Error> {
//! let tls = Tls::new()
//!     .domains(["example.com"])
//!     .store("/var/lib/tachyon/tls")
//!     .acme(Acme::lets_encrypt().contact("admin@example.com"))
//!     .self_signed(KeyAlgorithm::MlDsa87);
//!
//! Server::new(Router::new().route("/pins", get(pins)))
//!     .https("0.0.0.0:443", tls)
//!     .redirect("0.0.0.0:80")
//!     .serve()
//!     .await
//! # }
//! # }
//! ```
//!
//! See the `tls` module for how one certificate is chosen per handshake, and [`ServerInfo`] for what a
//! handler can read: every endpoint (including `.onion`/`.b32.i2p` addresses) and every
//! certificate with its SHA-256 fingerprints, names, issuer and expiry.
//!
//! ## Feature flags
//!
//! | Flag | Default | Enables |
//! |---|---|---|
//! | `http1` | on | HTTP/1.1 |
//! | `http2` | on | HTTP/2 (over TLS, and h2c when allowed) |
//! | `tracing` | on | `tracing` events from the transport layer; nothing is emitted without a subscriber |
//! | `tls` | | TLS 1.3 via `rustls` + `aws-lc-rs`, and self-signed certificate generation |
//! | `tls12-legacy` | | additionally offer TLS 1.2 |
//! | `http3` | | HTTP/3 beside every HTTPS endpoint |
//! | `acme` | | in-process ACME (Let's Encrypt, or any RFC 8555 CA) issuance and renewal |
//! | `fips` | | AWS-LC's FIPS 140-3 module in approved mode, and the restricted TLS policy |
//! | `cnsa` | | the CNSA 2.0 profile: `fips`, ML-KEM-1024, ML-DSA-87 only; excludes `acme`, `tls12-legacy`, `tor` and `i2p` |
//! | `tor` | | Tor v3 onion services via `arti-client` |
//! | `i2p` | | I2P eepsites via an embedded `libi2pd` — links C++, see the `i2p` module |
//!
//! Axum's own features (`json`, `ws`, `macros`, …) are enabled on your `axum` dependency.
//! At least one of `http1`/`http2` must stay enabled.

#![forbid(unsafe_code, elided_lifetimes_in_paths)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

macro_rules! telemetry_debug {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        tracing::debug!($($arg)*);
        #[cfg(not(feature = "tracing"))]
        let _ = format_args!($($arg)*);
    }};
}
macro_rules! telemetry_info {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        tracing::info!($($arg)*);
        #[cfg(not(feature = "tracing"))]
        let _ = format_args!($($arg)*);
    }};
}
macro_rules! telemetry_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        tracing::warn!($($arg)*);
        #[cfg(not(feature = "tracing"))]
        let _ = format_args!($($arg)*);
    }};
}
macro_rules! telemetry_error {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        tracing::error!($($arg)*);
        #[cfg(not(feature = "tracing"))]
        let _ = format_args!($($arg)*);
    }};
}
pub(crate) use {telemetry_debug, telemetry_error, telemetry_info, telemetry_warn};

#[cfg(all(feature = "cnsa", feature = "acme"))]
compile_error!(
    "the `cnsa` and `acme` features are mutually exclusive: CNSA 2.0 requires an ML-DSA-87 \
     certificate, which public ACME services do not issue"
);

#[cfg(all(feature = "cnsa", feature = "tls12-legacy"))]
compile_error!(
    "the `cnsa` and `tls12-legacy` features are mutually exclusive: CNSA 2.0 is TLS 1.3 only"
);

#[cfg(all(feature = "cnsa", any(feature = "tor", feature = "i2p")))]
compile_error!(
    "the `cnsa` feature is mutually exclusive with `tor` and `i2p`: neither network's own \
     cryptography is CNSA 2.0, and a CNSA-only TLS provider cannot reach Tor relays"
);

#[cfg(not(any(feature = "http1", feature = "http2")))]
compile_error!(
    "tachyon-web requires at least one of the \"http1\" or \"http2\" features to serve anything"
);

#[cfg(all(
    doctest,
    feature = "http1",
    feature = "http2",
    feature = "acme",
    feature = "tor",
    feature = "i2p",
    not(feature = "cnsa"),
))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

mod error;
mod info;
mod server;
#[cfg(feature = "tls")]
pub mod tls;

pub use error::Error;
pub use info::{Endpoint, Network, Reachability, ServerInfo};
#[cfg(feature = "i2p")]
pub use server::i2p;
#[cfg(feature = "tor")]
pub use server::tor;
pub use server::{Bind, IpNetwork, Limits, SecurityPolicy, Serve, Server};
