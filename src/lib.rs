//! # Tachyon-Web
//!
//! A clean, highly optimized, multi-protocol web framework for Rust.
//!
//! `tachyon-web` follows the philosophy of an **Axum-compatible API**, but takes a simpler,
//! more unified approach to high-performance transport protocols. Where other frameworks require
//! complex configurations and separate crates to handle modern protocols, `tachyon-web` provides
//! a seamless, unified experience out-of-the-box for **HTTP/1.1, HTTP/2, and HTTP/3**, as well
//! as **automatic Let's Encrypt TLS certificate management**.
//!
//! ## Design philosophy
//!
//! 1. **Axum-like simplicity**: Build a `Router`, chain `.route()` calls, and use type-safe
//!    extractors (`Path`, `Query`, `Json`, `State`) in handler functions — the same ergonomic
//!    patterns you already know.
//!
//! 2. **Drop-in replacement for Axum workloads**: Most `axum` handlers compile against
//!    `tachyon-web` without modification. The main incompatibility is Tower middleware layers,
//!    which Tachyon does not use — by design, to eliminate the overhead Tower introduces.
//!
//! 3. **Effortless TLS, HTTP/2, and HTTP/3**: Starting a TLS server is a single call.
//!    Let's Encrypt integration is built-in — no CLI tools, no shell scripts, no cron jobs.
//!    Certificates are automatically issued, cached to disk, and hot-reloaded on renewal.
//!
//! 4. **High Performance**: Built natively on `hyper` and `s2n-quic`, `tachyon-web` prioritizes
//!    minimal allocations, lock-free hot paths, and direct socket handling.
//!
//! ## Quick start: Plain HTTP
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//! use tachyon_web::http::response::Html;
//! use tokio::net::TcpListener;
//!
//! async fn hello_world() -> Html<&'static str> {
//!     Html("<h1>Hello from Tachyon-Web!</h1>")
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new()
//!         .route("/", get(hello_world));
//!
//!     let listener = TcpListener::bind("0.0.0.0:8080").await?;
//!     Server::new(app).serve_http(listener).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## HTTPS with automatic Let's Encrypt certificates
//!
//! Call [`Server::serve_all_acme`] to get fully automatic certificate management:
//! - Issues a certificate from Let's Encrypt on first startup.
//! - Serves ACME HTTP-01 challenges in-process (no separate server or Certbot required).
//! - Saves credentials and the certificate to disk — safe across restarts.
//! - Renews automatically 30 days before expiry with exponential-backoff retries.
//! - Hot-swaps the certificate in the TLS stack with **zero downtime**.
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//!
//! async fn hello() -> &'static str { "Hello, secure world!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     #[cfg(feature = "lets-encrypt")]
//!     {
//!         let app = Router::new().route("/", get(hello));
//!
//!         Server::new(app)
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
//! use tachyon_web::{Router, Server, get};
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
//!         // Generate an ephemeral self-signed cert (for development only).
//!         let cert = tls::generate_self_signed_cert(vec!["localhost".to_string()])?;
//!
//!         Server::new(app)
//!             .start_all(
//!                 "0.0.0.0:443",
//!                 Some("0.0.0.0:80"),  // optional HTTP → HTTPS redirect
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
//! With the `tor` feature, [`Server::serve_tor`] publishes the app directly as a v3 Tor hidden
//! service — via [`arti-client`](https://docs.rs/arti-client)/[`tor-hsservice`](https://docs.rs/tor-hsservice) —
//! with no external `tor` daemon or reverse proxy required:
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//!
//! async fn hello() -> &'static str { "Hello from an onion service!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     #[cfg(feature = "tor")]
//!     {
//!         let app = Router::new().route("/", get(hello));
//!         Server::new(app).serve_tor("my-hidden-service").await?;
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Native I2P `.b32.i2p` eepsites
//!
//! With the `i2p` feature, [`Server::serve_i2p`] publishes the app directly as an I2P eepsite —
//! via the vendored, statically-linked [`libi2pd`](https://github.com/PurpleI2P/i2pd) router —
//! with no external `i2pd`/Java-I2P process required:
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//!
//! async fn hello() -> &'static str { "Hello from an eepsite!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     #[cfg(feature = "i2p")]
//!     {
//!         let app = Router::new().route("/", get(hello));
//!         Server::new(app).serve_i2p("my-eepsite").await?;
//!     }
//!     Ok(())
//! }
//! ```
//!
//! **⚠️ Unlike every other feature in this crate, `i2p` pulls in a dependency that itself
//! contains `unsafe` code — the `#![forbid(unsafe_code)]` below still holds for
//! `tachyon-web`'s own source (it cannot be locally overridden by any feature), but it says
//! nothing about the FFI boundary this feature links in.** `libi2pd` is a C++ library with no
//! stable C ABI, so supporting it at all requires an `unsafe` FFI boundary — one written for
//! this project ([`i2pd-sys`](https://docs.rs/i2pd-sys)/[`tachyon-i2p`](https://docs.rs/tachyon-i2p)),
//! not a long-established independently-audited pure-Rust dependency the way `arti-client` is
//! for `tor`. See [`server::i2p`] for the full disclosure before enabling this in anything
//! security-sensitive.

#![forbid(unsafe_code, elided_lifetimes_in_paths)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

#[cfg(not(any(feature = "http1", feature = "http2")))]
compile_error!(
    "tachyon-web requires at least one of the \"http1\" or \"http2\" features to serve anything"
);

pub mod http;
pub mod routing;
pub mod server;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "ws")]
pub mod ws;

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use http::error::{Error, Result};
pub use http::response;
pub use http::response::{
    AppendHeaders, Html, IntoResponse, IntoResponseParts, Redirect, ResponseParts,
};
pub use routing::extract;
#[cfg(feature = "cookies")]
pub use routing::extract::Cookies;
#[cfg(feature = "form")]
pub use routing::extract::Form;
#[cfg(feature = "json")]
pub use routing::extract::Json;
#[cfg(feature = "original-uri")]
pub use routing::extract::OriginalUri;
#[cfg(feature = "query")]
pub use routing::extract::Query;
pub use routing::extract::{
    ConnectInfo, Extension, FromRef, FromRequest, FromRequestParts, Host, Path, RawQuery, State,
};
pub use routing::handler::{BoxedFuture, BoxedHandler, Handler};
pub use routing::middleware::{MiddlewarePosition, Next};
pub use routing::static_dir::ServeDir;
pub use routing::{
    MethodRouter, Router, RouterError, any, connect, delete, get, head, options, patch, post, put,
    trace,
};
#[cfg(feature = "tls")]
pub use server::{HttpsServer, RustlsConfig, bind_rustls};
pub use server::{MultiServer, Server, serve};
