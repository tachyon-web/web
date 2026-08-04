//! # Tachyon-Web
//!
//! A multi-protocol web framework: HTTP/1.1, h2c, HTTP/2, HTTP/3, Tor and I2P, with
//! built-in Let's Encrypt certificate management.
//!
//! The router/extractor API mirrors `axum`, so most `axum` handlers compile unmodified.
//! The exception is Tower middleware, which Tachyon deliberately does not use; the `tower`
//! feature provides an interop layer for the cases that need it.
//!
//! ## Plain HTTP
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
//! [`Server::serve_all_acme`] issues the certificate on first startup, answers the HTTP-01
//! challenge in-process, caches account credentials and the certificate to disk, renews 30
//! days before expiry, and hot-swaps the result into the running TLS stack.
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
//! ## Response compression
//!
//! With any `compression-*` feature, [`Server::compression`] negotiates `zstd`, `br`, `gzip`
//! or `deflate` per request and applies it to every transport above at once — see
//! [`http::compression`] for what is and isn't compressed, and
//! [`Router::compression`] to scope it to one router.
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//! use tachyon_web::http::compression::Compression;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let app: Router = Router::new().route("/", get(|| async { "hello" }));
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//!
//! Server::new(app)
//!     .compression(Compression::new())
//!     .serve_http(listener)
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## `103 Early Hints`
//!
//! With the `early-hints` feature, a handler can tell the browser what to fetch *while it is
//! still working* — an informational response ahead of the real one, which the
//! `Service<Request> → Response` shape underneath every other Rust framework cannot express.
//! Reaching it means Tachyon drives HTTP/2 itself; see [`http::early_hints`] for the
//! transport matrix and the tradeoffs that come with that.
//!
//! ```rust,no_run
//! use tachyon_web::{Html, Router, Server, get};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! #   #[cfg(all(feature = "early-hints", feature = "cert-gen"))]
//! #   {
//!     use tachyon_web::http::early_hints::{EarlyHints, EarlyHintsConfig, Link};
//!
//!     async fn page(hints: EarlyHints) -> Html<&'static str> {
//!         hints.send([Link::preload("/static/app.css").as_style()]);
//!         // ... the database round trip that hint is overlapping ...
//!         Html("<h1>hello</h1>")
//!     }
//!
//!     let app = Router::new().route("/", get(page));
//!     let cert = tachyon_web::tls::generate_self_signed_cert(vec!["localhost".into()])?;
//!
//!     Server::new(app)
//!         .early_hints(EarlyHintsConfig::new())
//!         .start_all("0.0.0.0:443", None, cert.cert_pem, cert.key_pem)
//!         .await?;
//! #   }
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
//! Unlike every other feature here, `i2p` links in `unsafe` code. The
//! `#![forbid(unsafe_code)]` below still holds for this crate's own source — no feature can
//! override it — but it says nothing about the FFI boundary. `libi2pd` is C++ with no stable
//! C ABI, so the bindings ([`i2pd-sys`](https://docs.rs/i2pd-sys) /
//! [`tachyon-i2p`](https://docs.rs/tachyon-i2p)) were written for this project rather than
//! being an independently audited pure-Rust dependency the way `arti-client` is for `tor`.
//! Read [`server::i2p`] before enabling it in anything security-sensitive.

#![forbid(unsafe_code, elided_lifetimes_in_paths)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

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

pub use http::compression::{self, Compression, CompressionLevel, Encoding};
#[cfg(feature = "early-hints")]
pub use http::early_hints::{self, EarlyHints, EarlyHintsConfig, Link};
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
