//! Native Tor `.onion` hidden-service support (see the `tor` feature).
//!
//! Wraps [`arti-client`](https://docs.rs/arti-client) and
//! [`tor-hsservice`](https://docs.rs/tor-hsservice) so a [`Server`](crate::server::Server) is
//! published directly as a v3 hidden service — no external `tor` daemon, no reverse proxy.
//!
//! - [`Server::serve_tor`](crate::server::Server::serve_tor) /
//!   [`serve_tor_with_client`](crate::server::Server::serve_tor_with_client): plaintext HTTP on
//!   virtual port 80, nothing to configure.
//! - [`Server::serve_onion`](crate::server::Server::serve_onion) /
//!   [`serve_onion_with_client`](crate::server::Server::serve_onion_with_client), driven by an
//!   [`OnionConfig`]: state/cache directories, vanguards, and an `on_ready` hook. With `tls`,
//!   also HTTPS on virtual port 443 from a caller-supplied `rustls::ServerConfig` (the same type
//!   `Server::serve_https_config` takes); with `cert-gen`, a self-signed certificate by default.
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use tachyon_web::Server;
//!
//! async fn hello() -> &'static str { "Hello from an onion service!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     // Publishes the service, prints its `.onion` address once reachable, then
//!     // blocks serving requests arriving over Tor rendezvous circuits.
//!     Server::new(app).serve_tor("my-hidden-service").await?;
//!     Ok(())
//! }
//! ```
//!
//! # HTTPS, custom directories, and vanguards
//!
//! Needs `tls`, and `cert-gen` for the default self-signed certificate.
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use tachyon_web::Server;
//! use tachyon_web::server::tor::OnionConfig;
//!
//! async fn hello() -> &'static str { "Hello, secure onion world!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     let config = OnionConfig::new("my-hidden-service")
//!         .state_dir("/var/lib/tachyon/tor/state")
//!         .cache_dir("/var/lib/tachyon/tor/cache")
//!         // Default (with `cert-gen` enabled) is a self-signed cert for the onion address;
//!         // pass your own instead:
//!         // .tls_config(my_rustls_server_config)
//!         .redirect_http(false) // dual-stack by default: plaintext AND TLS both work
//!         .on_ready(|addr| println!("reachable at https://{addr}"));
//!
//!     Server::new(app).serve_onion(config).await?;
//!     Ok(())
//! }
//! ```
//!
//! Onion keys and Arti's state live in Arti's default directories unless overridden with
//! [`OnionConfig::state_dir`]/[`OnionConfig::cache_dir`]; the same `nickname` and directories
//! keep the same `.onion` address across restarts. Use the `*_with_client` variants to reuse
//! one bootstrapped client (e.g. with custom bridges) across services.
//!
//! # Vanguards
//!
//! [Vanguards](https://blog.torproject.org/vanguards-onion-services/) harden onion services
//! against guard discovery and are on by default (arti's "lite" mode); see
//! [`OnionConfig::vanguards`].

mod config;
mod serve;

pub use config::OnionConfig;
