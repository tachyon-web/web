//! Native Tor `.onion` hidden-service support (see the `tor` feature).
//!
//! Wraps [`arti-client`](https://docs.rs/arti-client) and
//! [`tor-hsservice`](https://docs.rs/tor-hsservice) so a Tachyon [`Server`](crate::server::Server)
//! can be published directly as a v3 Tor hidden service — no external `tor` daemon, no reverse
//! proxy — with the same `serve_*` ergonomics as
//! [`Server::serve_https`](crate::server::Server::serve_https).
//!
//! Two entry points are available:
//!
//! - [`Server::serve_tor`](crate::server::Server::serve_tor) /
//!   [`Server::serve_tor_with_client`](crate::server::Server::serve_tor_with_client) — the
//!   simplest possible onion service: plaintext HTTP on virtual port 80, nothing else
//!   configurable. Always available under the `tor` feature alone — no TLS stack required.
//! - [`Server::serve_onion`](crate::server::Server::serve_onion) /
//!   [`Server::serve_onion_with_client`](crate::server::Server::serve_onion_with_client), driven
//!   by an [`OnionConfig`] — adds custom state/cache directories, a vanguards toggle, and an
//!   `on_ready` hook for reading the published `.onion` address, all available under `tor`
//!   alone. Native HTTPS (virtual port 443, terminated with the *same* `rustls::ServerConfig`
//!   type used by
//!   [`Server::serve_https_config`](crate::server::Server::serve_https_config), so a
//!   FIPS-constrained crypto provider or custom cert chain can be shared between the clearnet
//!   and onion listeners) is additionally available when the `tls` feature is enabled alongside
//!   `tor` — the self-signed-certificate convenience ([`OnionConfig::self_signed_tls`], the
//!   default whenever it's available) further requires `cert-gen`.
//!
//! This module is split into `config` (the [`OnionConfig`] builder) and `serve` (the
//! `Server::serve_*` entry points and per-stream dispatch) — see `super::anon_tls` for the
//! TLS-mode plumbing this shares with [`i2p`](crate::server::i2p).
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
//! HTTPS support (this example) requires enabling `tls` (and `cert-gen` for the self-signed
//! certificate shown here) alongside `tor` — see the [module docs](self) above.
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
//!         .on_ready(|addr| tracing::info!("reachable at https://{addr}"));
//!
//!     Server::new(app).serve_onion(config).await?;
//!     Ok(())
//! }
//! ```
//!
//! Persistent onion service keys and Arti's own state/cache are stored under Arti's default
//! state directory unless overridden via [`OnionConfig::state_dir`]/[`OnionConfig::cache_dir`];
//! reusing the same `nickname` (and directories) across restarts keeps the same `.onion`
//! address. Pass an already-bootstrapped client (e.g. one configured with custom bridges) via
//! [`Server::serve_onion_with_client`](crate::server::Server::serve_onion_with_client)/
//! [`Server::serve_tor_with_client`](crate::server::Server::serve_tor_with_client) instead of
//! bootstrapping a fresh one per service.
//!
//! # Vanguards
//!
//! [Vanguards](https://blog.torproject.org/vanguards-onion-services/) harden onion services
//! against guard-discovery attacks and are enabled by default (arti's own "lite" mode).
//! [`OnionConfig::vanguards`] overrides this at runtime, e.g. `OnionConfig::new(nickname).vanguards(false)`.

mod config;
mod serve;

pub use config::OnionConfig;
