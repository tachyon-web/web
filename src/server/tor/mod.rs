//! Native Tor `.onion` services (the `tor` feature).
//!
//! Wraps [`arti-client`](https://docs.rs/arti-client) and
//! [`tor-hsservice`](https://docs.rs/tor-hsservice) so the app is published directly as a v3
//! onion service — no external `tor` daemon, no reverse proxy. Add one with
//! [`Server::onion`](crate::Server::onion); its address appears in
//! [`ServerInfo`](crate::ServerInfo) once it is reachable, which can take minutes on a first
//! bootstrap.
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use tachyon_web::Server;
//! use tachyon_web::server::tor::OnionConfig;
//!
//! # async fn run() -> Result<(), tachyon_web::Error> {
//! let app = Router::new().route("/", get(|| async { "Hello from an onion service!" }));
//! Server::new(app)
//!     .onion(OnionConfig::new("my-service").state_dir("/var/lib/tachyon/tor"))
//!     .on_ready(|endpoint| println!("reachable at {}", endpoint.url()))
//!     .serve()
//!     .await
//! # }
//! ```
//!
//! # Vanguards
//!
//! [Vanguards](https://blog.torproject.org/vanguards-onion-services/) harden onion services
//! against guard discovery and are on by default (arti's "lite" mode); see
//! [`OnionConfig::vanguards`].

mod config;
pub(crate) mod serve;

pub use config::OnionConfig;
