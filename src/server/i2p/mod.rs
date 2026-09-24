//! Native I2P `.b32.i2p` eepsite support (see the `i2p` feature).
//!
//! Wraps [`tachyon_i2p`] (a wrapper around the vendored `libi2pd` router) so a
//! [`Server`](crate::server::Server) is published directly as an eepsite — no external
//! `i2pd`/Java-I2P process, no SAM/BOB bridge.
//!
//! # This feature does not honor `forbid(unsafe_code)`
//!
//! This crate's own source stays `#![forbid(unsafe_code)]`, but `libi2pd` is C++ with no
//! stable C ABI. Reaching it goes through [`i2pd-sys`](https://docs.rs/i2pd-sys) (a
//! hand-written `extern "C"` shim) and [`tachyon-i2p`](https://docs.rs/tachyon-i2p), both
//! written for this project and far less scrutinized than `arti` is for `tor`. Enabling `i2p`
//! statically links `libi2pd`, Boost and AWS-LC C/C++ code into your process:
//!
//! - Memory safety here rests on this project's review of `libi2pd`'s threading/ownership
//!   contracts (documented in `i2pd-sys/shim/shim.h` and `tachyon-i2p`), not on the compiler.
//! - A memory-safety bug in `libi2pd` or the glue is a bug in *your* process; there is no
//!   process isolation as with a standalone `i2pd` daemon.
//! - Review `tachyon-i2p` yourself and treat it like any other C/C++ dependency before
//!   exposing it to hostile input.
//!
//! # Entry points
//!
//! - [`Server::serve_i2p`](crate::server::Server::serve_i2p): plaintext, persistent
//!   destination, nothing to configure.
//! - [`Server::serve_i2p_config`](crate::server::Server::serve_i2p_config) with an
//!   [`I2pConfig`]: data directory, `on_ready` hook, identity algorithms, and optional TLS
//!   (`I2pConfig::tls_config` with `tls`, `I2pConfig::self_signed_tls` with `cert-gen`).
//!
//! One destination serves one mode: I2P streaming has no virtual-port convention wired up
//! here, so unlike Tor there is no dual-stack or `redirect_http` option. Pick plaintext (the
//! default, and the common eepsite setup) or TLS up front.
//!
//! # FIPS
//!
//! Under `fips`, `i2pd-sys` links the FIPS-validated AWS-LC module too. That covers TLS
//! termination on the eepsite (checked with `assert_fips_server_config`), **not** the I2P
//! transport: every [`tachyon_i2p::CryptoType`] uses X25519, and every signature type but
//! [`tachyon_i2p::SigType::EcdsaP521`] uses a non-approved curve. See
//! [`i2pd-sys`'s README](https://docs.rs/i2pd-sys) before relying on it for compliance.
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use tachyon_web::Server;
//!
//! async fn hello() -> &'static str { "Hello from an eepsite!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     // Blocks serving requests over I2P streams.
//!     Server::new(app).serve_i2p("my-eepsite").await?;
//!     Ok(())
//! }
//! ```
//!
//! # Custom data directory and an `on_ready` hook
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use tachyon_web::Server;
//! use tachyon_web::server::i2p::I2pConfig;
//!
//! async fn hello() -> &'static str { "Hello, eepsite world!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     let config = I2pConfig::new("my-eepsite")
//!         .data_dir("/var/lib/tachyon/i2p")
//!         .on_ready(|addr| println!("reachable at http://{addr}"));
//!
//!     Server::new(app).serve_i2p_config(config).await?;
//!     Ok(())
//! }
//! ```
//!
//! Reusing the same `nickname` (and data directory) across restarts keeps the same `.b32.i2p`
//! address — the destination's keys file is created on first run and reused after that.
//!
//! # Choosing the identity's signature algorithm, and the destination's encryption capability
//!
//! [`I2pConfig::signature_type`] picks the identity's signature algorithm, used only when the
//! keys are first generated (default [`tachyon_i2p::SigType::Eddsa25519`]).
//! [`I2pConfig::crypto_type`] narrows the encryption types the `LeaseSet2` advertises, on every
//! run. By default that is `ElGamal` + ECIES-X25519, plus ML-KEM-768 hybrid on a PQ-capable
//! backend:
//!
//! ```rust,no_run
//! use tachyon_web::server::i2p::I2pConfig;
//! use tachyon_i2p::{CryptoType, SigType};
//!
//! let config = I2pConfig::new("my-eepsite")
//!     .signature_type(SigType::Eddsa25519)
//!     .crypto_type(CryptoType::EciesX25519); // classical-only, no ML-KEM component
//! ```

mod config;
mod serve;

pub use config::I2pConfig;
