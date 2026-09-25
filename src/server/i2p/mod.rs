//! Native I2P `.b32.i2p` eepsite support (see the `i2p` feature).
//!
//! Wraps [`tachyon_i2p`] (a wrapper around the vendored `libi2pd` router) so a
//! [`Server`](crate::Server) is published directly as an eepsite — no external
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
//! Add one with [`Server::i2p`](crate::Server::i2p). The eepsite's address appears in
//! [`ServerInfo`](crate::ServerInfo) as soon as its destination is created, as
//! [`Reachability::Unconfirmed`](crate::Reachability::Unconfirmed): libi2pd publishes the
//! `LeaseSet` in the background and reports no signal when peers can reach it.
//!
//! # FIPS
//!
//! Under `fips`, `i2pd-sys` links the FIPS-validated AWS-LC module too. That covers TLS
//! termination on the eepsite, **not** the I2P
//! transport: every [`tachyon_i2p::CryptoType`] uses X25519, and every signature type but
//! [`tachyon_i2p::SigType::EcdsaP521`] uses a non-approved curve. See
//! [`i2pd-sys`'s README](https://docs.rs/i2pd-sys) before relying on it for compliance.
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use tachyon_web::{Network, Server, ServerInfo};
//! use tachyon_web::server::i2p::I2pConfig;
//!
//! async fn address(info: ServerInfo) -> String {
//!     info.endpoints()
//!         .into_iter()
//!         .find(|e| e.network == Network::I2p)
//!         .map(|e| e.url())
//!         .unwrap_or_default()
//! }
//!
//! # async fn run() -> Result<(), tachyon_web::Error> {
//! let app = Router::new().route("/", get(address));
//! Server::new(app)
//!     .i2p(I2pConfig::new("my-eepsite").data_dir("/var/lib/tachyon/i2p"))
//!     .serve()
//!     .await
//! # }
//! ```
//!
//! Reusing the same `nickname` and data directory across restarts keeps the same `.b32.i2p`
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
pub(crate) mod serve;

pub use config::I2pConfig;
