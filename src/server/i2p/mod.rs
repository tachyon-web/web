//! Native I2P `.b32.i2p` eepsite support (see the `i2p` feature).
//!
//! Wraps [`tachyon_i2p`] (itself a safe wrapper around the vendored `libi2pd` router, see that
//! crate's docs) so a Tachyon [`Server`](crate::server::Server) can be published directly as an
//! I2P eepsite — no external `i2pd`/Java-I2P process, no SAM/BOB bridge — with the same
//! `serve_*` ergonomics as [`Server::serve_tor`](crate::server::Server::serve_tor).
//!
//! # This feature does not honor `tachyon-web`'s `forbid(unsafe_code)` guarantee
//!
//! `tachyon-web` itself has `#![forbid(unsafe_code)]` at its crate root, same as always. But
//! `libi2pd` is a C++ library with no stable C ABI, so reaching it at all requires an FFI
//! boundary — that boundary is [`i2pd-sys`](https://docs.rs/i2pd-sys) (a hand-written `extern
//! "C"` shim over `libi2pd`, vendored from [PurpleI2P/i2pd](https://github.com/PurpleI2P/i2pd))
//! and [`tachyon-i2p`](https://docs.rs/tachyon-i2p) (the safe wrapper crate built on top of it),
//! both **written for this project**, not a long-established, independently-audited pure-Rust
//! dependency the way `arti-client`/`tor-hsservice` are for the `tor` feature. Enabling `i2p`
//! pulls that FFI layer — and the statically-linked `libi2pd`/Boost/AWS-LC C/C++ code it
//! compiles from vendored source — into your binary.
//!
//! Concretely, this means:
//! - Memory safety for everything reachable through this feature rests on this project's own
//!   review of `libi2pd`'s threading/ownership contracts (documented inline in
//!   `i2pd-sys/shim/shim.h` and `tachyon-i2p`'s source), not on the Rust compiler.
//! - A memory-safety bug in `libi2pd` itself, or in the shim/wrapper glue, is a bug in *your*
//!   process — there is no separate-process/SAM-bridge isolation boundary the way there would
//!   be running a standalone `i2pd` daemon.
//! - This is meaningfully newer and less battle-tested than the `tor` feature. Treat it
//!   accordingly for anything security-sensitive: review `tachyon-i2p`'s source yourself, keep
//!   the crate updated, and don't expose it to hostile input without the same caution you'd
//!   apply to any other C/C++ dependency compiled into your binary.
//!
//! None of this is a knock on `libi2pd` itself (it's the reference I2P router implementation and
//! plenty battle-tested on its own), but *this specific FFI boundary* is new, project-specific
//! code, not something with years of independent scrutiny the way `arti`'s pure-Rust stack has.
//!
//! # Two entry points
//!
//! - [`Server::serve_i2p`](crate::server::Server::serve_i2p) — the simplest possible eepsite: a
//!   persistent destination (keys stored under a data directory, so the address survives
//!   restarts), plaintext only.
//! - [`Server::serve_i2p_config`](crate::server::Server::serve_i2p_config), driven by an
//!   [`I2pConfig`] — adds an `on_ready` hook and a custom keys-file location, always available
//!   under the `i2p` feature alone. Optional TLS ([`I2pConfig::tls_config`], and
//!   [`I2pConfig::self_signed_tls`] specifically) additionally requires enabling `tls` (and
//!   `cert-gen` for the self-signed convenience) alongside `i2p` — see the [module docs](self)
//!   below and the `i2p` feature's own docs in `Cargo.toml`.
//!
//! This module is split into `config` (the [`I2pConfig`] builder) and `serve` (the
//! `Server::serve_*` entry points and per-stream dispatch) — see `super::anon_tls` for the
//! TLS-mode plumbing this shares with [`tor`](crate::server::tor).
//!
//! # Crypto backend: `aws-lc` (default) vs FIPS
//!
//! `i2pd-sys` (via `tachyon-i2p`) links one of two crypto backends: regular AWS-LC (the default,
//! selected here by the `i2p` feature) or the FIPS 140-3-validated AWS-LC-FIPS module. There's no
//! separate `i2p-fips` feature — this crate's single top-level `fips` feature reaches into
//! `tachyon-i2p/fips` too (taking priority over `i2p`'s `aws-lc` pick, harmlessly — see
//! `i2pd-sys`'s crate docs for why), so enabling `i2p` and `fips` together links the
//! FIPS-validated module for both the optional TLS layer
//! ([`I2pConfig::tls_config`]/[`I2pConfig::self_signed_tls`], enforced via
//! `assert_fips_server_config`) and the I2P transport crypto `i2pd-sys` performs internally.
//!
//! **This does not make the I2P transport itself FIPS-140-3-compliant** — only the module
//! computing its primitives. Every destination signature type
//! ([`tachyon_i2p::SigType::Eddsa25519`] by default) that isn't
//! [`tachyon_i2p::SigType::EcdsaP521`] uses a non-approved curve, and every
//! [`tachyon_i2p::CryptoType`] variant is an `Ecies*X25519` scheme —
//! ECIES-X25519-AEAD-Ratchet mandates X25519 key agreement, which (like Tor's `ntor`/`ntor-v3`
//! handshakes) isn't an approved key-establishment technique regardless of which library
//! computes it. Under `fips`, treat only TLS termination on the eepsite's virtual TLS port as
//! being in the FIPS boundary; the I2P transport underneath is out of scope by protocol
//! design. See [`i2pd-sys`'s README](https://docs.rs/i2pd-sys) ("FIPS" section) for what
//! linking the validated module does and does not get you before reaching for it to satisfy a
//! compliance requirement.
//!
//! # Why there's no `redirect_http`/dual-stack option like `tor`'s `OnionConfig`
//!
//! A Tor onion service multiplexes plaintext (virtual port 80) and TLS (virtual port 443) over
//! the *same* `.onion` address, because Tor's rendezvous protocol carries a virtual port per
//! stream. I2P's streaming protocol has no equivalent convention actually wired up here — one
//! [`Destination`](tachyon_i2p::Destination) is one address serving *one* mode. Pick plaintext
//! (the default, and by far the more common real-world eepsite setup) or TLS
//! ([`I2pConfig::tls_config`]) up front; there's no in-band redirect between them the way there
//! is for Tor.
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
//!     // Publishes the service, prints its `.b32.i2p` address as soon as the destination is
//!     // created (not necessarily reachable on the network yet), then blocks serving requests
//!     // arriving over I2P streams.
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
//!         .on_ready(|addr| tracing::info!("reachable at http://{addr}"));
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
//! [`I2pConfig::signature_type`] controls the identity's signature algorithm, used **the first
//! time** a destination's keys are generated (irrelevant once a keys file already exists — an
//! existing destination keeps whatever it was originally created with); it defaults to
//! [`tachyon_i2p::SigType::Eddsa25519`], the I2P network's own current default.
//!
//! [`I2pConfig::crypto_type`] is different: it controls which encryption algorithm(s) the
//! destination's `LeaseSet2` *advertises*, and applies on every run, not just first-time
//! generation (the identity's own certificate is always plain `ElGamal` regardless — that's a
//! hard requirement of real I2P clients, not something this crate exposes a choice over). Not
//! calling it at all (the default) already publishes a hybrid `ElGamal` + ECIES-X25519 set, plus
//! the post-quantum `ML-KEM-768` hybrid variant too if this was built against a
//! post-quantum-capable crypto backend — maximizing both reachability and, when available,
//! "harvest now, decrypt later" resistance, with no explicit opt-in needed. Call it only to
//! *narrow* that down to one specific algorithm, e.g. for a smaller `LeaseSet2` or to deliberately
//! exclude the post-quantum component:
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
