//! Single aggregated integration-test binary.
//!
//! Every suite here used to be its own `tests/*.rs` file, which cargo compiles and *links*
//! as an independent binary. With TLS/QUIC/Tor/I2P features enabled, several of those suites
//! statically link heavy crypto and native (`libi2pd`) code — paying that link cost once per
//! file rather than once total made full-feature test builds far more CPU/RAM-hungry than the
//! tests themselves warrant. Folding them into modules of one binary keeps per-suite file
//! boundaries (and each suite's own `#![allow(...)]` lints) while cargo links the heavy
//! dependencies exactly once.
//!
//! Per-suite feature gates mirror what each file previously declared with
//! `#![cfg(feature = "...")]`.

#[cfg(feature = "cookies")]
mod advanced_tests;
mod e2e_tests;
mod integration_tests;
mod server_tests;
mod static_dir_tests;

#[cfg(feature = "lets-encrypt")]
mod acme_tests;
#[cfg(feature = "i2p")]
mod i2p_tests;
#[cfg(all(feature = "tls", feature = "http3"))]
mod tls_h3_tests;
#[cfg(feature = "tor")]
mod tor_tests;
#[cfg(feature = "tower")]
mod tower_tests;
#[cfg(feature = "ws")]
mod ws_tests;
