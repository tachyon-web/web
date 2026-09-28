//! One clearnet endpoint, three certificates — and a page that shows visitors exactly what
//! they can pin.
//!
//! - **Let's Encrypt ECDSA P-256**: what every browser is served, because it is first.
//! - **Self-signed ML-DSA-87**: served to clients that offer ML-DSA but not P-256; no browser
//!   offers ML-DSA yet.
//! - **Self-signed ECDSA P-521**: a pinning client that offers *only*
//!   `ecdsa_secp521r1_sha512` receives it and verifies it against its pin instead of a CA.
//!
//! The store keeps the self-signed keys across restarts, so their fingerprints — rendered at
//! `/.well-known/pins` — stay valid for pins and attestation reports.
//!
//! Needs everything `lets_encrypt.rs` does (public DNS, port 80 reachable), and like it orders
//! from Let's Encrypt staging: switch to `Acme::lets_encrypt()` for a browser-trusted
//! certificate. Run with:
//!
//! ```sh
//! cargo run --example multi_cert --features acme
//!
//! # Browser path: the Let's Encrypt certificate.
//! curl -sS https://example.com/.well-known/pins
//!
//! # Pinning path: offer only P-521 and check the fingerprint against the one published.
//! openssl s_client -connect example.com:443 -servername example.com \
//!     -sigalgs ecdsa_secp521r1_sha512 </dev/null 2>/dev/null \
//!   | openssl x509 -outform der | sha256sum
//! ```

use std::fmt::Write as _;

use axum::{Router, routing::get};
use tachyon_web::tls::{Acme, KeyAlgorithm, Tls};
use tachyon_web::{Server, ServerInfo};

const DOMAIN: &str = "example.com";

async fn pins(info: ServerInfo) -> String {
    let mut out = String::new();
    for cert in info.certificates() {
        let _ = writeln!(
            out,
            "{:?} issued by {:?} for {:?}\n  sha256 {}\n  expires {:?}",
            cert.algorithm,
            cert.issuer,
            cert.names,
            cert.sha256_hex(),
            cert.not_after,
        );
    }
    for endpoint in info.endpoints() {
        let _ = writeln!(out, "reachable at {}", endpoint.url());
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let tls = Tls::new()
        .domains([DOMAIN])
        .store("/var/lib/tachyon/tls")
        .acme(Acme::lets_encrypt_staging().contact("admin@example.com"))
        .self_signed(KeyAlgorithm::MlDsa87)
        .self_signed(KeyAlgorithm::EcdsaP521);

    Server::new(Router::new().route("/.well-known/pins", get(pins)))
        .https("0.0.0.0:443", tls)
        .redirect("0.0.0.0:80")
        .serve()
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
