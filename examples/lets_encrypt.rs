//! Production HTTPS with certificates issued and renewed in-process by Let's Encrypt.
//!
//! The server owns the whole certificate lifecycle: it loads a cached certificate if one is
//! still valid, otherwise places an ACME order, answers the HTTP-01 challenge on the redirect
//! listener itself, caches the result, renews 30 days before expiry, and hot-swaps the new
//! certificate into the running TLS stack without dropping connections. There is no certbot,
//! no cron job, and no reload signal.
//!
//! # What this needs before it will work
//!
//! - **Every name in `DOMAINS` must already resolve to this machine.** The CA validates by
//!   fetching a URL from the public internet; nothing else substitutes for working DNS.
//! - **Port 80 must be reachable from the internet**, not just open locally. That is where the
//!   HTTP-01 challenge is answered. Port 443 must be reachable for anyone to use the result.
//! - **Binding 80 and 443 needs privilege.** Prefer a capability or a socket-activation unit
//!   over running as root: `sudo setcap 'cap_net_bind_service=+ep' ./target/debug/examples/lets_encrypt`
//! - **`STORE` must persist across restarts and be owner-only.** It holds the account key and
//!   the certificate's private key; the server refuses to start if the directory is group- or
//!   world-accessible, or is not owned by the running user. Losing it means re-registering and
//!   re-issuing, which is how deployments walk into Let's Encrypt's rate limits.
//!
//! # Use staging first
//!
//! `Acme::lets_encrypt_staging()` issues certificates no browser trusts, but with rate limits
//! high enough to iterate against. Production limits are low enough that a misconfigured retry
//! loop can lock you out of issuance for a week. Get a successful staging issuance, *then*
//! switch to `Acme::lets_encrypt()`.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example lets_encrypt --features acme
//! ```
//!
//! ACME runs in the background, so progress and failures are reported as `tracing` events —
//! install a subscriber (as below) or a failing order is silent.

use axum::{Router, routing::get};
use tachyon_web::tls::{Acme, Tls};
use tachyon_web::{Limits, Server};

/// Every name the certificate will cover. All of them must resolve here.
const DOMAINS: [&str; 2] = ["example.com", "www.example.com"];
/// Account key + certificate store. Must survive restarts and stay owner-only (`0700`).
const STORE: &str = "/var/lib/tachyon/tls";

async fn index() -> &'static str {
    "hello over a real certificate\n"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/", get(index));
    // The domains also become the host allow-list; anything else gets `421`.
    let tls = Tls::new()
        .domains(DOMAINS)
        .store(STORE)
        .acme(Acme::lets_encrypt_staging().contact("admin@example.com"));

    Server::new(app)
        .limits(
            Limits::default()
                .max_body_size(2 * 1024 * 1024)
                .max_connections(4_096)
                .max_active_requests(512)
                .max_tls_handshakes(512),
        )
        .https("0.0.0.0:443", tls)
        // Answers HTTP-01 challenges, and redirects everything else to HTTPS.
        .redirect("0.0.0.0:80")
        .serve()
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
