//! Production HTTPS with certificates issued and renewed in-process by Let's Encrypt.
//!
//! `serve_all_acme` owns the whole certificate lifecycle: it loads a cached certificate if one
//! is still valid, otherwise places an ACME order, answers the HTTP-01 challenge on the
//! cleartext listener itself, caches the result, renews 30 days before expiry, and hot-swaps
//! the new certificate into the running TLS stack without dropping connections. There is no
//! certbot, no cron job, and no reload signal.
//!
//! # What this needs before it will work
//!
//! - **Every name in `DOMAINS` must already resolve to this machine.** The CA validates by
//!   fetching a URL from the public internet; nothing else substitutes for working DNS.
//! - **Port 80 must be reachable from the internet**, not just open locally. That is where the
//!   HTTP-01 challenge is answered. Port 443 must be reachable for anyone to use the result.
//! - **Binding 80 and 443 needs privilege.** Prefer a capability or a socket-activation unit
//!   over running as root: `sudo setcap 'cap_net_bind_service=+ep' ./target/debug/examples/lets_encrypt`
//! - **`CACHE_DIR` must persist across restarts and be owner-only.** It holds the account key
//!   and the certificate's private key; the manager refuses to start if the directory is group-
//!   or world-accessible, or is not owned by the running user. Losing it means re-registering
//!   and re-issuing, which is how deployments walk into Let's Encrypt's rate limits.
//!
//! # Use staging first
//!
//! The `STAGING` flag below points at Let's Encrypt's staging environment: certificates no
//! browser will trust, but rate limits high enough to iterate against. Production limits are
//! low enough that a misconfigured retry loop can lock you out of issuance for a week. Get a
//! successful staging issuance, *then* flip the flag.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example lets_encrypt --features lets-encrypt,telemetry
//! ```
//!
//! `telemetry` is worth enabling here: without it the ACME progress and renewal events are
//! compiled out, and a failing order is silent.

use axum::{Router, routing::get};
use tachyon_web::Server;
use tachyon_web::server::SecurityPolicy;

/// Every name the certificate will cover. All of them must resolve here.
const DOMAINS: [&str; 2] = ["example.com", "www.example.com"];
/// Contact address for expiry warnings and CA policy notices.
const EMAIL: &str = "admin@example.com";
/// Account key + certificate cache. Must survive restarts and stay owner-only (`0700`).
const CACHE_DIR: &str = "/var/cache/tachyon/certs";
/// `true` = staging (untrusted certs, generous limits). Start here.
const STAGING: bool = true;

async fn index() -> &'static str {
    "hello over a real certificate\n"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/", get(index));

    let server = Server::new(app)
        // `serve_all_acme` already defaults the host allow-list to `DOMAINS`. Setting it
        // explicitly is how you serve a *narrower* set than the certificate covers — or, as
        // here, simply make the intent visible at the call site.
        .security_policy(SecurityPolicy::new().allowed_hosts(DOMAINS))
        .max_body_size(2 * 1024 * 1024)
        .max_connections(4_096)
        .max_active_requests(512)
        .max_tls_handshakes(512);

    println!(
        "requesting certificates for {DOMAINS:?} ({})",
        if STAGING { "staging" } else { "production" }
    );

    // Blocks on the HTTPS listener. The port-80 listener and the renewal loop run as spawned
    // tasks alongside it. Startup waits up to a minute for a first certificate, then binds
    // anyway — so a slow order delays early connections instead of hanging the process.
    server
        .serve_all_acme(
            "0.0.0.0:443",
            "0.0.0.0:80",
            DOMAINS.iter().map(|d| (*d).to_string()).collect(),
            EMAIL.to_string(),
            CACHE_DIR,
            STAGING,
        )
        .await?;

    Ok(())
}
