//! Request-boundary hardening: host allow-listing, reverse-proxy trust, response headers, and
//! the concurrency limits that bound a denial-of-service attempt.
//!
//! Everything here is enforced *before* a request reaches the router, so it applies identically
//! to HTTP/1.1, HTTP/2, HTTP/3, `.onion` and `.i2p` traffic.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example hardened_server
//! ```
//!
//! Then exercise each control. The interesting cases are the ones that get rejected:
//!
//! ```sh
//! # Allowed host -> 200, plus the hardened response headers.
//! curl -sSD- http://127.0.0.1:8080/ -H 'Host: localhost:8080'
//!
//! # Unknown host -> 421 Misdirected Request. This is what closes DNS rebinding and
//! # Host-header confusion against a server reachable under more than one name.
//! curl -sSD- -o /dev/null http://127.0.0.1:8080/ -H 'Host: evil.example'
//!
//! # Spoofed forwarding header from an untrusted peer -> stripped before any handler sees it,
//! # so application code cannot mistake it for a real client address.
//! curl -sS http://127.0.0.1:8080/whoami -H 'Host: localhost:8080' -H 'X-Forwarded-For: 1.2.3.4'
//!
//! # CONNECT -> 405. An app server is not a forward proxy.
//! curl -sSD- -o /dev/null -X CONNECT http://127.0.0.1:8080/ -H 'Host: localhost:8080'
//!
//! # Over the body limit -> 413, refused without buffering the excess.
//! head -c 200000 /dev/zero | curl -sSD- -o /dev/null --data-binary @- http://127.0.0.1:8080/echo -H 'Host: localhost:8080'
//! ```

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::Serialize;
use std::net::SocketAddr;
use tachyon_web::Server;
use tachyon_web::server::{DeploymentProfile, IpNetwork, SecurityPolicy};

/// The forwarding headers this deployment would honor, and what actually survived to the
/// handler. Anything a peer outside `trusted_proxies` sends is gone by the time this runs.
const FORWARDING_HEADERS: [&str; 4] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
];

#[derive(Serialize)]
struct WhoAmI {
    /// The transport-level peer. Behind a proxy this is the proxy, not the end client — which
    /// is exactly why forwarding headers exist and why they must be trusted selectively.
    peer: String,
    /// Forwarding headers that reached the handler. Empty unless `peer` is a trusted proxy.
    forwarded: Vec<String>,
}

async fn index() -> &'static str {
    "hardened. try the curl commands in this example's header comment.\n"
}

async fn whoami(ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Json<WhoAmI> {
    let forwarded = FORWARDING_HEADERS
        .iter()
        .filter_map(|name| {
            let value = headers.get(*name)?.to_str().ok()?;
            Some(format!("{name}: {value}"))
        })
        .collect();
    Json(WhoAmI {
        peer: peer.to_string(),
        forwarded,
    })
}

async fn echo(body: String) -> String {
    format!("received {} bytes\n", body.len())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", get(index))
        .route("/whoami", get(whoami))
        .route("/echo", post(echo));

    // Only these names are served. An empty list would reject *every* authority; not calling
    // `allowed_hosts` at all is what disables the check, so the fail-safe direction is to
    // configure it explicitly rather than to leave it out.
    let security = SecurityPolicy::new()
        .allowed_hosts(["localhost", "127.0.0.1", "example.test"])
        // Forwarding headers are believed only from these networks. Everything else has them
        // stripped, so a direct-to-origin request cannot forge a client IP. With no trusted
        // proxies configured (the default) nothing is believed — the right default for a
        // server that might be exposed directly.
        .trusted_proxies([
            "10.0.0.0/8".parse::<IpNetwork>()?,
            IpNetwork::new(std::net::IpAddr::from([192, 168, 0, 0]), 16)?,
        ])
        // All three are already the default; spelled out so this example documents them.
        .strip_untrusted_forwarding_headers(true)
        .allow_connect(false)
        // `nosniff`, `no-referrer`, `no-store` on errors, HSTS on secure transports, and
        // `Server` removed. Application-set values always win — hardening never overwrites a
        // header a handler chose. `Permissions-Policy` and `Content-Security-Policy` are
        // deliberately left alone: the right value depends on what your pages actually do,
        // so they belong in your own middleware rather than in a transport-layer default.
        .harden_responses(true)
        // h2c is plaintext HTTP/2 with no ALPN. Browsers never speak it, so leaving it off
        // costs nothing and removes a protocol-confusion surface from a public listener.
        // Turn it on only when a load balancer in front of you terminates TLS and speaks h2c.
        .allow_h2c(false);

    let server = Server::new(app)
        .security_policy(security)
        // Bounds on what a hostile peer can consume. These are shared across every transport a
        // `Server` runs, so adding listeners does not multiply the ceiling.
        .max_body_size(64 * 1024)
        .max_connections(1_024)
        // Excess requests are shed with 503 immediately rather than queued — a queue under
        // overload just converts a throughput problem into a latency and memory problem.
        .max_active_requests(256)
        // Coherent preset applied last so it cannot be silently undone by a later builder call.
        // `ExtremePrivacy` additionally disables TLS session resumption and tightens the
        // anonymity-transport limits; `Hardened` is the default.
        .deployment_profile(DeploymentProfile::Hardened);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("listening on http://{addr}");
    println!(
        "limits: {} connections, {} concurrent handlers, {} byte bodies",
        server.connection_limit(),
        server.active_request_limit(),
        64 * 1024,
    );

    server.serve_http(listener).await?;
    Ok(())
}
