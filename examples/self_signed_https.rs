//! HTTPS from generated certificates, with a plaintext listener that redirects to it — the
//! local-development counterpart to `lets_encrypt.rs`.
//!
//! Two self-signed certificates share the endpoint: ECDSA P-256 for ordinary clients, and
//! ML-DSA-65 for clients that offer ML-DSA. Uses unprivileged ports so it runs without root;
//! with `--features http3`, HTTP/3 is served on the same port over UDP.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example self_signed_https --features tls
//! cargo run --example self_signed_https --features tls,http3
//! ```
//!
//! Then:
//!
//! ```sh
//! # `-k` because no CA vouches for these certificates.
//! curl -ksSD- https://localhost:8443/
//!
//! # TLS 1.3 only by default: a client pinned to 1.2 is refused.
//! curl -ksS --tls-max 1.2 https://localhost:8443/ # TLS connect error, as intended
//!
//! # The cleartext port redirects rather than serving anything.
//! curl -sSD- -o /dev/null http://localhost:8080/some/path
//!
//! # Both fingerprints, and which endpoints serve them.
//! curl -ksS https://localhost:8443/certs
//! ```
//!
//! A `cnsa` build has neither P-256 nor ML-DSA-65, so there this example only says so.

#[cfg(not(feature = "cnsa"))]
use {
    axum::{Router, routing::get},
    std::fmt::Write as _,
    tachyon_web::tls::{KeyAlgorithm, Tls, TlsPolicy},
    tachyon_web::{Limits, Server, ServerInfo},
};

#[cfg(feature = "cnsa")]
fn main() {
    eprintln!("self_signed_https uses P-256 and ML-DSA-65, which a `cnsa` build does not have");
}

#[cfg(not(feature = "cnsa"))]
async fn index() -> &'static str {
    "hello over TLS\n"
}

#[cfg(not(feature = "cnsa"))]
async fn certs(info: ServerInfo) -> String {
    let mut out = String::new();
    for cert in info.certificates() {
        let _ = writeln!(
            out,
            "{:?} {} {:?}",
            cert.algorithm,
            cert.sha256_hex(),
            cert.endpoints
        );
    }
    out
}

#[cfg(not(feature = "cnsa"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(index))
        .route("/certs", get(certs));

    // Preference order: clients that verify P-256 (all of them) get it; only a client that
    // offers ML-DSA and not P-256 gets the ML-DSA certificate. Put ML-DSA first to prefer it
    // for every client that offers it. Add `.store(dir)` to keep the keys across restarts.
    let tls = Tls::new()
        .domains(["localhost", "127.0.0.1"])
        .self_signed(KeyAlgorithm::EcdsaP256)
        .self_signed(KeyAlgorithm::MlDsa65);

    Server::new(app)
        // Shared by every TLS endpoint the server runs. The default already negotiates TLS 1.3
        // only; `disable_resumption` also refuses 0-RTT and session tickets: a full handshake
        // per reconnect, but no replay surface and no cross-connection linkability.
        .tls_policy(TlsPolicy::new().disable_resumption(true))
        // Caps handshakes in flight: each is asymmetric crypto a peer can make us do before
        // it has proven anything, so this bounds a handshake flood.
        .limits(Limits::default().max_tls_handshakes(256))
        .https("127.0.0.1:8443", tls)
        .redirect("127.0.0.1:8080")
        .serve()
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
