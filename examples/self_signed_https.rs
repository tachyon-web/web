//! HTTPS from a generated certificate, with a plaintext listener that redirects to it — the
//! local-development counterpart to `lets_encrypt.rs`, which does the same thing with a real CA.
//!
//! Uses unprivileged ports so it runs without root. `start_all` serves HTTPS on the TLS
//! address, adds HTTP/3 on the same address when built with `--features http3`, and runs the
//! cleartext address as a `308` redirector.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example self_signed_https --features cert-gen
//!
//! # ...and with HTTP/3 on the same port over UDP:
//! cargo run --example self_signed_https --features cert-gen,http3
//! ```
//!
//! Then:
//!
//! ```sh
//! # `-k` because the certificate is self-signed and no CA vouches for it.
//! curl -ksSD- https://localhost:8443/
//!
//! # Negotiates TLS 1.3 — and, by default, *only* TLS 1.3. A client pinned to 1.2 is refused
//! # with a `protocol_version` alert. Build with `--features tls12-legacy` to allow a fallback.
//! curl -ksS --tls-max 1.2 https://localhost:8443/ # TLS connect error, as intended
//!
//! # The cleartext port redirects rather than serving anything.
//! curl -sSD- -o /dev/null http://localhost:8080/some/path
//!
//! # HTTP/3, when built with the `http3` feature.
//! curl -ksS --http3-only https://localhost:8443/
//! ```

use axum::{Router, routing::get};
use tachyon_web::Server;
use tachyon_web::server::SecurityPolicy;
use tachyon_web::tls::{self, TlsPolicy};

async fn index() -> &'static str {
    "hello over TLS\n"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/", get(index));

    // In a `cnsa` build this is an ML-DSA-87 key instead of ECDSA P-384, with no parameter to
    // downgrade it. The SANs here become the default host allow-list below.
    let cert =
        tls::generate_self_signed_cert(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;

    let server = Server::new(app)
        // Shared by every listener this server runs — clearnet HTTPS here, and equally the
        // `.onion`/`.i2p` TLS layers if those were added. The default already negotiates TLS
        // 1.3 only; `disable_resumption` additionally refuses 0-RTT, session tickets and the
        // stateful cache, which costs a reconnect a full handshake but removes the replay
        // surface and a cross-connection linkability signal.
        .tls_policy(TlsPolicy::new().disable_resumption(true))
        // `start_all` seeds the allow-list from the certificate's SANs when a policy does not
        // set one, so this is belt-and-braces — but stating it means the server keeps failing
        // closed if the certificate is later reissued with wider SANs.
        .security_policy(SecurityPolicy::new().allowed_hosts(["localhost", "127.0.0.1"]))
        .max_body_size(1024 * 1024)
        // Caps handshakes in flight. Each one is asymmetric crypto the peer can make us do
        // before it has proven anything, so this is the knob that bounds a handshake flood.
        .max_tls_handshakes(256);

    println!("https://localhost:8443  (self-signed; curl needs -k)");
    println!("http://localhost:8080   (308 redirect to https)");
    if cfg!(feature = "http3") {
        println!("h3 on udp/8443");
    }

    server
        .start_all(
            "127.0.0.1:8443",
            Some("127.0.0.1:8080"),
            cert.cert_pem,
            cert.key_pem,
        )
        .await?;

    Ok(())
}
