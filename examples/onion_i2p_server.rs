//! The same app served over clearnet HTTP, a Tor onion service and an I2P eepsite at once —
//! no external `tor` or `i2pd` process, no reverse proxy, no SAM/BOB bridge.
//!
//! The onion service also serves HTTPS with a persistent ML-DSA-87 certificate for its
//! `.onion` address, and every page links to the mirrors the server has published so far —
//! the addresses only exist once each network has published them.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example onion_i2p_server --features tor,i2p,tls
//! curl -sS http://127.0.0.1:8080/
//! ```

use std::fmt::Write as _;

use axum::{Router, routing::get};
use tachyon_web::server::i2p::I2pConfig;
use tachyon_web::server::tor::OnionConfig;
use tachyon_web::tls::{KeyAlgorithm, Tls};
use tachyon_web::{Network, Server, ServerInfo};

async fn mirrors(info: ServerInfo) -> String {
    let mut page = String::from("Hello from Tachyon-Web. Mirrors:\n");
    for endpoint in info.endpoints() {
        if endpoint.network != Network::Clearnet {
            let _ = writeln!(page, "  {:?}: {}", endpoint.network, endpoint.url());
        }
    }
    for cert in info.certificates() {
        let _ = writeln!(
            page,
            "  certificate for {:?}: sha256 {}",
            cert.names,
            cert.sha256_hex()
        );
    }
    page
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/", get(mirrors));

    let onion = OnionConfig::new("tachyon-example")
        // Persist keys and state next to the example instead of Arti's default directories.
        .state_dir("./.tachyon-tor/state")
        .cache_dir("./.tachyon-tor/cache")
        .tls(
            Tls::new()
                .store("./.tachyon-tor/tls")
                .self_signed(KeyAlgorithm::MlDsa87),
        );
    let eepsite = I2pConfig::new("tachyon-example").data_dir("./.tachyon-i2p");

    Server::new(app)
        .http("127.0.0.1:8080")
        .onion(onion)
        .i2p(eepsite)
        .on_ready(|endpoint| println!("[{:?}] reachable at {}", endpoint.network, endpoint.url()))
        .serve()
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
