//! Serves the same app as a Tor v3 onion service AND an I2P eepsite, simultaneously —
//! no external `tor` or `i2pd` process, no reverse proxy, no SAM/BOB bridge.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example onion_i2p_server --features tor,i2p
//! ```

use tachyon_web::server::i2p::I2pConfig;
use tachyon_web::server::tor::OnionConfig;
use tachyon_web::{Router, Server, get};

async fn hello() -> &'static str {
    "Hello from Tachyon-Web, reachable over Tor and I2P!"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/", get(hello));

    let onion_config = OnionConfig::new("tachyon-example")
        // Persist keys/state next to the example instead of Arti's default OS state dir.
        .state_dir("./.tachyon-tor/state")
        .cache_dir("./.tachyon-tor/cache")
        .on_ready(|addr| println!("[tor]  reachable at http://{addr}"));

    let i2p_config = I2pConfig::new("tachyon-example")
        .data_dir("./.tachyon-i2p")
        .on_ready(|addr| println!("[i2p]  reachable at http://{addr}"));

    // `MultiServer` owns the multi-transport boilerplate: one task per `.with_*` transport.
    Server::new(app)
        .with_onion(onion_config)
        .with_i2p(i2p_config)
        .serve()
        .await?;

    Ok(())
}
