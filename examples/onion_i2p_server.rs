//! Serves the same app as a Tor v3 onion service AND an I2P eepsite, simultaneously —
//! no external `tor` or `i2pd` process, no reverse proxy, no SAM/BOB bridge.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example onion_i2p_server --features tor,i2p
//! ```
//!
//! Both services publish over the anonymity network they belong to, which takes real time.
//! The i2p `on_ready` fires quickly (as soon as the local destination exists — not necessarily
//! reachable yet). Tor's is slower and has no fixed upper bound: it only fires once the onion
//! service's descriptor has actually been accepted by `HsDirs` on the live network, which is
//! commonly tens of seconds but, especially on a first run with no cached consensus, can take
//! several minutes. Run with `RUST_LOG=info` to watch that bootstrap progress (each Tor state
//! transition is logged) instead of wondering whether it hung.
//!
//! Keys/state persist across restarts as long as you reuse the same nickname and
//! directories: the onion service keeps its `.onion` address, and the eepsite keeps its
//! `.b32.i2p` address.
//!
//! Note on trust model: `tor` is pure Rust (`arti-client`/`tor-hsservice`), same
//! `#![forbid(unsafe_code)]` guarantee as the rest of Tachyon-Web. `i2p` links the vendored
//! `libi2pd` C++ router through an FFI shim (`tachyon-i2p`/`i2pd-sys`) — see
//! `tachyon_web::server::i2p` module docs for the full disclosure before using it for anything
//! security-sensitive.

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
        // Persist keys/state next to the example instead of Arti's default OS state dir,
        // so re-running this example keeps the same .onion address.
        .state_dir("./.tachyon-tor/state")
        .cache_dir("./.tachyon-tor/cache")
        .on_ready(|addr| println!("[tor]  reachable at http://{addr}"));

    let i2p_config = I2pConfig::new("tachyon-example")
        .data_dir("./.tachyon-i2p")
        .on_ready(|addr| println!("[i2p]  reachable at http://{addr}"));

    // `MultiServer` owns the multi-transport boilerplate: one task per `.with_*` transport,
    // driven concurrently, torn down together as soon as any one of them finishes.
    Server::new(app)
        .with_onion(onion_config)
        .with_i2p(i2p_config)
        .serve()
        .await?;

    Ok(())
}
