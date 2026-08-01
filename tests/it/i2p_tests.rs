//! Tests for native I2P `.b32.i2p` eepsite support (the `i2p` feature).
//!
//! Most coverage lives as unit tests inside `src/server/i2p.rs` — `I2pConfig`'s builder
//! defaults/toggles and its keys-file path resolution are pure and tested there without
//! needing any network access.
//!
//! This file covers one full round-trip test that actually starts the vendored `libi2pd`
//! router, publishes an eepsite, and fetches a page from it over a real I2P stream (via a
//! second, transient destination sharing the same router — only one [`I2pRouter`] may run per
//! process, see [`Server::serve_i2p_config_with_router`]). It's marked `#[ignore]` since it
//! needs I2P network egress and real tunnels have to be built, which commonly takes a few
//! minutes; run it explicitly with:
//!
//! ```sh
//! cargo test --features i2p --test it -- --ignored
//! ```

use tachyon_i2p::I2pRouter;
use tachyon_web::Router;
use tachyon_web::server::i2p::I2pConfig;

#[test]
fn i2p_config_defaults_are_plaintext_no_on_ready() {
    let config = I2pConfig::new("my-nickname");
    assert_eq!(config.nickname(), "my-nickname");
    assert!(!config.tls_enabled());
}

#[test]
fn i2p_config_self_signed_tls_enables_https() {
    let config = I2pConfig::new("my-nickname").self_signed_tls();
    assert!(config.tls_enabled());
}

#[test]
fn i2p_config_no_tls_disables_https_again() {
    let config = I2pConfig::new("my-nickname").self_signed_tls().no_tls();
    assert!(!config.tls_enabled());
}

#[test]
fn i2p_config_builder_methods_chain_in_any_order() {
    let config = I2pConfig::new("chained")
        .data_dir("/tmp/tachyon-i2p-test-data")
        .self_signed_tls();
    assert_eq!(config.nickname(), "chained");
    assert!(config.tls_enabled());
}

/// Publishes a real eepsite serving a tiny [`Router`], connects to it from a second, transient
/// destination sharing the same [`I2pRouter`], and asserts the HTTP response round-trips
/// correctly over a real I2P stream.
///
/// Ignored by default: this needs outbound network access to the live I2P network and building
/// real tunnels commonly takes from several seconds up to a few minutes, which is too slow and
/// too flaky-under-sandboxing for a default test run.
#[tokio::test]
#[ignore = "needs live I2P network egress; run explicitly with `-- --ignored`"]
async fn eepsite_round_trip_over_a_real_i2p_stream() {
    use std::time::Duration;
    use tachyon_web::{Server, get};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn hello() -> &'static str {
        "hello from an eepsite"
    }

    let app = Router::new().route("/", get(hello));

    let router = I2pRouter::start("tachyon-web-test-i2p")
        .await
        .expect("start I2pRouter");

    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel::<String>();
    let mut addr_tx = Some(addr_tx);

    let keys_dir = tempfile::tempdir().expect("create temp dir");
    let config = I2pConfig::new("tachyon-web-test-eepsite")
        .data_dir(keys_dir.path())
        .on_ready(move |addr| {
            if let Some(tx) = addr_tx.take() {
                let _ = tx.send(addr.to_string());
            }
        });

    let serve_router = router.clone();
    let server_task = tokio::spawn(async move {
        Server::new(app)
            .serve_i2p_config_with_router(&serve_router, config)
            .await
    });

    let eepsite_host = tokio::time::timeout(Duration::from_mins(3), addr_rx)
        .await
        .expect("eepsite became reachable within 180s")
        .expect("on_ready callback fired");

    let client_dest = router
        .create_transient_destination()
        .await
        .expect("create client destination");

    // Decode the `.b32.i2p` address back to its raw IdentHash for `connect` -- the safe API
    // deliberately has no other way to get one from a bare address string, since every real
    // caller either already has the `Destination` (and thus `ident_hash()`) or is connecting to
    // a *different* process's eepsite, in which case this same decode is exactly what's needed.
    let ident_hash = b32_decode_ident_hash(&eepsite_host);

    eprintln!("connecting to {eepsite_host} (up to 180s)...");
    let mut stream = client_dest
        .connect(ident_hash, Duration::from_mins(3))
        .await
        .expect("connect to eepsite over I2P");

    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {eepsite_host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("send request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&response);

    assert!(
        response.contains("200 OK"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("hello from an eepsite"),
        "unexpected response body: {response}"
    );

    server_task.abort();
}

/// Decodes a `<52 chars>.b32.i2p` address back to its raw 32-byte `IdentHash` (RFC 4648 base32,
/// lowercase, no padding) -- test-only; the safe API has no public equivalent since real callers
/// either already hold the `Destination` (and its `ident_hash()`) or, like here, are simulating
/// a second, unrelated process that only has the address string.
#[allow(clippy::expect_used)]
fn b32_decode_ident_hash(host: &str) -> [u8; 32] {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let encoded = host
        .strip_suffix(".b32.i2p")
        .expect("unexpected address format");
    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut out = Vec::with_capacity(32);
    for c in encoded.bytes() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c.to_ascii_lowercase())
            .expect("invalid base32 character");
        bits = (bits << 5) | val as u64;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            #[allow(clippy::cast_possible_truncation)] // masked to 8 bits by construction
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    out.try_into().expect("decoded length was not 32 bytes")
}
