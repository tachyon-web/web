//! Tests for native Tor `.onion` hidden-service support (the `tor` feature).
//!
//! Most coverage lives as unit tests inside `src/server/tor.rs` — the request-routing
//! decision (plaintext / TLS / redirect / reject) and the redirect URL builder are pure
//! functions and are exhaustively tested there without needing any network access.
//!
//! This file covers the public `OnionConfig` builder contract, plus one full round-trip
//! test that actually bootstraps Arti, publishes an onion service, and fetches a page from
//! it over a real Tor connection. That last test is marked `#[ignore]` since it needs Tor
//! network egress and can take a minute or more to bootstrap and become reachable; run it
//! explicitly with:
//!
//! ```sh
//! cargo test --features tor --test it -- --ignored
//! ```

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args
)]

use tachyon_web::Router;
use tachyon_web::server::tor::OnionConfig;

// ─── OnionConfig builder contract ──────────────────────────────────────────────

#[test]
fn onion_config_defaults_are_tls_on_dual_stack_no_redirect() {
    let config = OnionConfig::new("my-nickname");
    assert_eq!(config.nickname(), "my-nickname");
    assert!(config.tls_enabled());
    assert!(!config.redirect_http_enabled());
}

#[test]
fn onion_config_no_tls_disables_https() {
    let config = OnionConfig::new("my-nickname").no_tls();
    assert!(!config.tls_enabled());
}

#[test]
fn onion_config_self_signed_tls_reenables_https() {
    let config = OnionConfig::new("my-nickname").no_tls().self_signed_tls();
    assert!(config.tls_enabled());
}

#[test]
fn onion_config_redirect_http_is_independently_toggleable() {
    let config = OnionConfig::new("my-nickname").redirect_http(true);
    assert!(config.tls_enabled());
    assert!(config.redirect_http_enabled());
}

#[test]
fn onion_config_vanguards_override_is_visible() {
    let enabled = OnionConfig::new("my-nickname").vanguards(true);
    assert!(enabled.vanguards_enabled());

    let disabled = OnionConfig::new("my-nickname").vanguards(false);
    assert!(!disabled.vanguards_enabled());
}

#[test]
fn onion_config_builder_methods_chain_in_any_order() {
    let config = OnionConfig::new("chained")
        .state_dir("/tmp/tachyon-tor-test-state")
        .cache_dir("/tmp/tachyon-tor-test-cache")
        .vanguards(false)
        .redirect_http(true);
    assert_eq!(config.nickname(), "chained");
    assert!(config.tls_enabled());
    assert!(config.redirect_http_enabled());
    assert!(!config.vanguards_enabled());
}

// ─── Full round-trip (ignored by default — needs live Tor network egress) ─────

/// Publishes a real onion service serving a tiny [`Router`], connects to it over a real Tor
/// circuit using a second bootstrapped [`arti_client::TorClient`], and asserts the response
/// body round-trips correctly.
///
/// Ignored by default: bootstrapping Arti requires outbound network access to the live Tor
/// network and can take anywhere from several seconds to a couple of minutes, which is too
/// slow and too flaky-under-sandboxing for a default test run.
#[tokio::test]
#[ignore = "needs live Tor network egress; run explicitly with `-- --ignored`"]
async fn onion_service_round_trip_over_a_real_tor_circuit() {
    use arti_client::{TorClient, TorClientConfig};
    use tachyon_web::{Server, get};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn hello() -> &'static str {
        "hello from an onion service"
    }

    let app = Router::new().route("/", get(hello));

    let client = TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .expect("bootstrap serving TorClient");

    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel::<String>();
    let mut addr_tx = Some(addr_tx);

    let config = OnionConfig::new("tachyon-web-test-onion")
        .no_tls()
        .on_ready(move |addr| {
            if let Some(tx) = addr_tx.take() {
                let _ = tx.send(addr.to_string());
            }
        });

    let serve_client = client.clone();
    let server_task = tokio::spawn(async move {
        Server::new(app)
            .serve_onion_with_client(&serve_client, config)
            .await
    });

    let onion_host = tokio::time::timeout(std::time::Duration::from_mins(3), addr_rx)
        .await
        .expect("onion service became reachable within 180s")
        .expect("on_ready callback fired");

    let fetch_client = TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .expect("bootstrap fetching TorClient");

    let mut stream = fetch_client
        .connect(format!("{onion_host}:80"))
        .await
        .expect("connect to onion service over Tor");

    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {onion_host}\r\nConnection: close\r\n\r\n").as_bytes(),
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
        response.contains("hello from an onion service"),
        "unexpected response body: {response}"
    );

    server_task.abort();
}
