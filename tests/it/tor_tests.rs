//! A full round trip over a real Tor circuit. Config validation and request routing are unit
//! tested in `src/server/tor`.
//!
//! Ignored by default: it needs Tor network egress and can take minutes to bootstrap. Run it
//! with:
//!
//! ```sh
//! cargo test --features tor --test it -- --ignored
//! ```

use axum::Router;
use axum::routing::get;
use tachyon_web::server::tor::OnionConfig;
use tachyon_web::{Network, Server, ServerInfo};

/// Publishes an onion service, fetches a page from it through a second Tor client, and checks
/// the handler saw its own `.onion` address in `ServerInfo`.
#[tokio::test]
#[ignore = "needs live Tor network egress; run explicitly with `-- --ignored`"]
async fn onion_service_round_trip_over_a_real_tor_circuit() {
    use arti_client::{TorClient, TorClientConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let app = Router::new().route(
        "/",
        get(|info: ServerInfo| async move {
            info.endpoints()
                .into_iter()
                .find(|e| e.network == Network::Tor)
                .map(|e| e.host)
                .unwrap_or_default()
        }),
    );
    let serving = TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .expect("bootstrap serving TorClient");
    let (host_tx, host_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut host_rx = host_rx;
    let server = Server::new(app)
        .onion(
            OnionConfig::new(format!("tachyon-test-{:x}", rand::random::<u32>())).client(serving),
        )
        .on_ready(move |endpoint| {
            let _ = host_tx.send(endpoint.host.clone());
        });
    let server_task = tokio::spawn(server.serve().into_future());

    let onion_host = tokio::time::timeout(std::time::Duration::from_mins(3), host_rx.recv())
        .await
        .expect("onion service became reachable within 180s")
        .expect("on_ready fired");

    let fetching = TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .expect("bootstrap fetching TorClient");
    let mut stream = fetching
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

    assert!(response.contains("200 OK"), "{response}");
    assert!(response.ends_with(&onion_host), "{response}");
    server_task.abort();
}
