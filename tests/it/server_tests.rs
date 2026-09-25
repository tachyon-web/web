//! Plaintext HTTP behavior shared by every transport: body handling, limits, h2c, graceful
//! shutdown, and the metadata handlers see.

use axum::Router;
use axum::routing::{get, post};
use bytes::Bytes;
use std::time::Duration;
use tachyon_web::{Limits, Network, Server, ServerInfo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::common::TestServer;

/// Serves `router`, sends a `POST /` declaring `Content-Length: 10` but no body, and returns
/// the connected stream with the server task.
async fn post_with_undelivered_body(
    router: Router,
) -> (tokio::net::TcpStream, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::new(router).http(listener);
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\n\r\n")
        .await
        .unwrap();
    (stream, handle)
}

async fn read_head(stream: &mut tokio::net::TcpStream) -> String {
    let mut buf = vec![0; 512];
    let n = stream.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(buf.get(..n).unwrap()).to_ascii_lowercase()
}

/// A body that never arrives times out; the `Bytes` extractor reports that as `400`, and the
/// HTTP/1.1 connection is closed rather than left waiting for unread bytes.
#[tokio::test(start_paused = true)]
async fn an_undelivered_body_times_out_and_closes_the_connection() {
    let router = Router::new().route("/", post(|_body: Bytes| async { "ok" }));
    let (mut stream, handle) = post_with_undelivered_body(router).await;

    tokio::time::advance(Duration::from_secs(32)).await;

    let head = read_head(&mut stream).await;
    assert!(head.contains("400"), "{head}");
    assert!(head.contains("connection: close"), "{head}");
    handle.abort();
}

/// Bodies stream lazily: a handler that never reads one answers at once instead of waiting
/// for bytes that may never come.
#[tokio::test]
async fn a_handler_that_ignores_the_body_answers_immediately() {
    let router = Router::new().route("/", post(|| async { "ok" }));
    let (mut stream, handle) = post_with_undelivered_body(router).await;

    let head = tokio::time::timeout(Duration::from_secs(5), read_head(&mut stream))
        .await
        .expect("the handler should not wait for the unread body");
    assert!(head.contains("200"), "{head}");
    assert!(head.contains("connection: close"), "{head}");
    handle.abort();
}

/// `max_body_size` is one setting: extractors accept everything up to it (Axum's own 2 MiB
/// default no longer cuts in first), and the transport refuses anything past it.
#[tokio::test]
async fn the_body_limit_applies_to_extractors_and_the_wire_alike() {
    let limit = rand::random_range(3 * 1024 * 1024..6 * 1024 * 1024);
    let router = Router::new().route(
        "/",
        post(|body: Bytes| async move { body.len().to_string() }),
    );
    let server = TestServer::spawn_with(router, |server| {
        server.limits(Limits::default().max_body_size(limit))
    })
    .await;

    let fits = rand::random_range(2 * 1024 * 1024 + 1..=limit);
    let response = server.post("/").body(vec![7u8; fits]).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), fits.to_string());

    let response = server
        .post("/")
        .body(vec![7u8; limit + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

/// With h2c off (the default) the HTTP/2 stack is not reachable on a plaintext port at all.
#[cfg(feature = "http2")]
#[tokio::test]
async fn plaintext_speaks_http2_only_when_h2c_is_allowed() {
    use tachyon_web::SecurityPolicy;

    async fn first_bytes_after_preface(allow_h2c: bool) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server = Server::new(Router::new())
            .security(SecurityPolicy::new().allow_h2c(allow_h2c))
            .http(listener);
        let handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .expect("write preface");
        let mut head = Vec::new();
        let _ = (&mut stream).take(8).read_to_end(&mut head).await;
        handle.abort();
        head
    }

    let refused = first_bytes_after_preface(false).await;
    assert!(
        refused.is_empty() || refused.starts_with(b"HTTP/1.1"),
        "HTTP/2 answered on a plaintext port with h2c off: {refused:?}"
    );
    // An HTTP/2 server's first frame is its SETTINGS (type 0x4, at byte 3).
    assert_eq!(first_bytes_after_preface(true).await.get(3), Some(&0x4));
}

/// Graceful shutdown lets an in-flight request finish, refuses new connections, and resolves
/// `Ok` once the last connection has closed.
#[tokio::test]
async fn graceful_shutdown_finishes_in_flight_requests_then_returns() {
    let (release, released) = tokio::sync::watch::channel(false);
    let (entered, mut entered_rx) = tokio::sync::mpsc::channel(1);
    let router = Router::new().route(
        "/",
        get(move || {
            let mut released = released.clone();
            let entered = entered.clone();
            async move {
                let _ = entered.send(()).await;
                let _ = released.wait_for(|go| *go).await;
                "finished"
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(
        Server::new(router)
            .http(listener)
            .serve()
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .into_future(),
    );

    let in_flight = tokio::spawn(reqwest::get(url.clone()));
    entered_rx.recv().await.expect("the handler started");
    stop.send(()).unwrap();
    // Accepting has stopped, but the server is still waiting on the open request.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(reqwest::get(&url).await.is_err());
    assert!(!server.is_finished());

    release.send(true).unwrap();
    let response = in_flight.await.unwrap().unwrap();
    assert_eq!(response.text().await.unwrap(), "finished");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server returns once its connections close")
        .unwrap()
        .expect("a graceful stop is not an error");
}

/// Handlers receive `ServerInfo`, and `on_ready` sees each endpoint as it comes up.
#[tokio::test]
async fn handlers_and_on_ready_see_the_published_endpoints() {
    let (ready, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
    let router = Router::new().route(
        "/",
        get(|info: ServerInfo| async move {
            info.endpoints()
                .iter()
                .map(tachyon_web::Endpoint::url)
                .collect::<Vec<_>>()
                .join(",")
        }),
    );
    let server = TestServer::spawn_with(router, move |server| {
        server.on_ready(move |endpoint| {
            let _ = ready.send(endpoint.clone());
        })
    })
    .await;

    let endpoint = ready_rx.recv().await.expect("the endpoint was published");
    assert_eq!(endpoint.network, Network::Clearnet);
    assert_eq!(endpoint.url(), format!("http://{}", server.addr()));
    let body = server.get("/").send().await.unwrap().text().await.unwrap();
    assert_eq!(body, endpoint.url());
}
