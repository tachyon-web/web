#[cfg(feature = "cert-gen")]
use crate::common::tls_client;
#[cfg(any(feature = "http1", feature = "cert-gen"))]
use crate::common::{free_loopback_addr, wait_until_listening};
#[cfg(feature = "http1")]
use bytes::Bytes;
#[cfg(feature = "http1")]
use std::time::Duration;
#[cfg(feature = "http1")]
use tachyon_web::routing::{get, post};
use tachyon_web::{Router, Server};
#[cfg(feature = "http1")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "http1")]
use tokio::net::TcpListener;

/// A `rustls::ServerConfig` holding a fresh self-signed `localhost` certificate, with the
/// given ALPN list — the setup five of the TLS tests below each spelled out in full.
#[cfg(feature = "cert-gen")]
fn self_signed_config(alpn: &[&[u8]]) -> rustls::ServerConfig {
    let cert = tachyon_web::tls::generate_self_signed_cert(vec!["localhost".to_string()])
        .expect("generate self-signed cert");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der], cert.key_der)
        .expect("build rustls ServerConfig");
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// Waits for `addr` to come up, then asserts a request to it answers `200` with `expected`.
#[cfg(any(feature = "http1", feature = "cert-gen"))]
async fn assert_serves(
    client: &reqwest::Client,
    url: &str,
    addr: std::net::SocketAddr,
    expected: &str,
) {
    wait_until_listening(addr).await;
    let res = client.get(url).send().await.expect("request");
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.expect("body"), expected);
}

#[test]
fn test_server_debug_and_config() {
    let router = Router::new();
    let server = Server::new(router).max_body_size(1024);
    assert_eq!(server.max_body_size, 1024);
    let dbg = format!("{:?}", server);
    assert!(dbg.contains("Server"));
}

#[tokio::test]
#[cfg(feature = "cert-gen")]
async fn test_start_all_invalid_address() {
    let router = Router::new();
    let server = Server::new(router);
    let res = server
        .start_all(
            "999.999.999.999:9999",
            None,
            "cert".to_string(),
            "key".to_string(),
        )
        .await;
    assert!(res.is_err());
}

/// Spawns `router` on plaintext HTTP, sends a `POST /` with a declared `Content-Length: 10`
/// but no body, and returns the connected stream plus the server task handle — the setup
/// the two body-read tests below both need before they diverge on what they wait for.
#[cfg(feature = "http1")]
async fn post_with_undelivered_body(
    router: Router<()>,
) -> (tokio::net::TcpStream, tokio::task::JoinHandle<()>) {
    let server = Server::new(router);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = server.serve_http(listener).await;
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req_headers = "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\n\r\n";
    stream.write_all(req_headers.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    (stream, server_handle)
}

// Bodies are streamed lazily (not eagerly buffered) — a handler only pays the cost of
// waiting for the body if it actually extracts it. A `413`/timeout can only surface once
// something reads the body, so this route uses `Bytes` (rather than an arity-0 handler)
// to exercise the read path.
//
// The response is `400`, not `408`: the body-read deadline firing surfaces to the `Bytes`
// extractor as a body-buffering failure, and — matching
// `axum_core::extract::rejection::FailedToBufferBody`'s fixed `UnknownBodyError` (`400`)
// shape exactly — that collapses to a fixed status rather than preserving the original
// error's status code.
#[cfg(feature = "http1")]
#[tokio::test(start_paused = true)]
async fn test_server_request_timeout() {
    let router = Router::new().route("/", post(|_body: Bytes| async { "ok" }));
    let (mut stream, server_handle) = post_with_undelivered_body(router).await;

    tokio::time::advance(Duration::from_secs(32)).await;

    let mut resp_bytes = vec![0; 512];
    let n = stream.read(&mut resp_bytes).await.unwrap();
    let resp_str = String::from_utf8_lossy(resp_bytes.get(..n).unwrap());
    assert!(resp_str.contains("400"), "response was: {resp_str}");

    server_handle.abort();
}

// A handler that never touches the body (arity-0) must respond immediately rather than
// waiting for the (never-sent) body — a deliberate improvement over always buffering the
// full body up front before dispatching to the handler at all.
#[cfg(feature = "http1")]
#[tokio::test]
async fn test_server_ignores_unread_body_for_bodyless_handler() {
    let router = Router::new().route("/", post(|| async { "ok" }));
    let (mut stream, server_handle) = post_with_undelivered_body(router).await;

    // No body is ever sent. The handler doesn't need it, so the response should arrive
    // promptly rather than after any body-read timeout.
    let resp_fut = async {
        let mut resp_bytes = vec![0; 512];
        let n = stream.read(&mut resp_bytes).await.unwrap();
        String::from_utf8_lossy(resp_bytes.get(..n).unwrap()).into_owned()
    };
    let resp_str = tokio::time::timeout(Duration::from_secs(5), resp_fut)
        .await
        .expect("handler should respond promptly without waiting on the unread body");
    assert!(resp_str.contains("200"), "response was: {resp_str}");

    server_handle.abort();
}

#[cfg(feature = "http1")]
#[tokio::test]
async fn test_server_enforces_transport_body_limit() {
    let router = Router::new().route("/", post(|_body: Bytes| async { "ok" }));
    let server = Server::new(router).max_body_size(10);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = server.serve_http(listener).await;
    });

    let response = reqwest::Client::new()
        .post(format!("http://{addr}/"))
        .body(vec![0_u8; 11])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    handle.abort();
}

#[cfg(feature = "http1")]
#[tokio::test]
async fn test_start_http_addr() {
    let addr = free_loopback_addr().await;
    let router = Router::new().route("/", get(|| async { "ok-addr" }));
    let server = Server::new(router);
    let handle = tokio::spawn(async move {
        let _ = server.start_http_addr(addr).await;
    });

    assert_serves(
        &reqwest::Client::new(),
        &format!("http://{addr}/"),
        addr,
        "ok-addr",
    )
    .await;
    handle.abort();
}

#[cfg(feature = "http1")]
#[tokio::test]
async fn test_start_http_with_address_string() {
    let addr = free_loopback_addr().await;
    let router = Router::new().route("/", get(|| async { "ok-str" }));
    let server = Server::new(router);
    let addr_str = addr.to_string();
    let handle = tokio::spawn(async move {
        let _ = server.start_http(&addr_str).await;
    });

    assert_serves(
        &reqwest::Client::new(),
        &format!("http://{addr}/"),
        addr,
        "ok-str",
    )
    .await;
    handle.abort();
}

#[tokio::test]
async fn test_start_http_rejects_unparseable_address() {
    let server = Server::new(Router::new());
    let err = server
        .start_http("this-is-not-a-socket-addr")
        .await
        .expect_err("unparseable bind address must fail fast, without binding anything");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn test_start_https_with_config_addr() {
    let server_config = self_signed_config(&[b"h2", b"http/1.1"]);
    let addr = free_loopback_addr().await;
    let router = Router::new().route("/", get(|| async { "ok-https-addr" }));
    let server = Server::new(router);
    let handle = tokio::spawn(async move {
        let _ = server
            .start_https_with_config_addr(addr, server_config)
            .await;
    });

    assert_serves(
        &tls_client(),
        &format!("https://{addr}/"),
        addr,
        "ok-https-addr",
    )
    .await;
    handle.abort();
}

#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn test_start_https_with_config_string() {
    let server_config = self_signed_config(&[b"h2", b"http/1.1"]);
    let addr = free_loopback_addr().await;
    let addr_str = addr.to_string();
    let router = Router::new().route("/", get(|| async { "ok-https-str" }));
    let server = Server::new(router);
    let handle = tokio::spawn(async move {
        let _ = server
            .start_https_with_config(&addr_str, server_config)
            .await;
    });

    assert_serves(
        &tls_client(),
        &format!("https://{addr}/"),
        addr,
        "ok-https-str",
    )
    .await;
    handle.abort();
}

#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn test_start_https_with_config_rejects_unparseable_address() {
    let server_config = self_signed_config(&[]);
    let server = Server::new(Router::new());
    let err = server
        .start_https_with_config("this-is-not-a-socket-addr", server_config)
        .await
        .expect_err("unparseable bind address must fail fast, without binding anything");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[cfg(all(feature = "cert-gen", feature = "http3"))]
#[tokio::test]
async fn test_start_https_and_h3_with_config() {
    let server_config = self_signed_config(&[]);
    let addr = free_loopback_addr().await;
    let addr_str = addr.to_string();
    let router = Router::new().route("/", get(|| async { "ok-h3-config" }));
    let server = Server::new(router);
    let handle = tokio::spawn(async move {
        let _ = server
            .start_https_and_h3_with_config(&addr_str, server_config)
            .await;
    });

    // Both the QUIC (UDP) and TCP TLS listeners share `addr`; waiting on the TCP one is
    // enough here, since that's what this request goes over.
    wait_until_listening(addr).await;
    let res = tls_client()
        .get(format!("https://{addr}/"))
        .version(reqwest::Version::HTTP_2)
        .send()
        .await
        .expect("https/2 request over the shared tls_addr");
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok-h3-config");
    handle.abort();
}

#[cfg(feature = "http1")]
#[tokio::test]
async fn test_free_serve_function() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route("/", get(|| async { "ok-serve-fn" }));

    let handle = tokio::spawn(async move {
        let _ = tachyon_web::serve(listener, router).await;
    });

    assert_serves(
        &reqwest::Client::new(),
        &format!("http://{addr}/"),
        addr,
        "ok-serve-fn",
    )
    .await;
    handle.abort();
}

#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn test_bind_rustls_https_server_serve() {
    use tachyon_web::RustlsConfig;
    use tachyon_web::tls::generate_self_signed_cert;

    let cert = generate_self_signed_cert(vec!["localhost".to_string()]).unwrap();
    let config = RustlsConfig::from_pem(cert.cert_pem.into_bytes(), cert.key_pem.into_bytes())
        .await
        .expect("build RustlsConfig from a valid self-signed cert");

    let addr = free_loopback_addr().await;
    let router = Router::new().route("/", get(|| async { "ok-bind-rustls" }));
    let handle = tokio::spawn(async move {
        let _ = tachyon_web::bind_rustls(addr, config).serve(router).await;
    });

    assert_serves(
        &tls_client(),
        &format!("https://{addr}/"),
        addr,
        "ok-bind-rustls",
    )
    .await;
    handle.abort();
}

#[cfg(all(feature = "cert-gen", feature = "http3"))]
#[tokio::test]
async fn test_bind_rustls_https_server_serve_with_http3_enabled() {
    use tachyon_web::RustlsConfig;
    use tachyon_web::tls::generate_self_signed_cert;

    let cert = generate_self_signed_cert(vec!["localhost".to_string()]).unwrap();
    let config = RustlsConfig::from_pem(cert.cert_pem.into_bytes(), cert.key_pem.into_bytes())
        .await
        .expect("build RustlsConfig from a valid self-signed cert");

    let addr = free_loopback_addr().await;
    let router = Router::new().route("/", get(|| async { "ok-bind-rustls-h3" }));
    let handle = tokio::spawn(async move {
        let _ = tachyon_web::bind_rustls(addr, config)
            .serve_http3(true)
            .serve(router)
            .await;
    });

    assert_serves(
        &tls_client(),
        &format!("https://{addr}/"),
        addr,
        "ok-bind-rustls-h3",
    )
    .await;
    handle.abort();
}

/// `serve()` must put a read deadline on request bodies, the same as `Server::serve_http`.
///
/// It used to map `hyper::body::Incoming` straight into a `Body`, skipping the `DeadlineBody`
/// wrapper the `Server` path applies. A peer could then send complete headers announcing a
/// body and simply never send it, pinning a connection for as long as it liked — and since
/// `serve()` now caps concurrency, enough such peers lock the listener out entirely rather
/// than merely growing memory.
///
/// Ignored by default: the deadline is `REQUEST_TIMEOUT` (30s), so proving it fires means
/// actually waiting it out, which is too slow for a default run.
#[cfg(feature = "http1")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "waits out the 30s body-read deadline; run explicitly with `-- --ignored`"]
async fn serve_applies_a_request_body_read_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app: Router<()> = Router::new().route(
        "/echo",
        post(|body: Bytes| async move { format!("got {}", body.len()) }),
    );
    let handle = tokio::spawn(std::future::IntoFuture::into_future(tachyon_web::serve(
        listener, app,
    )));
    wait_until_listening(addr).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Complete headers announcing a body, then send exactly nothing.
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n")
        .await
        .unwrap();

    let mut buf = Vec::new();
    let drained = tokio::time::timeout(Duration::from_secs(45), stream.read_to_end(&mut buf)).await;
    assert!(
        drained.is_ok(),
        "connection was still held open after 45s — the body read deadline is not being applied"
    );
    handle.abort();
}
