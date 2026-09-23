#[cfg(feature = "cert-gen")]
use crate::common::tls_client;
#[cfg(any(feature = "http1", feature = "cert-gen"))]
use crate::common::{free_loopback_addr, wait_until_listening};
#[cfg(feature = "http1")]
use bytes::Bytes;
#[cfg(feature = "http1")]
use std::time::Duration;
// `get` is used by the `cert-gen` TLS tests too, so it follows the same gate as the
// `common` helpers above; `post` is only ever reached from an `http1` test.
#[cfg(any(feature = "http1", feature = "cert-gen"))]
use tachyon_web::routing::get;
#[cfg(feature = "http1")]
use tachyon_web::routing::post;
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
    assert!(
        resp_str.to_ascii_lowercase().contains("connection: close"),
        "failed bodies must not leave an HTTP/1.1 connection waiting for unread bytes: {resp_str}"
    );

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
    assert!(
        resp_str.to_ascii_lowercase().contains("connection: close"),
        "an unread HTTP/1.1 body cannot be reused safely: {resp_str}"
    );

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
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONNECTION)
            .and_then(|value| value.to_str().ok()),
        Some("close")
    );
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

/// `max_tls_handshakes` bounds handshakes in flight, not live TLS connections. Its permit used
/// to ride along for the whole connection, so a limit of 1 served exactly one client at a time.
#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn tls_handshake_permit_is_released_once_the_handshake_completes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("https://{}/", listener.local_addr().expect("local_addr"));
    let server =
        Server::new(Router::new().route("/", get(|| async { "ok" }))).max_tls_handshakes(1);
    let config = self_signed_config(&[b"h2", b"http/1.1"]);
    let handle = tokio::spawn(async move {
        let _ = server.serve_https_config(listener, config).await;
    });

    // Already bound, so no `wait_until_listening` probe: with one permit, a probe's aborted
    // handshake could still be holding it when the real client arrives.
    // Each client keeps its pooled connection open, so both are live at once.
    let clients = [tls_client(), tls_client()];
    for client in &clients {
        let response = client.get(&url).send().await.expect("TLS request");
        assert_eq!(response.status(), 200);
    }

    handle.abort();
}

/// A failed HTTPS bind must not leave the detached cleartext listener behind: the caller got
/// an `Err`, so a retry has to find that port free.
#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn a_failed_tls_bind_leaves_the_cleartext_port_free() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let tls_addr = occupied.local_addr().expect("local_addr").to_string();
    let cleartext_addr = free_loopback_addr().await.to_string();
    let cert = tachyon_web::tls::generate_self_signed_cert(vec!["localhost".to_string()])
        .expect("generate self-signed cert");

    let started = Server::new(Router::new())
        .start_all(
            &tls_addr,
            Some(&cleartext_addr),
            cert.cert_pem,
            cert.key_pem,
        )
        .await;
    assert!(started.is_err());
    drop(
        tokio::net::TcpListener::bind(&cleartext_addr)
            .await
            .expect("start_all left the cleartext port bound"),
    );

    #[cfg(feature = "lets-encrypt")]
    {
        let cache = tempfile::tempdir().expect("create cache directory");
        let started = Server::new(Router::new())
            .serve_all_acme(
                &tls_addr,
                &cleartext_addr,
                vec!["localhost".to_string()],
                "admin@example.com".to_string(),
                cache.path(),
                true,
            )
            .await;
        assert!(started.is_err());
        drop(
            tokio::net::TcpListener::bind(&cleartext_addr)
                .await
                .expect("serve_all_acme left the cleartext port bound"),
        );
    }
}

/// Sidecar listeners belong to the serving future: cancelling HTTPS must release the
/// cleartext redirect port instead of leaving a detached server behind.
#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn cancelling_https_stops_its_redirect_listener() {
    let tls_addr = free_loopback_addr().await;
    let cleartext_addr = free_loopback_addr().await;
    let cert = tachyon_web::tls::generate_self_signed_cert(vec!["localhost".to_string()])
        .expect("generate self-signed cert");

    let tls_addr_string = tls_addr.to_string();
    let cleartext_addr_string = cleartext_addr.to_string();
    let task = tokio::spawn(async move {
        Server::new(Router::new())
            .start_all(
                &tls_addr_string,
                Some(&cleartext_addr_string),
                cert.cert_pem,
                cert.key_pem,
            )
            .await
    });
    wait_until_listening(cleartext_addr).await;

    task.abort();
    let _ = task.await;
    drop(
        tokio::net::TcpListener::bind(cleartext_addr)
            .await
            .expect("redirect listener survived its HTTPS server"),
    );
}

/// With h2c off (the default) the HTTP/2 stack is not reachable on a plaintext port at all:
/// HTTP/1.1 refuses the connection preface. Opting in brings HTTP/2 back.
#[cfg(all(feature = "http1", feature = "http2"))]
#[tokio::test]
async fn plaintext_speaks_http2_only_when_h2c_is_allowed() {
    async fn first_bytes_after_preface(allow_h2c: bool) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let policy = tachyon_web::server::SecurityPolicy::new().allow_h2c(allow_h2c);
        let server = Server::new(Router::new()).security_policy(policy);
        let handle = tokio::spawn(async move {
            let _ = server.serve_http(listener).await;
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .expect("write preface");
        let mut head = Vec::new();
        let _ = (&mut stream)
            .take(8)
            .read_to_end(&mut head)
            .await
            .expect("read reply");
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
