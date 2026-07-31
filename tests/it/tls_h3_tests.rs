#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::items_after_statements,
    clippy::use_self,
    clippy::semicolon_if_nothing_returned,
    clippy::similar_names
)]

use reqwest::{Client, Version};
use std::time::Duration;
use tachyon_web::http::response::Html;
use tachyon_web::tls::generate_self_signed_cert;
use tachyon_web::{Router, Server, get};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct AppState {}

async fn handle_root() -> Html<&'static str> {
    Html("<h1>Tachyon Secure Web</h1>")
}

#[tokio::test]
async fn test_server_https_and_h3() {
    let app = Router::new()
        .route("/", get(handle_root))
        .with_state(AppState::default());

    // Generate self signed cert
    let certs =
        generate_self_signed_cert(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();

    // Find a free port before starting the unified server
    let https_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind https");
    let https_port = https_listener.local_addr().expect("local addr").port();
    drop(https_listener); // free the port to reuse it in start_all

    let http_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let http_port = http_listener.local_addr().expect("local addr").port();
    drop(http_listener);

    let addr = format!("127.0.0.1:{}", https_port);
    let redirect_addr = format!("127.0.0.1:{}", http_port);

    let server = Server::new(app);
    let _server_handle = tokio::spawn(async move {
        // Start HTTP/3, HTTP/2, and HTTP/1.1 effortlessly
        server
            .start_all(&addr, Some(&redirect_addr), certs.cert_pem, certs.key_pem)
            .await
            .expect("start_all failed");
    });

    // Wait for the servers to initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test HTTPS (HTTP/2) route
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none()) // Don't auto-follow redirect so we can test the status code
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build client");

    let res = client
        .get(format!("https://127.0.0.1:{}/", https_port))
        .version(Version::HTTP_2)
        .send()
        .await
        .expect("send req https");

    assert_eq!(res.status(), 200);
    assert_eq!(
        res.text().await.expect("text"),
        "<h1>Tachyon Secure Web</h1>"
    );

    // Test HTTP → HTTPS redirect (308 Permanent Redirect preserves the HTTP method,
    // which is important for POST requests; 301 would allow method changes to GET).
    let res_redirect = client
        .get(format!("http://127.0.0.1:{}/some/path?query=1", http_port))
        .send()
        .await
        .expect("send req http redirect");
    assert_eq!(res_redirect.status(), 308);
    let loc = res_redirect
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        loc,
        &format!("https://127.0.0.1:{}/some/path?query=1", https_port)
    );
}
