use crate::common::{free_loopback_addr, wait_until_listening};
use reqwest::{Client, Version};
use std::time::Duration;
use tachyon_web::http::response::Html;
use tachyon_web::tls::generate_self_signed_cert;
use tachyon_web::{Router, Server, get};

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

    // `start_all` binds these itself, so hand it free ports rather than live listeners.
    let https_addr = free_loopback_addr().await;
    let http_addr = free_loopback_addr().await;
    let (https_port, http_port) = (https_addr.port(), http_addr.port());

    let server = Server::new(app);
    let _server_handle = tokio::spawn(async move {
        // Start HTTP/3, HTTP/2, and HTTP/1.1 effortlessly
        server
            .start_all(
                &https_addr.to_string(),
                Some(&http_addr.to_string()),
                certs.cert_pem,
                certs.key_pem,
            )
            .await
            .expect("start_all failed");
    });

    // Poll for both listeners rather than guessing a fixed startup delay.
    wait_until_listening(https_addr).await;
    wait_until_listening(http_addr).await;

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
