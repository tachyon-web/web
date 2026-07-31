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

use reqwest::Client;
use std::fs;
use tachyon_web::{Router, ServeDir, Server};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_static_dir_serving() {
    let temp_dir = std::env::temp_dir().join("tachyon_static_test2");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create dir");

    fs::write(temp_dir.join("index.html"), "<h1>Home</h1>").expect("write html");
    fs::write(temp_dir.join("style.css"), "body { color: red; }").expect("write css");

    // Simple API: .index() replaces the confusing .fallback_override()
    let static_service = ServeDir::new(&temp_dir)
        .index("index.html")
        .preload()
        .await
        .expect("preload");

    // Serve at / — root → index.html, /style.css → style.css
    let app: Router<()> = Router::new().serve_dir("/", static_service);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let server = Server::new(app);
    let _handle = tokio::spawn(async move {
        server.serve_http(listener).await.expect("serve");
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();
    let base = format!("http://127.0.0.1:{}", port);

    // Root → index.html
    let res = client
        .get(format!("{}/", base))
        .send()
        .await
        .expect("get /");
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert_eq!(res.text().await.unwrap(), "<h1>Home</h1>");

    // Direct file path
    let res = client
        .get(format!("{}/style.css", base))
        .send()
        .await
        .expect("get css");
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/css")
    );
    assert_eq!(res.text().await.unwrap(), "body { color: red; }");

    // Missing file → 404
    let res = client
        .get(format!("{}/missing.js", base))
        .send()
        .await
        .expect("get missing");
    assert_eq!(res.status(), 404);
}
