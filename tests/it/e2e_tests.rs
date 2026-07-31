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
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tachyon_web::Path;
use tachyon_web::http::response::Html;
use tachyon_web::{Router, Server, get};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct AppState {}

#[derive(Deserialize, Serialize)]
struct User {
    id: u32,
    name: String,
}

async fn handle_root() -> Html<&'static str> {
    Html("<h1>Hello World</h1>")
}

async fn handle_user(Path(user): Path<User>) -> tachyon_web::http::response::Json<User> {
    tachyon_web::http::response::Json(user)
}

#[tokio::test]
async fn test_server_e2e() {
    let app = Router::new()
        .route("/", get(handle_root))
        .route("/user/:id/:name", get(handle_user))
        .with_state(AppState::default());

    let server = Server::new(app);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let _handle = tokio::spawn(async move {
        server.serve_http(listener).await.expect("serve http");
    });

    // Give it a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::new();

    // Test root route
    let res = client
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await
        .expect("send req");
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.expect("text"), "<h1>Hello World</h1>");

    // Test JSON and Path Extractor route
    let res = client
        .get(format!("http://127.0.0.1:{}/user/123/alice", port))
        .send()
        .await
        .expect("send req");
    assert_eq!(res.status(), 200);

    let user: User = res.json().await.expect("json");
    assert_eq!(user.id, 123);
    assert_eq!(user.name, "alice");
}
