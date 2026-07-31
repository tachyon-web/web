#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Serialize)]
struct Message {
    message: &'static str,
}

async fn plaintext() -> &'static str {
    "Hello, World!"
}

async fn json() -> Json<Message> {
    Json(Message {
        message: "Hello, World!",
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(plaintext))
        .route("/json", get(json));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Axum server listening on {}", addr);

    axum::serve(listener, app).await.unwrap();
}
