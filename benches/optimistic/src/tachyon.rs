#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use serde::Serialize;
use tachyon_web::http::response::{IntoResponse, Json};
use tachyon_web::routing::{Router, get};

#[derive(Serialize)]
struct Message {
    message: &'static str,
}

async fn plaintext() -> &'static str {
    "Hello, World!"
}

async fn json() -> impl IntoResponse {
    Json(Message {
        message: "Hello, World!",
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(plaintext))
        .route("/json", get(json));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Tachyon server listening on {}", addr);

    tachyon_web::serve(listener, app).await.unwrap();
}
