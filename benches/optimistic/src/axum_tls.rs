#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use serde::Serialize;
use std::net::SocketAddr;

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

    // Generate certificates using Tachyon's helper
    let certs = tachyon_web::tls::generate_self_signed_cert(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .unwrap();

    // Configure rustls via axum-server
    let config = RustlsConfig::from_pem(certs.cert_pem.into_bytes(), certs.key_pem.into_bytes())
        .await
        .unwrap();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    println!("Axum TLS server listening on {}", addr);

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
