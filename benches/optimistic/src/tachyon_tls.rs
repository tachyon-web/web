#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use serde::Serialize;
use tachyon_web::http::response::{IntoResponse, Json};
use tachyon_web::routing::{Router, get};
use tachyon_web::tls::generate_self_signed_cert;

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

    let certs =
        generate_self_signed_cert(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();

    let config = tachyon_web::RustlsConfig::from_pem(
        certs.cert_pem.into_bytes(),
        certs.key_pem.into_bytes(),
    )
    .await
    .unwrap();

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Tachyon TLS server listening on {}", addr);

    tachyon_web::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
