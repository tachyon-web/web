#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    message: &'static str,
}

async fn plaintext() -> impl Responder {
    "Hello, World!"
}

async fn json() -> impl Responder {
    HttpResponse::Ok().json(Message {
        message: "Hello, World!",
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certs = tachyon_web::tls::generate_self_signed_cert(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .unwrap();

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certs.cert_der], certs.key_der)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    println!("Actix TLS server listening on 127.0.0.1:8082");

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(plaintext))
            .route("/json", web::get().to(json))
    })
    .bind_rustls_0_23("127.0.0.1:8082", config)?
    .run()
    .await
}
