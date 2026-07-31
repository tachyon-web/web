#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::prelude::*;
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    message: &'static str,
}

#[handler]
async fn plaintext() -> &'static str {
    "Hello, World!"
}

#[handler]
async fn json(res: &mut Response) {
    res.render(Json(Message {
        message: "Hello, World!",
    }));
}

#[tokio::main]
async fn main() {
    let router = Router::new()
        .get(plaintext)
        .push(Router::with_path("json").get(json));

    let certs = tachyon_web::tls::generate_self_signed_cert(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .unwrap();

    let config = RustlsConfig::new(
        Keycert::new()
            .cert(certs.cert_pem.as_bytes())
            .key(certs.key_pem.as_bytes()),
    );

    let listener = TcpListener::new("127.0.0.1:8084").rustls(config);
    let acceptor = listener.bind().await;

    println!("Salvo TLS server listening on 127.0.0.1:8084");

    Server::new(acceptor).serve(router).await;
}
