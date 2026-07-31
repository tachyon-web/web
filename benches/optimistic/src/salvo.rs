#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use salvo::prelude::*;
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    message: &'static str,
}

#[handler]
async fn plaintext(res: &mut Response) {
    res.render("Hello, World!");
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

    let acceptor = TcpListener::new("127.0.0.1:8084").bind().await;
    println!("Salvo server listening on 127.0.0.1:8084");
    Server::new(acceptor).serve(router).await;
}
