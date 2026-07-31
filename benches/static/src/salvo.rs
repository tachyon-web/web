#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use salvo::prelude::*;
use salvo::serve_static::StaticDir;

#[tokio::main]
async fn main() {
    let router = Router::with_path("<*path>").get(
        StaticDir::new(["benches/static/public"])
            .defaults("index.html")
            .auto_list(false),
    );

    let acceptor = TcpListener::new("127.0.0.1:8084").bind().await;
    println!("Salvo static server on 127.0.0.1:8084");
    Server::new(acceptor).serve(router).await;
}
