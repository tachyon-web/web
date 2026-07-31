#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use tachyon_web::Router;

#[tokio::main]
async fn main() {
    let app = Router::new().serve_static("benches/static/public");

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Tachyon static server on {}", addr);

    tachyon_web::serve(listener, app).await.unwrap();
}
