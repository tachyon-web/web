#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use axum::Router;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let app = Router::new().fallback_service(ServeDir::new("benches/static/public"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Axum static server on {addr}");
    axum::serve(listener, app).await.unwrap();
}
