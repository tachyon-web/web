//! Static file serving under a path prefix, plus a custom 404 fallback.

use std::net::SocketAddr;
use tachyon_web::http::StatusCode;
use tachyon_web::{Router, ServeDir, response::IntoResponse, routing::get};

async fn not_found_fallback() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        "Oops! The page you are looking for does not exist.",
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let public_dir = std::path::Path::new("public");
    if !public_dir.exists() {
        std::fs::create_dir(public_dir)?;
        std::fs::write(
            public_dir.join("index.html"),
            "<h1>Hello from Static Index!</h1>",
        )?;
        std::fs::write(
            public_dir.join("style.css"),
            "body { background: #fafafa; }",
        )?;
    }

    let serve_dir = ServeDir::new("public")
        .index("index.html")
        .preload()
        .await?;

    let app = Router::new()
        .route("/api/health", get(|| async { "OK" }))
        .serve_dir("/static", serve_dir)
        .fallback(not_found_fallback)
        .with_state(());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("listening on http://{addr}");
    println!("  /static/index.html, /static/style.css, /api/health, /missing");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
