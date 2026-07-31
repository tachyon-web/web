//! An example demonstrating static file serving and custom fallback routing.
//! Useful for single-page applications (SPAs) or file-serving servers.

use std::net::SocketAddr;
use tachyon_web::http::StatusCode;
use tachyon_web::{Router, ServeDir, response::IntoResponse, routing::get};

/// Fallback handler for requests that don't match any registered route.
async fn not_found_fallback() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        "Oops! The page you are looking for does not exist.",
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Create a dummy public folder for testing
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

    // 2. Configure a static file directory server
    let serve_dir = ServeDir::new("public")
        .index("index.html")
        .preload()
        .await?;

    // 3. Build our router
    let app = Router::new()
        // Serve a simple API route
        .route("/api/health", get(|| async { "OK" }))
        // Serve the static files at the /static path prefix
        .serve_dir("/static", serve_dir)
        // Add a fallback handler for any unmatched paths
        .fallback(not_found_fallback)
        .with_state(());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("🚀 Static file server running at http://{addr}");
    println!("  - Try visiting http://{addr}/static/index.html");
    println!("  - Try visiting http://{addr}/static/style.css");
    println!("  - Try visiting http://{addr}/api/health");
    println!("  - Try visiting a missing page http://{addr}/missing");

    // Bind listener and run the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
