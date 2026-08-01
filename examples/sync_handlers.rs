//! Synchronous handlers: extraction, state, and what happens when one blocks.
//!
//! A sync handler runs to completion on the Tokio worker thread that picked up the request —
//! no future is allocated, but a blocking call inside one stalls every other request that
//! worker is responsible for. Keep them to quick CPU-bound work and static responses; use
//! `spawn_blocking` for anything that touches the disk or network.

use serde::Serialize;
use std::net::SocketAddr;
use std::time::SystemTime;
use tachyon_web::http::StatusCode;
use tachyon_web::{
    Router,
    extract::State,
    response::{Html, IntoResponse, Json},
    routing::get,
};

#[derive(Clone)]
struct AppConfig {
    version: &'static str,
}

#[derive(Serialize)]
struct SystemStatus {
    version: &'static str,
    timestamp: u128,
}

const fn static_home() -> Html<&'static str> {
    Html("<h1>Tachyon-Web Synchronous Handler Demo</h1><p>Fast, heap-free, and safe.</p>")
}

fn system_status(State(config): State<AppConfig>) -> impl IntoResponse {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    (
        StatusCode::OK,
        Json(SystemStatus {
            version: config.version,
            timestamp: now,
        }),
    )
}

/// Counter-example, deliberately unrouted: this blocks the worker thread for the duration of
/// the read, so concurrent requests on that worker stall behind it.
#[allow(dead_code)]
fn dangerous_blocking_read() -> String {
    std::fs::read_to_string("config.toml").unwrap_or_default()
}

async fn safe_blocking_read() -> impl IntoResponse {
    let contents =
        tokio::task::spawn_blocking(|| std::fs::read_to_string("Cargo.toml").unwrap_or_default())
            .await
            .unwrap_or_default();

    (StatusCode::OK, contents)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = AppConfig { version: "0.1.0" };

    let app = Router::new()
        .route("/", get(static_home))
        .route("/status", get(system_status))
        .route("/config", get(safe_blocking_read))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("listening on http://{addr}");
    println!("  /        sync");
    println!("  /status  sync, with state");
    println!("  /config  async, blocking read offloaded to spawn_blocking");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
