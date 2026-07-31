//! A complete example demonstrating synchronous (sync) handlers in Tachyon-Web.
//!
//! This example shows:
//! 1. How to use synchronous handlers to achieve true zero-allocation (heap-free) routing.
//! 2. How parameter extraction works seamlessly in synchronous contexts.
//! 3. The critical difference between non-blocking CPU operations and blocking I/O.
//! 4. How to safely offload blocking tasks to Tokio's dedicated blocking pool.
//!
//! # ⚠️ Critical Performance & Thread-Safety Note
//! Because Tachyon runs on a cooperative async runtime (Tokio), running blocking code in a
//! normal handler (sync or async) will freeze the Tokio worker thread, stalling other requests.
//! ONLY use synchronous handlers for quick, non-blocking calculations or returning static responses.

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

// ─── Shared Application State ──────────────────────────────────────────────────

#[derive(Clone)]
struct AppConfig {
    version: &'static str,
}

#[derive(Serialize)]
struct SystemStatus {
    version: &'static str,
    timestamp: u128,
}

// ─── 1. Instant / Non-Blocking Sync Handlers (SAFE & RECOMMENDED) ──────────────
// These perform quick, CPU-bound computations and return immediately.
// Because they are synchronous, Tachyon resolves them without any future allocation.

/// Returns a static HTML page synchronously with zero allocations.
const fn static_home() -> Html<&'static str> {
    Html("<h1>Tachyon-Web Synchronous Handler Demo</h1><p>Fast, heap-free, and safe.</p>")
}

/// Dynamically reads system state and parameters synchronously.
/// Since it has no yields or waits, it remains completely non-blocking.
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

// ─── 2. Blocking I/O (⚠️ BAD PRACTICE inside Sync Handlers) ────────────────────

/// DONT DO THIS: Reading a file synchronously blocks the event loop thread!
/// If multiple requests hit this endpoint, the whole server could stall.
#[allow(dead_code)]
fn dangerous_blocking_read() -> String {
    // This blocks the thread for milliseconds!
    std::fs::read_to_string("config.toml").unwrap_or_default()
}

// ─── 3. Safe Offloading of Blocking Work (RECOMMENDED) ────────────────────────

/// DO THIS: Use `tokio::task::spawn_blocking` to run blocking operations
/// off of the main event loop worker threads.
async fn safe_blocking_read() -> impl IntoResponse {
    // Offloads the heavy blocking operation to Tokio's dedicated blocking pool.
    // The main worker thread is freed up to process other requests in the meantime.
    let contents =
        tokio::task::spawn_blocking(|| std::fs::read_to_string("Cargo.toml").unwrap_or_default())
            .await
            .unwrap_or_default();

    (StatusCode::OK, contents)
}

// ─── Main Server Entrypoint ───────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = AppConfig { version: "0.1.0" };

    // Build the Router using both sync and async routes
    let app = Router::new()
        // / and /status are processed synchronously without any Future or Box allocations:
        .route("/", get(static_home))
        .route("/status", get(system_status))
        // /config offloads the blocking disk I/O safely to the blocking thread pool:
        .route("/config", get(safe_blocking_read))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("🚀 Tachyon server running at http://{addr}");
    println!("  - http://{addr}/         [Sync, Zero-Allocation]");
    println!("  - http://{addr}/status   [Sync + State, Zero-Allocation]");
    println!("  - http://{addr}/config   [Async, Offloaded Blocking I/O]");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
