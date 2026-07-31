//! A stateful application example demonstrating shared state,
//! thread-safe updates, and sub-state extraction using the `FromRef` pattern.
//!
//! This example shows the best practices for zero-allocation state management:
//! 1. Wrapping the application state in an `Arc` to make state cloning a cheap reference-count increment.
//! 2. Avoiding `Clone` on the main state struct to prevent accidental heavy clones.
//! 3. Utilizing the `FromRef` pattern to extract specific parts of the state.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tachyon_web::{
    Router,
    extract::{FromRef, State},
    response::IntoResponse,
    routing::get,
};

// ─── App State Definition ────────────────────────────────────────────────────

/// The main application state.
/// We intentionally omit deriving `Clone` on `AppState` to prevent developers
/// from accidentally cloning the heavy `db_conn` string on every request.
struct AppState {
    // Shared thread-safe counter
    counter: AtomicU64,
    // Simulated database connection string (heavy field)
    db_conn: String,
}

/// A sub-state extracted from `Arc<AppState>`.
#[derive(Clone)]
struct CounterState(Arc<AppState>);

// Implement `FromRef` to allow handlers to extract a cheap clone of the sub-state.
impl FromRef<Arc<AppState>> for CounterState {
    fn from_ref(app_state: &Arc<AppState>) -> Self {
        Self(app_state.clone())
    }
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

/// Handler that accesses the full `AppState` by wrapping it in `Arc`.
/// Cloning `Arc<AppState>` only increments a reference count and does not allocate.
async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    format!(
        "Server Status: Active. Connected to database: '{}'",
        state.db_conn
    )
}

/// Handler that extracts and updates only the `CounterState` sub-state.
async fn visit(State(CounterState(state)): State<CounterState>) -> impl IntoResponse {
    let visits = state.counter.fetch_add(1, Ordering::SeqCst) + 1;
    format!("Total visits: {visits}")
}

// ─── Main Server Entrypoint ───────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize our shared state wrapped in an Arc.
    // This allows the router and handlers to share the state with zero heap allocations at request time.
    let state = Arc::new(AppState {
        counter: AtomicU64::new(0),
        db_conn: "postgresql://localhost:5432/my_db".to_string(),
    });

    // Build the Router and attach the state
    let app = Router::new()
        .route("/status", get(status))
        .route("/visit", get(visit))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("🚀 Stateful server running at http://{addr}");
    println!("  - http://{addr}/status   [Accesses full AppState via Arc]");
    println!("  - http://{addr}/visit    [Accesses counter sub-state via FromRef]");

    // Bind listener and run the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
