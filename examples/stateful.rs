//! Shared state behind an `Arc`, with sub-state extraction via `FromRef`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tachyon_web::{
    Router,
    extract::{FromRef, State},
    response::IntoResponse,
    routing::get,
};

/// No `Clone` derive, deliberately: handlers should share this through the `Arc` rather than
/// copying `db_conn` per request.
struct AppState {
    counter: AtomicU64,
    db_conn: String,
}

#[derive(Clone)]
struct CounterState(Arc<AppState>);

impl FromRef<Arc<AppState>> for CounterState {
    fn from_ref(app_state: &Arc<AppState>) -> Self {
        Self(app_state.clone())
    }
}

async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    format!(
        "Server Status: Active. Connected to database: '{}'",
        state.db_conn
    )
}

async fn visit(State(CounterState(state)): State<CounterState>) -> impl IntoResponse {
    let visits = state.counter.fetch_add(1, Ordering::SeqCst) + 1;
    format!("Total visits: {visits}")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(AppState {
        counter: AtomicU64::new(0),
        db_conn: "postgresql://localhost:5432/my_db".to_string(),
    });

    let app = Router::new()
        .route("/status", get(status))
        .route("/visit", get(visit))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("listening on http://{addr}");
    println!("  /status  full AppState");
    println!("  /visit   counter sub-state via FromRef");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
