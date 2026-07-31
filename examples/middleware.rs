//! An example demonstrating custom Tachyon-Web `hoop` middleware, showcasing:
//! 1. Global vs Scoped/Nested middleware execution scopes.
//! 2. Custom execution ordering via `hoop_at`.
//! 3. Shared application state access inside middlewares via `next.state()`.

use std::net::SocketAddr;
use std::time::Instant;
use tachyon_web::http::header::AUTHORIZATION;
use tachyon_web::http::{Request, StatusCode};
use tachyon_web::{
    MiddlewarePosition, Next, Router,
    response::{Body, IntoResponse},
    routing::get,
};

// ─── Shared State ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    expected_token: String,
}

// ─── Middleware Handlers ──────────────────────────────────────────────────────

/// A logging middleware that measures request duration.
/// Applied globally on the main router to run on all endpoints.
async fn request_timer(req: Request<Body>, next: Next<AppState>) -> impl IntoResponse {
    let start = Instant::now();
    let path = req.uri().path().to_owned();

    println!("⏱️  [Timer Middleware] Entering for path: {path}");
    let response = next.run(req).await;
    println!(
        "⏱️  [Timer Middleware] Exiting for path: {}: took {:?}",
        path,
        start.elapsed()
    );

    response
}

/// An authentication middleware that checks for a bearer token in the headers.
/// Applied only on the secure nested router to protect specific endpoints.
async fn mock_auth(req: Request<Body>, next: Next<AppState>) -> impl IntoResponse {
    let path = req.uri().path().to_owned();
    println!("🔑 [Auth Middleware] Checking authorization for: {path}");

    // Retrieve state safely and quickly using `next.state()`.
    let state = next.state();
    let expected_auth_header = format!("Bearer {}", state.expected_token);

    let is_authorized = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|val| val == expected_auth_header);

    if is_authorized {
        println!("🔑 [Auth Middleware] Authorized successfully!");
        next.run(req).await
    } else {
        println!("🔑 [Auth Middleware] Authorization failed!");
        (
            StatusCode::UNAUTHORIZED,
            "Missing or invalid authorization token",
        )
            .into_response()
    }
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

async fn index() -> &'static str {
    "Welcome! This endpoint is public and does not require authentication."
}

async fn secure_data() -> &'static str {
    "Top-secret database info accessed successfully!"
}

// ─── Main Server Entrypoint ───────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = AppState {
        expected_token: "secret-token-123".to_string(),
    };

    // 1. Build a nested secure router and protect its endpoints with `mock_auth`.
    // We use `hoop_at` here to control the position of `mock_auth`.
    let secure_router = Router::new()
        .route("/data", get(secure_data))
        .hoop_at(MiddlewarePosition::First, mock_auth);

    // 2. Build the main application router.
    // - Nest the secure router under the "/secure" path.
    // - Apply the `request_timer` globally via the standard `.hoop` method.
    // - Attach the shared application state.
    let app = Router::new()
        .route("/", get(index))
        .nest("/secure", secure_router)
        // .hoop is a shorthand for .hoop_at(MiddlewarePosition::First, ...)
        .hoop(request_timer)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("🚀 Stateful & Ordered Scoped Middleware server running at http://{addr}");
    println!("  - Visit public endpoint (bypasses auth, runs only timer): http://{addr}");
    println!(
        "  - Visit secure endpoint (returns 401, runs timer + auth): http://{addr}/secure/data"
    );
    println!("  - Test with valid token via curl (runs timer + auth):");
    println!("    curl -H \"Authorization: Bearer secret-token-123\" http://{addr}/secure/data");

    // Bind listener and run the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
