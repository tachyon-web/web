//! `hoop` middleware: global vs nested scope, ordering via `hoop_at`, and reading shared
//! state from inside a middleware with `next.state()`.

use std::net::SocketAddr;
use std::time::Instant;
use tachyon_web::http::header::AUTHORIZATION;
use tachyon_web::http::{Request, StatusCode};
use tachyon_web::{
    MiddlewarePosition, Next, Router,
    response::{Body, IntoResponse},
    routing::get,
};

#[derive(Clone)]
struct AppState {
    expected_token: String,
}

async fn request_timer(req: Request<Body>, next: Next<AppState>) -> impl IntoResponse {
    let start = Instant::now();
    let path = req.uri().path().to_owned();

    let response = next.run(req).await;
    println!("timer path={path} elapsed={:?}", start.elapsed());

    response
}

async fn mock_auth(req: Request<Body>, next: Next<AppState>) -> impl IntoResponse {
    let state = next.state();
    let expected_auth_header = format!("Bearer {}", state.expected_token);

    let is_authorized = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|val| val == expected_auth_header);

    if is_authorized {
        next.run(req).await
    } else {
        println!("auth rejected path={}", req.uri().path());
        (
            StatusCode::UNAUTHORIZED,
            "Missing or invalid authorization token",
        )
            .into_response()
    }
}

async fn index() -> &'static str {
    "Welcome! This endpoint is public and does not require authentication."
}

async fn secure_data() -> &'static str {
    "Top-secret database info accessed successfully!"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = AppState {
        expected_token: "secret-token-123".to_string(),
    };

    let secure_router = Router::new()
        .route("/data", get(secure_data))
        .hoop_at(MiddlewarePosition::First, mock_auth);

    // `.hoop` is shorthand for `.hoop_at(MiddlewarePosition::First, ...)`.
    let app = Router::new()
        .route("/", get(index))
        .nest("/secure", secure_router)
        .hoop(request_timer)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("listening on http://{addr}");
    println!("  /                 public, timer only");
    println!("  /secure/data      401 without a token, timer + auth");
    println!("    curl -H \"Authorization: Bearer secret-token-123\" http://{addr}/secure/data");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
