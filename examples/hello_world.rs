//! Routing, path/query extraction, JSON payloads, custom status codes.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tachyon_web::http::StatusCode;
use tachyon_web::{
    Router,
    extract::{Json, Path, Query},
    response::{Html, IntoResponse},
    routing::{get, post},
};

#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

const fn default_limit() -> usize {
    10
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: u64,
    username: String,
    email: String,
    status: &'static str,
}

async fn index() -> Html<&'static str> {
    Html("<h1>Welcome to Tachyon-Web!</h1><p>Check out the rest of the endpoints.</p>")
}

async fn greet(Path(name): Path<String>) -> String {
    format!("Hello, {name}!")
}

async fn search(Query(query): Query<SearchQuery>) -> impl IntoResponse {
    format!("Search results for: '{}' (limit: {})", query.q, query.limit)
}

async fn create_user(Json(payload): Json<CreateUserRequest>) -> impl IntoResponse {
    let user = UserResponse {
        id: 42,
        username: payload.username,
        email: payload.email,
        status: "active",
    };

    (StatusCode::CREATED, Json(user))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", get(index))
        .route("/hello/:name", get(greet))
        .route("/search", get(search))
        .route("/api/users", post(create_user));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tachyon_web::serve(listener, app).await?;

    Ok(())
}
