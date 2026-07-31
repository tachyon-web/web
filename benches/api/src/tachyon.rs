#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use serde::{Deserialize, Serialize};

use tachyon_web::http::response::{IntoResponse, Json};
use tachyon_web::routing::extract::{Path, Query};
use tachyon_web::routing::{Router, get, post};

// ─── Common types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IdParam {
    id: u64,
}

#[derive(Serialize)]
struct User {
    id: u64,
    name: &'static str,
    email: &'static str,
    role: &'static str,
    active: bool,
    created_at: &'static str,
}

#[derive(Deserialize)]
struct CreateUser {
    name: String,
    email: String,
    role: Option<String>,
}

#[derive(Serialize)]
struct CreateUserResp {
    id: u64,
    name: String,
    email: String,
    role: String,
    created_at: &'static str,
}

#[derive(Deserialize)]
struct PatchUser {
    name: Option<String>,
    email: Option<String>,
    active: Option<bool>,
}

#[derive(Serialize)]
struct PatchUserResp {
    id: u64,
    updated: bool,
    fields_changed: u8,
}

#[derive(Serialize)]
struct Post {
    id: u64,
    user_id: u64,
    title: &'static str,
    slug: &'static str,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    page: Option<u32>,
    per_page: Option<u32>,
}

#[derive(Serialize)]
struct SearchResult {
    query: String,
    page: u32,
    per_page: u32,
    total: u64,
    results: Vec<User>,
}

#[derive(Serialize)]
struct MetricPoint {
    ts: u64,
    value: f64,
    label: &'static str,
}

#[derive(Serialize)]
struct Metrics {
    window: &'static str,
    points: Vec<MetricPoint>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct Deleted {
    id: u64,
    deleted: bool,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    Json(Health {
        status: "ok",
        version: "0.1.0",
        uptime_secs: 1234,
    })
}

async fn get_user(Path(p): Path<IdParam>) -> impl IntoResponse {
    Json(User {
        id: p.id,
        name: "Alice Rustacean",
        email: "alice@example.com",
        role: "admin",
        active: true,
        created_at: "2025-01-01T00:00:00Z",
    })
}

async fn get_user_posts(Path(p): Path<IdParam>) -> impl IntoResponse {
    let posts: Vec<Post> = (1u64..=5)
        .map(|i| Post {
            id: p.id * 100 + i,
            user_id: p.id,
            title: "How to write fast web servers",
            slug: "fast-web-servers",
        })
        .collect();
    Json(posts)
}

async fn create_user(
    tachyon_web::routing::extract::Json(req): tachyon_web::routing::extract::Json<CreateUser>,
) -> impl IntoResponse {
    Json(CreateUserResp {
        id: 99_999,
        role: req.role.unwrap_or_else(|| "user".to_string()),
        name: req.name,
        email: req.email,
        created_at: "2026-06-26T00:00:00Z",
    })
}

async fn patch_user(
    Path(p): Path<IdParam>,
    tachyon_web::routing::extract::Json(body): tachyon_web::routing::extract::Json<PatchUser>,
) -> impl IntoResponse {
    let changed =
        body.name.is_some() as u8 + body.email.is_some() as u8 + body.active.is_some() as u8;
    Json(PatchUserResp {
        id: p.id,
        updated: true,
        fields_changed: changed,
    })
}

async fn delete_user(Path(p): Path<IdParam>) -> impl IntoResponse {
    Json(Deleted {
        id: p.id,
        deleted: true,
    })
}

async fn search_users(Query(q): Query<SearchQuery>) -> impl IntoResponse {
    let page = q.page.unwrap_or(1);
    let per_page = q.per_page.unwrap_or(20).min(100);
    let results: Vec<User> = (0..3)
        .map(|i| User {
            id: i + 1,
            name: "Alice Rustacean",
            email: "alice@example.com",
            role: "user",
            active: true,
            created_at: "2025-06-01T00:00:00Z",
        })
        .collect();
    Json(SearchResult {
        query: q.q,
        page,
        per_page,
        total: 1337,
        results,
    })
}

async fn get_metrics() -> impl IntoResponse {
    let points: Vec<MetricPoint> = (0u64..60)
        .map(|i| MetricPoint {
            ts: 1_750_000_000 + i * 60,
            value: 100.0 + (i as f64).sin() * 25.0,
            label: "req_per_sec",
        })
        .collect();
    Json(Metrics {
        window: "1h",
        points,
    })
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/api/v1/users/:id",
            get(get_user).patch(patch_user).delete(delete_user),
        )
        .route("/api/v1/users/:id/posts", get(get_user_posts))
        .route("/api/v1/users", post(create_user))
        .route("/api/v1/search", get(search_users))
        .route("/api/v1/metrics", get(get_metrics));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Tachyon API server on {}", addr);
    tachyon_web::serve(listener, app).await.unwrap();
}
