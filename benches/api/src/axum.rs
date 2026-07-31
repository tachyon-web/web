#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use axum::extract::{Path, Query};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

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

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: "0.1.0",
        uptime_secs: 1234,
    })
}

async fn get_user(Path(p): Path<IdParam>) -> Json<User> {
    Json(User {
        id: p.id,
        name: "Alice Rustacean",
        email: "alice@example.com",
        role: "admin",
        active: true,
        created_at: "2025-01-01T00:00:00Z",
    })
}

async fn get_user_posts(Path(p): Path<IdParam>) -> Json<Vec<Post>> {
    Json(
        (1u64..=5)
            .map(|i| Post {
                id: p.id * 100 + i,
                user_id: p.id,
                title: "How to write fast web servers",
                slug: "fast-web-servers",
            })
            .collect(),
    )
}

async fn create_user(Json(req): Json<CreateUser>) -> Json<CreateUserResp> {
    Json(CreateUserResp {
        id: 99_999,
        role: req.role.unwrap_or_else(|| "user".to_string()),
        name: req.name,
        email: req.email,
        created_at: "2026-06-26T00:00:00Z",
    })
}

async fn patch_user(Path(p): Path<IdParam>, Json(body): Json<PatchUser>) -> Json<PatchUserResp> {
    let changed =
        body.name.is_some() as u8 + body.email.is_some() as u8 + body.active.is_some() as u8;
    Json(PatchUserResp {
        id: p.id,
        updated: true,
        fields_changed: changed,
    })
}

async fn delete_user(Path(p): Path<IdParam>) -> Json<Deleted> {
    Json(Deleted {
        id: p.id,
        deleted: true,
    })
}

async fn search_users(Query(q): Query<SearchQuery>) -> Json<SearchResult> {
    let page = q.page.unwrap_or(1);
    let per_page = q.per_page.unwrap_or(20).min(100);
    Json(SearchResult {
        query: q.q,
        page,
        per_page,
        total: 1337,
        results: (0..3)
            .map(|i| User {
                id: i + 1,
                name: "Alice Rustacean",
                email: "alice@example.com",
                role: "user",
                active: true,
                created_at: "2025-06-01T00:00:00Z",
            })
            .collect(),
    })
}

async fn get_metrics() -> Json<Metrics> {
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
            "/api/v1/users/{id}",
            get(get_user).patch(patch_user).delete(delete_user),
        )
        .route("/api/v1/users/{id}/posts", get(get_user_posts))
        .route("/api/v1/users", post(create_user))
        .route("/api/v1/search", get(search_users))
        .route("/api/v1/metrics", get(get_metrics));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Axum API server on {addr}");
    axum::serve(listener, app).await.unwrap();
}
