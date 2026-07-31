#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[macro_use]
extern crate rocket;
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};

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

#[derive(FromForm, Deserialize)]
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

#[get("/health")]
fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: "0.1.0",
        uptime_secs: 1234,
    })
}

#[get("/api/v1/users/<id>")]
fn get_user(id: u64) -> Json<User> {
    Json(User {
        id,
        name: "Alice Rustacean",
        email: "alice@example.com",
        role: "admin",
        active: true,
        created_at: "2025-01-01T00:00:00Z",
    })
}

#[get("/api/v1/users/<id>/posts")]
fn get_user_posts(id: u64) -> Json<Vec<Post>> {
    let posts: Vec<Post> = (1u64..=5)
        .map(|i| Post {
            id: id * 100 + i,
            user_id: id,
            title: "How to write fast web servers",
            slug: "fast-web-servers",
        })
        .collect();
    Json(posts)
}

#[post("/api/v1/users", data = "<body>")]
fn create_user(body: Json<CreateUser>) -> Json<CreateUserResp> {
    Json(CreateUserResp {
        id: 99_999,
        role: body.role.clone().unwrap_or_else(|| "user".to_string()),
        name: body.name.clone(),
        email: body.email.clone(),
        created_at: "2026-06-26T00:00:00Z",
    })
}

#[patch("/api/v1/users/<id>", data = "<body>")]
fn patch_user(id: u64, body: Json<PatchUser>) -> Json<PatchUserResp> {
    let changed =
        body.name.is_some() as u8 + body.email.is_some() as u8 + body.active.is_some() as u8;
    Json(PatchUserResp {
        id,
        updated: true,
        fields_changed: changed,
    })
}

#[delete("/api/v1/users/<id>")]
fn delete_user(id: u64) -> Json<Deleted> {
    Json(Deleted { id, deleted: true })
}

#[get("/api/v1/search?<q..>")]
fn search_users(q: SearchQuery) -> Json<SearchResult> {
    let page = q.page.unwrap_or(1);
    let per_page = q.per_page.unwrap_or(20).min(100);
    Json(SearchResult {
        query: q.q.clone(),
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

#[get("/api/v1/metrics")]
fn get_metrics() -> Json<Metrics> {
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

#[launch]
fn rocket() -> _ {
    let config = rocket::Config::figment()
        .merge(("port", 8083))
        .merge(("address", "127.0.0.1"))
        .merge(("log_level", rocket::config::LogLevel::Off));
    rocket::custom(config).mount(
        "/",
        routes![
            health,
            get_user,
            get_user_posts,
            create_user,
            patch_user,
            delete_user,
            search_users,
            get_metrics,
        ],
    )
}
