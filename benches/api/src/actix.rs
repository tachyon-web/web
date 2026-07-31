#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use actix_web::{App, HttpResponse, HttpServer, Responder, delete, get, patch, post, web};
use serde::{Deserialize, Serialize};

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

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(Health {
        status: "ok",
        version: "0.1.0",
        uptime_secs: 1234,
    })
}

#[get("/api/v1/users/{id}")]
async fn get_user(path: web::Path<IdParam>) -> impl Responder {
    HttpResponse::Ok().json(User {
        id: path.id,
        name: "Alice Rustacean",
        email: "alice@example.com",
        role: "admin",
        active: true,
        created_at: "2025-01-01T00:00:00Z",
    })
}

#[get("/api/v1/users/{id}/posts")]
async fn get_user_posts(path: web::Path<IdParam>) -> impl Responder {
    let posts: Vec<Post> = (1u64..=5)
        .map(|i| Post {
            id: path.id * 100 + i,
            user_id: path.id,
            title: "How to write fast web servers",
            slug: "fast-web-servers",
        })
        .collect();
    HttpResponse::Ok().json(posts)
}

#[post("/api/v1/users")]
async fn create_user(req: web::Json<CreateUser>) -> impl Responder {
    HttpResponse::Ok().json(CreateUserResp {
        id: 99_999,
        role: req.role.clone().unwrap_or_else(|| "user".to_string()),
        name: req.name.clone(),
        email: req.email.clone(),
        created_at: "2026-06-26T00:00:00Z",
    })
}

#[patch("/api/v1/users/{id}")]
async fn patch_user(path: web::Path<IdParam>, body: web::Json<PatchUser>) -> impl Responder {
    let changed =
        body.name.is_some() as u8 + body.email.is_some() as u8 + body.active.is_some() as u8;
    HttpResponse::Ok().json(PatchUserResp {
        id: path.id,
        updated: true,
        fields_changed: changed,
    })
}

#[delete("/api/v1/users/{id}")]
async fn delete_user(path: web::Path<IdParam>) -> impl Responder {
    HttpResponse::Ok().json(Deleted {
        id: path.id,
        deleted: true,
    })
}

#[get("/api/v1/search")]
async fn search_users(q: web::Query<SearchQuery>) -> impl Responder {
    let page = q.page.unwrap_or(1);
    let per_page = q.per_page.unwrap_or(20).min(100);
    HttpResponse::Ok().json(SearchResult {
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
async fn get_metrics() -> impl Responder {
    let points: Vec<MetricPoint> = (0u64..60)
        .map(|i| MetricPoint {
            ts: 1_750_000_000 + i * 60,
            value: 100.0 + (i as f64).sin() * 25.0,
            label: "req_per_sec",
        })
        .collect();
    HttpResponse::Ok().json(Metrics {
        window: "1h",
        points,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Actix API server listening on 127.0.0.1:8082");
    HttpServer::new(|| {
        App::new()
            .service(health)
            .service(get_user)
            .service(get_user_posts)
            .service(create_user)
            .service(patch_user)
            .service(delete_user)
            .service(search_users)
            .service(get_metrics)
    })
    .bind(("127.0.0.1", 8082))?
    .run()
    .await
}
