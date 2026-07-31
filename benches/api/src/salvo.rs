#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use salvo::prelude::*;
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

#[handler]
async fn health(res: &mut Response) {
    res.render(Json(Health {
        status: "ok",
        version: "0.1.0",
        uptime_secs: 1234,
    }));
}

#[handler]
async fn get_user(req: &mut Request, res: &mut Response) {
    let id = req.param::<u64>("id").unwrap_or(0);
    res.render(Json(User {
        id,
        name: "Alice Rustacean",
        email: "alice@example.com",
        role: "admin",
        active: true,
        created_at: "2025-01-01T00:00:00Z",
    }));
}

#[handler]
async fn get_user_posts(req: &mut Request, res: &mut Response) {
    let id = req.param::<u64>("id").unwrap_or(0);
    let posts: Vec<Post> = (1u64..=5)
        .map(|i| Post {
            id: id * 100 + i,
            user_id: id,
            title: "How to write fast web servers",
            slug: "fast-web-servers",
        })
        .collect();
    res.render(Json(posts));
}

#[handler]
async fn create_user(req: &mut Request, res: &mut Response) {
    let body = req.parse_json::<CreateUser>().await.unwrap();
    res.render(Json(CreateUserResp {
        id: 99_999,
        role: body.role.clone().unwrap_or_else(|| "user".to_string()),
        name: body.name.clone(),
        email: body.email.clone(),
        created_at: "2026-06-26T00:00:00Z",
    }));
}

#[handler]
async fn patch_user(req: &mut Request, res: &mut Response) {
    let id = req.param::<u64>("id").unwrap_or(0);
    let body = req.parse_json::<PatchUser>().await.unwrap();
    let changed =
        body.name.is_some() as u8 + body.email.is_some() as u8 + body.active.is_some() as u8;
    res.render(Json(PatchUserResp {
        id,
        updated: true,
        fields_changed: changed,
    }));
}

#[handler]
async fn delete_user(req: &mut Request, res: &mut Response) {
    let id = req.param::<u64>("id").unwrap_or(0);
    res.render(Json(Deleted { id, deleted: true }));
}

#[handler]
async fn search_users(req: &mut Request, res: &mut Response) {
    let q_val = req.query::<String>("q").unwrap_or_default();
    let page = req.query::<u32>("page").unwrap_or(1);
    let per_page = req.query::<u32>("per_page").unwrap_or(20).min(100);
    res.render(Json(SearchResult {
        query: q_val,
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
    }));
}

#[handler]
async fn get_metrics(res: &mut Response) {
    let points: Vec<MetricPoint> = (0u64..60)
        .map(|i| MetricPoint {
            ts: 1_750_000_000 + i * 60,
            value: 100.0 + (i as f64).sin() * 25.0,
            label: "req_per_sec",
        })
        .collect();
    res.render(Json(Metrics {
        window: "1h",
        points,
    }));
}

#[tokio::main]
async fn main() {
    let router = Router::new()
        .push(Router::with_path("health").get(health))
        .push(
            Router::with_path("api/v1/users/{id}")
                .get(get_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .push(Router::with_path("api/v1/users/{id}/posts").get(get_user_posts))
        .push(Router::with_path("api/v1/users").post(create_user))
        .push(Router::with_path("api/v1/search").get(search_users))
        .push(Router::with_path("api/v1/metrics").get(get_metrics));

    let acceptor = TcpListener::new("127.0.0.1:8084").bind().await;
    println!("Salvo API server on 127.0.0.1:8084");
    Server::new(acceptor).serve(router).await;
}
