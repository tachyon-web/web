//! Comprehensive integration tests covering correctness, security, and edge cases.
//!
//! These tests spin up real in-process HTTP servers and exercise the framework
//! through a full network stack using `reqwest`.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::items_after_statements,
    clippy::use_self,
    clippy::semicolon_if_nothing_returned,
    clippy::similar_names
)]

use bytes::Bytes;
use hyper::{Request, StatusCode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tachyon_web::{
    Router, Server, get,
    http::response::{Body, Html, Json},
    post,
    routing::extract::{Form, Path, Query, State},
};
use tokio::net::TcpListener;

// ─── helpers ──────────────────────────────────────────────────────────────────

async fn spawn_server(router: Router<()>) -> (u16, tokio::task::JoinHandle<()>) {
    let app = router.with_state(());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let server = Server::new(app);
    let handle = tokio::spawn(async move {
        server.serve_http(listener).await.expect("serve_http");
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (port, handle)
}

fn client() -> Client {
    Client::new()
}

// ─── Basic routing ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_root() {
    async fn handler() -> &'static str {
        "hello"
    }
    let (port, _h) = spawn_server(Router::new().route("/", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "hello");
}

#[tokio::test]
async fn test_method_not_allowed_returns_405_with_allow() {
    async fn handler() -> &'static str {
        "ok"
    }
    let (port, _h) = spawn_server(Router::new().route("/only-get", get(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/only-get", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405);
    let allow = res.headers().get("allow").expect("Allow header");
    assert!(allow.to_str().unwrap().contains("GET"));
}

#[tokio::test]
async fn test_not_found_returns_404() {
    async fn handler() -> &'static str {
        "ok"
    }
    let (port, _h) = spawn_server(Router::new().route("/exists", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/nope", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn test_all_http_methods() {
    async fn handler() -> &'static str {
        "ok"
    }
    let router = Router::new().route(
        "/multi",
        get(handler)
            .post(handler)
            .put(handler)
            .delete(handler)
            .patch(handler),
    );
    let (port, _h) = spawn_server(router).await;
    let base = format!("http://127.0.0.1:{}/multi", port);
    let c = client();
    for (method, req) in [
        ("GET", c.get(&base).build().unwrap()),
        ("POST", c.post(&base).build().unwrap()),
        ("PUT", c.put(&base).build().unwrap()),
        ("DELETE", c.delete(&base).build().unwrap()),
        ("PATCH", c.patch(&base).build().unwrap()),
    ] {
        let res = c.execute(req).await.unwrap();
        assert_eq!(res.status(), 200, "{method} should be 200");
    }
}

// ─── Path parameters ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct UserParams {
    id: u32,
    name: String,
}

#[tokio::test]
async fn test_path_params_deserialized() {
    async fn handler(Path(p): Path<UserParams>) -> Json<UserParams> {
        Json(p)
    }
    let (port, _h) = spawn_server(Router::new().route("/user/:id/:name", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/user/42/alice", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let user: UserParams = res.json().await.unwrap();
    assert_eq!(user.id, 42);
    assert_eq!(user.name, "alice");
}

#[tokio::test]
async fn test_path_param_type_mismatch_returns_400() {
    async fn handler(Path(p): Path<UserParams>) -> Json<UserParams> {
        Json(p)
    }
    let (port, _h) = spawn_server(Router::new().route("/user/:id/:name", get(handler))).await;
    // "abc" can't parse as u32
    let res = client()
        .get(format!("http://127.0.0.1:{}/user/abc/bob", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

// ─── Query parameters ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: String,
    page: Option<u32>,
}

#[tokio::test]
async fn test_query_extraction() {
    async fn handler(Query(q): Query<SearchQuery>) -> String {
        format!("q={} page={}", q.q, q.page.unwrap_or(1))
    }
    let (port, _h) = spawn_server(Router::new().route("/search", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/search?q=rust&page=3", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "q=rust page=3");
}

#[tokio::test]
async fn test_query_url_encoded() {
    async fn handler(Query(q): Query<SearchQuery>) -> String {
        q.q
    }
    let (port, _h) = spawn_server(Router::new().route("/search", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/search?q=hello+world", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "hello world");
}

#[tokio::test]
async fn test_query_percent_encoded() {
    async fn handler(Query(q): Query<SearchQuery>) -> String {
        q.q
    }
    let (port, _h) = spawn_server(Router::new().route("/search", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/search?q=foo%20bar", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "foo bar");
}

// ─── JSON extractor ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct Payload {
    value: String,
}

#[tokio::test]
async fn test_json_extractor_ok() {
    async fn handler(tachyon_web::Json(p): tachyon_web::Json<Payload>) -> Json<Payload> {
        Json(p)
    }
    let (port, _h) = spawn_server(Router::new().route("/echo", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/echo", port))
        .json(&Payload {
            value: "test".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let p: Payload = res.json().await.unwrap();
    assert_eq!(p.value, "test");
}

#[tokio::test]
async fn test_json_extractor_wrong_content_type_415() {
    async fn handler(tachyon_web::Json(p): tachyon_web::Json<Payload>) -> Json<Payload> {
        Json(p)
    }
    let (port, _h) = spawn_server(Router::new().route("/echo", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/echo", port))
        .header("content-type", "text/plain")
        .body("{\"value\":\"test\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 415, "wrong content-type must return 415");
}

#[tokio::test]
async fn test_json_extractor_syntax_error_400() {
    // Matches Axum's `JsonRejection`: invalid JSON *syntax* is a 400 Bad Request,
    // distinct from valid JSON that doesn't match the target type's shape (422 —
    // see `test_json_extractor_data_error_422` below).
    async fn handler(tachyon_web::Json(p): tachyon_web::Json<Payload>) -> Json<Payload> {
        Json(p)
    }
    let (port, _h) = spawn_server(Router::new().route("/echo", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/echo", port))
        .header("content-type", "application/json")
        .body("not json at all !!!")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400, "malformed JSON syntax must return 400");
}

#[tokio::test]
async fn test_json_extractor_data_error_422() {
    // Well-formed JSON that doesn't match the target type (missing required field)
    // is a 422 Unprocessable Entity, matching Axum.
    async fn handler(tachyon_web::Json(p): tachyon_web::Json<Payload>) -> Json<Payload> {
        Json(p)
    }
    let (port, _h) = spawn_server(Router::new().route("/echo", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/echo", port))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        422,
        "valid JSON with the wrong shape must return 422"
    );
}

// ─── Form extractor ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct FormData {
    username: String,
    age: u8,
}

#[tokio::test]
async fn test_form_extractor_ok() {
    async fn handler(Form(f): Form<FormData>) -> Json<FormData> {
        Json(f)
    }
    let (port, _h) = spawn_server(Router::new().route("/form", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/form", port))
        .form(&[("username", "alice"), ("age", "30")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let f: FormData = res.json().await.unwrap();
    assert_eq!(f.username, "alice");
    assert_eq!(f.age, 30);
}

#[tokio::test]
async fn test_form_extractor_wrong_content_type_415() {
    async fn handler(Form(f): Form<FormData>) -> Json<FormData> {
        Json(f)
    }
    let (port, _h) = spawn_server(Router::new().route("/form", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/form", port))
        .header("content-type", "application/json")
        .body("username=alice&age=30")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 415);
}

// ─── State extractor ──────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct AppState {
    greeting: String,
}

#[tokio::test]
async fn test_state_extractor() {
    async fn handler(State(s): State<AppState>) -> String {
        s.greeting
    }
    let app = Router::new()
        .route("/greet", get(handler))
        .with_state(AppState {
            greeting: "howdy".into(),
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _h = tokio::spawn(async move { Server::new(app).serve_http(listener).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/greet", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "howdy");
}

// ─── Response types ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_html_response_content_type() {
    async fn handler() -> Html<&'static str> {
        Html("<h1>hi</h1>")
    }
    let (port, _h) = spawn_server(Router::new().route("/", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await
        .unwrap();
    let ct = res.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("text/html"), "ct: {ct}");
}

#[tokio::test]
async fn test_status_code_response() {
    async fn handler() -> StatusCode {
        StatusCode::CREATED
    }
    let (port, _h) = spawn_server(Router::new().route("/create", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/create", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
}

#[tokio::test]
async fn test_tuple_status_response() {
    async fn handler() -> (StatusCode, &'static str) {
        (StatusCode::ACCEPTED, "accepted")
    }
    let (port, _h) = spawn_server(Router::new().route("/acc", post(handler))).await;
    let res = client()
        .post(format!("http://127.0.0.1:{}/acc", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    assert_eq!(res.text().await.unwrap(), "accepted");
}

// ─── Body size limits ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_oversized_body_returns_413() {
    async fn handler(tachyon_web::Json(_p): tachyon_web::Json<Payload>) -> &'static str {
        "ok"
    }
    let app = Router::new().route("/upload", post(handler)).with_state(());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _h = tokio::spawn(async move {
        Server::new(app)
            .max_body_size(100) // tiny limit
            .serve_http(listener)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    // Send 200 bytes of JSON (exceeds 100-byte limit)
    let big_value = "x".repeat(200);
    let res = client()
        .post(format!("http://127.0.0.1:{}/upload", port))
        .header("content-type", "application/json")
        .body(format!("{{\"value\":\"{big_value}\"}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 413, "oversized body must return 413");
}

#[tokio::test]
async fn test_default_body_limit_override_is_stricter_than_server_default() {
    use tachyon_web::routing::extract::DefaultBodyLimit;

    async fn handler(tachyon_web::Json(_p): tachyon_web::Json<Payload>) -> &'static str {
        "ok"
    }

    // Server-wide limit is generous (1 MiB); the route overrides it down to 10 bytes.
    let app = Router::new()
        .route("/upload", post(handler))
        .hoop(DefaultBodyLimit::max(10).into_middleware())
        .with_state(());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _h = tokio::spawn(async move {
        Server::new(app)
            .max_body_size(1024 * 1024)
            .serve_http(listener)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let res = client()
        .post(format!("http://127.0.0.1:{}/upload", port))
        .header("content-type", "application/json")
        .body("{\"value\":\"this is well under 1 MiB\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        413,
        "route-level DefaultBodyLimit::max(10) must override the server's 1 MiB default"
    );
}

#[tokio::test]
async fn test_default_body_limit_disable_allows_large_body() {
    use tachyon_web::routing::extract::DefaultBodyLimit;

    async fn handler(tachyon_web::Json(_p): tachyon_web::Json<Payload>) -> &'static str {
        "ok"
    }

    // Server-wide limit is tiny; the route disables it entirely.
    let app = Router::new()
        .route("/upload", post(handler))
        .hoop(DefaultBodyLimit::disable().into_middleware())
        .with_state(());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _h = tokio::spawn(async move {
        Server::new(app)
            .max_body_size(10)
            .serve_http(listener)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let big_value = "x".repeat(2000);
    let res = client()
        .post(format!("http://127.0.0.1:{}/upload", port))
        .header("content-type", "application/json")
        .body(format!("{{\"value\":\"{big_value}\"}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        200,
        "DefaultBodyLimit::disable() must lift the server's 10-byte default"
    );
}

// ─── Trailing slash strictness (matches Axum: /foo and /foo/ are distinct) ───

#[tokio::test]
async fn test_trailing_slash_not_stripped_e2e() {
    async fn handler() -> &'static str {
        "ok"
    }
    let (port, _h) = spawn_server(Router::new().route("/no-slash", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/no-slash/", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn test_trailing_slash_not_added_e2e() {
    async fn handler() -> &'static str {
        "ok"
    }
    let (port, _h) = spawn_server(Router::new().route("/with-slash/", get(handler))).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/with-slash", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

// ─── Nested router ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_nested_router_e2e() {
    async fn v1_status() -> &'static str {
        "v1 ok"
    }
    async fn v2_status() -> &'static str {
        "v2 ok"
    }
    let v1 = Router::new().route("/status", get(v1_status));
    let v2 = Router::new().route("/status", get(v2_status));
    let app = Router::new().nest("/api/v1", v1).nest("/api/v2", v2);
    let (port, _h) = spawn_server(app).await;
    let c = client();
    let r1 = c
        .get(format!("http://127.0.0.1:{}/api/v1/status", port))
        .send()
        .await
        .unwrap();
    let r2 = c
        .get(format!("http://127.0.0.1:{}/api/v2/status", port))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.text().await.unwrap(), "v1 ok");
    assert_eq!(r2.text().await.unwrap(), "v2 ok");
}

// ─── Custom fallback ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_custom_fallback_e2e() {
    async fn handler() -> &'static str {
        "ok"
    }
    let app = Router::new()
        .route("/exists", get(handler))
        .fallback(|_req: Request<Bytes>| async { (StatusCode::NOT_FOUND, "custom 404") });
    let (port, _h) = spawn_server(app).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/missing", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.text().await.unwrap(), "custom 404");
}

// ─── serve_file ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_serve_file_static() {
    let dir = tempfile::tempdir().unwrap();
    let fpath = dir.path().join("hello.txt");
    std::fs::write(&fpath, b"hello from file").unwrap();
    let app = Router::new()
        .serve_file("/hello", fpath.to_str().unwrap())
        .expect("serve_file");
    let (port, _h) = spawn_server(app).await;
    let res = client()
        .get(format!("http://127.0.0.1:{}/hello", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "hello from file");
}

#[tokio::test]
async fn test_serve_file_missing_returns_err() {
    let result = Router::<()>::new().serve_file("/missing", "/nonexistent/path/file.txt");
    assert!(
        result.is_err(),
        "serve_file on missing file must return Err"
    );
}

// ─── Path traversal (security) ───────────────────────────────────────────────

#[tokio::test]
async fn test_static_dir_path_traversal_blocked() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("safe.txt"), b"safe").unwrap();
    let serve = tachyon_web::ServeDir::new(dir.path())
        .preload()
        .await
        .unwrap();
    let app = Router::new().serve_dir("/files", serve);
    let (port, _h) = spawn_server(app).await;
    // Attempt directory traversal via path param
    let res = client()
        .get(format!("http://127.0.0.1:{}/files/../../etc/passwd", port))
        .send()
        .await
        .unwrap();
    assert!(
        res.status() == 403 || res.status() == 404,
        "traversal must be blocked: {}",
        res.status()
    );
}

// ─── Concurrent requests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_concurrent_requests() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let counter = Arc::new(AtomicUsize::new(0));
    let counter2 = counter.clone();

    // We can't easily pass the Arc into a static handler so use State instead.
    #[derive(Clone)]
    struct Ctr(Arc<AtomicUsize>);

    impl Default for Ctr {
        fn default() -> Self {
            Ctr(Arc::new(AtomicUsize::new(0)))
        }
    }

    async fn handler(State(c): State<Ctr>) -> String {
        let n = c.0.fetch_add(1, Ordering::SeqCst);
        n.to_string()
    }

    let app = Router::new()
        .route("/count", get(handler))
        .with_state(Ctr(counter2));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _h = tokio::spawn(async move { Server::new(app).serve_http(listener).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let c = Arc::new(client());
    let mut handles = Vec::new();
    for _ in 0..50 {
        let c2 = c.clone();
        let url = format!("http://127.0.0.1:{}/count", port);
        handles.push(tokio::spawn(async move {
            c2.get(url).send().await.unwrap().status()
        }));
    }
    let results: Vec<_> = futures::future::join_all(handles).await;
    let success = results
        .iter()
        .filter(|r| r.as_ref().unwrap() == &StatusCode::OK)
        .count();
    assert_eq!(success, 50, "all 50 concurrent requests must succeed");
    assert_eq!(counter.load(Ordering::SeqCst), 50);
}

// ─── Unit-level extractor tests (no network) ─────────────────────────────────

mod extractor_unit {
    use super::*;
    use tachyon_web::routing::extract::{Cookies, FromRequest, PathParams};

    fn make_req_with_body(method: &str, uri: &str, ct: &str, body: &[u8]) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", ct)
            .body(Body::full(Bytes::copy_from_slice(body)))
            .unwrap()
    }

    #[tokio::test]
    async fn json_rejects_wrong_content_type() {
        let req = make_req_with_body("POST", "/", "text/plain", b"{\"value\":\"x\"}");
        let result = tachyon_web::Json::<Payload>::from_request(req, &()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let resp = tachyon_web::IntoResponse::into_response(err);
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn form_rejects_json_content_type() {
        let req = make_req_with_body("POST", "/", "application/json", b"username=alice&age=30");
        let result = Form::<FormData>::from_request(req, &()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cookies_extractor_parses_header() {
        let req = Request::builder()
            .uri("/")
            .header("cookie", "session=abc123; theme=dark")
            .body(Body::empty())
            .unwrap();
        let cookies = Cookies::from_request(req, &()).await.unwrap();
        assert_eq!(cookies.get("session").unwrap().value(), "abc123");
        assert_eq!(cookies.get("theme").unwrap().value(), "dark");
    }

    #[tokio::test]
    async fn extension_extractor_ok() {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let _ = req.extensions_mut().insert(42u32);
        let ext = tachyon_web::Extension::<u32>::from_request(req, &())
            .await
            .unwrap();
        assert_eq!(ext.0, 42u32);
    }

    #[tokio::test]
    async fn extension_extractor_missing_returns_500() {
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let result = tachyon_web::Extension::<u32>::from_request(req, &()).await;
        let resp = tachyon_web::IntoResponse::into_response(result.unwrap_err());
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn path_extractor_missing_returns_400() {
        let req = Request::builder()
            .uri("/user/1")
            .body(Body::empty())
            .unwrap();
        let result = Path::<UserParams>::from_request(req, &()).await;
        let resp = tachyon_web::IntoResponse::into_response(result.unwrap_err());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn path_extractor_type_error_returns_400() {
        let mut req = Request::builder()
            .uri("/user/abc/bob")
            .body(Body::empty())
            .unwrap();
        // Insert params with invalid type for `id`
        let _ = req.extensions_mut().insert(PathParams(vec![
            ("id".into(), "not-a-number".into()),
            ("name".into(), "bob".into()),
        ]));
        let result = Path::<UserParams>::from_request(req, &()).await;
        let resp = tachyon_web::IntoResponse::into_response(result.unwrap_err());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn string_extractor_invalid_utf8_returns_400() {
        let invalid_utf8 = vec![0xFF, 0xFE];
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::full(Bytes::from(invalid_utf8)))
            .unwrap();
        let result = String::from_request(req, &()).await;
        let resp = tachyon_web::IntoResponse::into_response(result.unwrap_err());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn host_extractor_ok() {
        use tachyon_web::Host;
        let req = Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        let host = Host::from_request(req, &()).await.unwrap();
        assert_eq!(host.0, "example.com");

        let req2 = Request::builder()
            .uri("http://example.org/")
            .body(Body::empty())
            .unwrap();
        let host2 = Host::from_request(req2, &()).await.unwrap();
        assert_eq!(host2.0, "example.org");
    }

    #[tokio::test]
    async fn original_uri_extractor_ok() {
        use tachyon_web::OriginalUri;
        let req = Request::builder()
            .uri("/original?foo=bar")
            .body(Body::empty())
            .unwrap();
        let original_uri = OriginalUri::from_request(req, &()).await.unwrap();
        assert_eq!(original_uri.0.path(), "/original");
        assert_eq!(original_uri.0.query().unwrap(), "foo=bar");
    }

    #[tokio::test]
    async fn connect_info_extractor_ok() {
        use std::net::SocketAddr;
        use tachyon_web::ConnectInfo;
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let _ = req.extensions_mut().insert(ConnectInfo(addr));
        let connect_info = ConnectInfo::<SocketAddr>::from_request(req, &())
            .await
            .unwrap();
        assert_eq!(connect_info.0, addr);
    }

    #[test]
    fn redirect_into_response() {
        use tachyon_web::Redirect;
        let r = Redirect::to("/login");
        let resp = tachyon_web::IntoResponse::into_response(r);
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get("location").unwrap().to_str().unwrap(),
            "/login"
        );

        let r_temp = Redirect::temporary("/temp");
        let resp_temp = tachyon_web::IntoResponse::into_response(r_temp);
        assert_eq!(resp_temp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            resp_temp
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap(),
            "/temp"
        );

        let r_perm = Redirect::permanent("/perm");
        let resp_perm = tachyon_web::IntoResponse::into_response(r_perm);
        assert_eq!(resp_perm.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            resp_perm
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap(),
            "/perm"
        );
    }

    #[tokio::test]
    async fn test_path_parameter_percent_decoding() {
        use serde::Deserialize;
        use tachyon_web::Path;

        #[derive(Deserialize)]
        struct NameParam {
            name: String,
        }

        async fn name_handler(Path(p): Path<NameParam>) -> String {
            p.name
        }

        let router = Router::new().route("/hello/:name", get(name_handler));
        let (port, _h) = spawn_server(router).await;

        let res = client()
            .get(format!("http://127.0.0.1:{}/hello/John%20Doe", port))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(res.text().await.unwrap(), "John Doe");
    }

    #[tokio::test]
    async fn test_static_file_serving_with_encoded_spaces() {
        use tachyon_web::ServeDir;

        let dir = tempfile::tempdir().unwrap();
        let fpath = dir.path().join("hello space.txt");
        std::fs::write(&fpath, b"hello space content").unwrap();

        let serve = ServeDir::new(dir.path()).preload().await.unwrap();
        let router = Router::new().serve_dir("/files", serve);
        let (port, _h) = spawn_server(router).await;

        let res = client()
            .get(format!("http://127.0.0.1:{}/files/hello%20space.txt", port))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(res.text().await.unwrap(), "hello space content");
    }
}

// ─── HTTP/2 over cleartext (h2c) ──────────────────────────────────────────────

#[cfg(feature = "http2")]
#[tokio::test]
async fn test_h2c_prior_knowledge_over_plain_tcp() {
    // `reqwest` can't speak "prior knowledge" h2c (it only ever negotiates
    // HTTP/2 via TLS ALPN), so this drives a raw `hyper` HTTP/2 client
    // connection directly over the same plaintext `serve_http` listener the
    // rest of this file uses — proving the server accepts HTTP/2 with no TLS
    // involved at all, not just that it still serves HTTP/1.1.
    async fn handler() -> &'static str {
        "h2c ok"
    }
    let (port, _h) = spawn_server(Router::new().route("/", get(handler))).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await
            .expect("h2c handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("request");
    let res = sender.send_request(req).await.expect("h2c request");
    assert_eq!(res.status(), 200);

    let body = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    assert_eq!(&body[..], b"h2c ok");
}

// ─── Opt-in trailing-slash normalization ──────────────────────────────────────

#[tokio::test]
async fn test_normalize_trailing_slash_strips_before_routing() {
    async fn handler() -> &'static str {
        "ok"
    }
    let router = Router::new()
        .route("/about", get(handler))
        .normalize_trailing_slash();
    let (port, _h) = spawn_server(router).await;

    // The route was registered without a trailing slash; with normalization
    // enabled, a request with one still reaches it.
    let res = client()
        .get(format!("http://127.0.0.1:{}/about/", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn test_normalize_trailing_slash_off_by_default_still_404s() {
    async fn handler() -> &'static str {
        "ok"
    }
    // No `.normalize_trailing_slash()` call — strict Axum-like behavior applies.
    let (port, _h) = spawn_server(Router::new().route("/about", get(handler))).await;

    let res = client()
        .get(format!("http://127.0.0.1:{}/about/", port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}
