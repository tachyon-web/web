//! Test suite for the `routing` module split across `method_router.rs` / `router.rs` / `compiled.rs`.

#![allow(clippy::unwrap_used)]
use super::*;
use crate::http::response::Body;
use crate::routing::extract::Path;
use crate::routing::router::normalize_route_pattern;
use bytes::Bytes;
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct IdParam {
    id: u32,
}

async fn handle_root() -> &'static str {
    "root"
}
async fn handle_id(Path(p): Path<IdParam>) -> String {
    format!("id:{}", p.id)
}
async fn handle_post() -> &'static str {
    "post"
}
async fn handle_delete() -> &'static str {
    "deleted"
}

fn make_req(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("valid request")
}

fn compile_app() -> CompiledRouter<()> {
    Router::new()
        .route("/", get(handle_root))
        .route(
            "/user/:id",
            get(handle_id).post(handle_post).delete(handle_delete),
        )
        .with_state::<()>(())
        .compile()
        .expect("compile router")
}

#[tokio::test]
async fn test_path_param_extraction() {
    use http_body_util::BodyExt;
    let router = compile_app();
    let resp = router.handle_request(make_req("GET", "/user/42")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"id:42");
}

#[tokio::test]
async fn test_not_found() {
    let router = compile_app();
    let resp = router.handle_request(make_req("GET", "/nonexistent")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_method_not_allowed_has_allow_header() {
    let router = compile_app();
    // /user/:id has GET, POST, DELETE — PATCH is not registered
    let resp = router.handle_request(make_req("PATCH", "/user/1")).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let allow = resp
        .headers()
        .get(hyper::header::ALLOW)
        .expect("Allow header must be present");
    let allow_str = allow.to_str().expect("valid utf8");
    assert!(allow_str.contains("GET"), "Allow: {allow_str}");
    assert!(allow_str.contains("POST"), "Allow: {allow_str}");
    assert!(allow_str.contains("DELETE"), "Allow: {allow_str}");
    assert!(!allow_str.contains("PATCH"), "Allow: {allow_str}");
}

/// `/foo` and `/foo/` are distinct routes in both directions, matching Axum.
#[tokio::test]
async fn test_trailing_slash_is_significant() {
    let router = compile_app();
    let resp = router.handle_request(make_req("GET", "/user/5/")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let router = Router::new()
        .route("/about/", get(handle_root))
        .with_state::<()>(())
        .compile()
        .expect("compile");
    let resp = router.handle_request(make_req("GET", "/about")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_case_sensitive_routing() {
    // Paths must match exactly — no silent case-folding.
    let router = compile_app();
    let resp = router.handle_request(make_req("GET", "/User/1")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_custom_fallback() {
    let router = Router::new()
        .route("/", get(handle_root))
        .fallback(|_req: Request<Body>| async { (StatusCode::FOUND, "redirected") })
        .with_state::<()>(())
        .compile()
        .expect("compile");
    let resp = router.handle_request(make_req("GET", "/missing")).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn test_overlapping_method_route_panics() {
    async fn v1() -> &'static str {
        "v1"
    }
    async fn v2() -> &'static str {
        "v2"
    }

    // Registering the same method for the same path twice panics,
    // matching Axum's "Overlapping method route" panic.
    let result = std::panic::catch_unwind(|| {
        Router::<()>::new()
            .route("/dup", get(v1))
            .route("/dup", get(v2))
    });
    assert!(result.is_err());
}

#[tokio::test]
async fn test_non_overlapping_methods_on_same_path_merge() {
    async fn handle_get() -> &'static str {
        "got"
    }
    async fn handle_post() -> &'static str {
        "posted"
    }

    // Registering different methods for the same path across separate
    // `.route()` calls merges into a single route answering both —
    // matching Axum, not tachyon-web's previous "any repeat path errors"
    // behavior.
    let app = Router::new()
        .route("/x", get(handle_get))
        .route("/x", post(handle_post))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let get_resp = app.handle_request(make_req("GET", "/x")).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_body = http_body_util::BodyExt::collect(get_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&get_body[..], b"got");

    let post_resp = app.handle_request(make_req("POST", "/x")).await;
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_body = http_body_util::BodyExt::collect(post_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&post_body[..], b"posted");
}

#[test]
fn test_normalize_route_pattern() {
    for (input, expected) in [
        ("/static/path", "/static/path"),
        ("/user/:id", "/user/{id}"),
        ("/files/*path", "/files/{*path}"),
        ("/api/:version/files/*rest", "/api/{version}/files/{*rest}"),
    ] {
        assert_eq!(normalize_route_pattern(input), expected, "input: {input}");
    }
}

/// A nested route is reachable at `prefix + path`, including when the inner path is `/`
/// (which mounts at the bare prefix).
#[tokio::test]
async fn test_nested_routes_are_reachable() {
    let app = Router::new()
        .nest("/api/v1", Router::new().route("/status", get(handle_root)))
        .nest("/api", Router::new().route("/", get(handle_root)))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    for path in ["/api/v1/status", "/api"] {
        let resp = app.handle_request(make_req("GET", path)).await;
        assert_eq!(resp.status(), StatusCode::OK, "path: {path}");
    }
}

#[tokio::test]
async fn test_nest_strips_prefix_from_uri() {
    use hyper::Uri;

    async fn echo_uri(uri: Uri) -> String {
        uri.path().to_string()
    }

    let api = Router::new().route("/users/{id}", get(echo_uri));
    let app = Router::new()
        .nest("/api", api)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/api/users/42")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    // Matches Axum: the nested handler sees the prefix-stripped path.
    assert_eq!(&body[..], b"/users/42");
}

#[cfg(feature = "original-uri")]
#[tokio::test]
async fn test_nest_original_uri_preserves_full_path() {
    use crate::routing::extract::OriginalUri;

    async fn echo_original(OriginalUri(uri): OriginalUri) -> String {
        uri.path().to_string()
    }

    let api = Router::new().route("/users/{id}", get(echo_original));
    let app = Router::new()
        .nest("/api", api)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/api/users/42")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    // OriginalUri recovers the full, pre-strip path.
    assert_eq!(&body[..], b"/api/users/42");
}

#[tokio::test]
async fn test_nested_path_reports_the_mount_prefix() {
    use crate::routing::extract::NestedPath;

    async fn echo_nested(nested: NestedPath) -> String {
        nested.as_str().to_string()
    }

    let inner = Router::new().route("/users", get(echo_nested));
    let v1 = Router::new().nest("/v1", inner);
    let app = Router::new()
        .nest("/api", v1)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/api/v1/users")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"/api/v1");
}

#[tokio::test]
async fn test_nested_path_rejects_on_a_non_nested_route() {
    use crate::http::response::IntoResponse;
    use crate::routing::extract::{FromRequestParts, NestedPath};

    let mut parts = make_req("GET", "/plain").into_parts().0;
    let err = NestedPath::from_request_parts(&mut parts, &())
        .await
        .unwrap_err();
    assert_eq!(
        err.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn test_nest_two_levels_accumulates_prefix() {
    async fn echo_uri(uri: hyper::Uri) -> String {
        uri.path().to_string()
    }

    let innermost = Router::new().route("/users", get(echo_uri));
    let v1 = Router::new().nest("/v1", innermost);
    let app = Router::new()
        .nest("/api", v1)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/api/v1/users")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"/users");
}

#[tokio::test]
async fn test_non_nested_route_uri_unaffected() {
    // A route registered directly (no `.nest()`) must see its Uri untouched.
    async fn echo_uri(uri: hyper::Uri) -> String {
        uri.path().to_string()
    }
    let app = Router::new()
        .route("/users/{id}", get(echo_uri))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/users/7")).await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"/users/7");
}

#[cfg(feature = "matched-path")]
#[tokio::test]
async fn test_matched_path_returns_route_pattern() {
    use crate::routing::extract::MatchedPath;

    async fn handler(path: MatchedPath) -> String {
        path.as_str().to_string()
    }

    let app = Router::new()
        .route("/users/{id}", get(handler))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/users/99")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"/users/{id}");
}

#[cfg(feature = "matched-path")]
#[tokio::test]
async fn test_matched_path_missing_returns_500() {
    use crate::routing::extract::{FromRequestParts, MatchedPath};
    // Directly exercising the extractor without going through the router at
    // all (no `MatchedPath` extension present) must reject with 500.
    let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
    let res = MatchedPath::from_request_parts(&mut parts, &()).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_any_dispatches_every_method() {
    async fn handler() -> &'static str {
        "any"
    }
    let app = Router::new()
        .route("/x", any(handler))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    for method in [
        "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
    ] {
        let resp = app.handle_request(make_req(method, "/x")).await;
        assert_eq!(resp.status(), StatusCode::OK, "method: {method}");
    }
}

#[tokio::test]
async fn test_connect_route() {
    async fn handler() -> &'static str {
        "connected"
    }
    let app = Router::new()
        .route("/tunnel", connect(handler))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("CONNECT", "/tunnel")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Route patterns that `matchit` can't disambiguate (a named param and a wildcard at the
/// same position) must surface as a compile error, not a silent mis-route.
#[test]
fn test_conflicting_route_patterns_fail_to_compile() {
    async fn dummy() -> &'static str {
        "ok"
    }
    let err = Router::new()
        .route("/user/:id", get(dummy))
        .route("/user/*path", get(dummy))
        .with_state::<()>(())
        .compile()
        .expect_err("conflicting patterns must not compile");
    assert!(err.to_string().contains("Router insert error"), "{err}");
}

#[tokio::test]
async fn test_serve_file_dynamic_reads_on_each_request() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("dynamic.txt");
    std::fs::write(&file, "hello dynamic").unwrap();

    let app = Router::new()
        .serve_file_dynamic("/dyn", file.to_str().unwrap())
        .serve_file_dynamic("/missing", "/nonexistent/file")
        .with_state::<()>(())
        .compile()
        .unwrap();

    let resp = app.handle_request(make_req("GET", "/dyn")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"hello dynamic");

    // Content is re-read per request, so an edit is visible without a restart.
    std::fs::write(&file, "edited").unwrap();
    let resp = app.handle_request(make_req("GET", "/dyn")).await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"edited");

    let resp = app.handle_request(make_req("GET", "/missing")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A `ServeDir` under a non-root prefix serves the index for both directory-request forms,
/// not just the files beneath it.
#[tokio::test]
async fn test_serve_dir_under_a_prefix_serves_index_and_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), b"<h1>idx</h1>").unwrap();
    std::fs::write(dir.path().join("app.css"), b"body{}").unwrap();
    std::fs::create_dir(dir.path().join("deep")).unwrap();
    std::fs::write(dir.path().join("deep/index.html"), b"<h1>deep</h1>").unwrap();

    let sd = static_dir::ServeDir::new(dir.path()).index("index.html");
    let app = Router::new()
        .serve_dir("/assets", sd)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    for (path, expected) in [
        ("/assets", &b"<h1>idx</h1>"[..]),
        ("/assets/", &b"<h1>idx</h1>"[..]),
        ("/assets/app.css", &b"body{}"[..]),
        ("/assets/deep/", &b"<h1>deep</h1>"[..]),
    ] {
        let resp = app.handle_request(make_req("GET", path)).await;
        assert_eq!(resp.status(), StatusCode::OK, "path: {path}");
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], expected, "path: {path}");
    }
}

/// At the root the bare-prefix and trailing-slash routes collapse into one `/` entry
/// rather than colliding.
#[tokio::test]
async fn test_serve_dir_at_root_serves_the_index() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), b"<h1>root</h1>").unwrap();

    let app = Router::new()
        .serve_static(dir.path())
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"<h1>root</h1>");
}

/// Applied at compile time, so it covers routes registered after the call too.
#[tokio::test]
async fn test_no_index_covers_routes_registered_in_either_order() {
    async fn handler() -> &'static str {
        "hi"
    }

    for app in [
        Router::new().route("/before", get(handler)).no_index(),
        Router::new().no_index().route("/before", get(handler)),
    ] {
        let app = app.with_state::<()>(()).compile().expect("compile");

        let resp = app.handle_request(make_req("GET", "/before")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-robots-tag").expect("header set"),
            "noindex, nofollow"
        );

        let resp = app.handle_request(make_req("GET", "/robots.txt")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"User-agent: *\nDisallow: /\n");
    }
}

/// An app that registers its own `/robots.txt` keeps it — `.no_index()` only fills the gap.
#[tokio::test]
async fn test_no_index_does_not_clobber_a_custom_robots_txt() {
    let app = Router::new()
        .no_index()
        .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/robots.txt")).await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"User-agent: *\nAllow: /\n");
}

#[tokio::test]
async fn test_merge_and_empty_prefix_nest_combine_route_tables() {
    async fn dummy() -> &'static str {
        "ok"
    }
    let app = Router::new()
        .route("/r1", get(dummy))
        .merge(Router::new().route("/r2", get(dummy)))
        .nest("", Router::new().route("/nested", get(dummy)))
        .with_state::<()>(())
        .compile()
        .unwrap();

    for path in ["/r1", "/r2", "/nested"] {
        let resp = app.handle_request(make_req("GET", path)).await;
        assert_eq!(resp.status(), StatusCode::OK, "path: {path}");
    }
}

#[tokio::test]
async fn test_merge_adopts_the_one_fallback_present() {
    async fn h() -> &'static str {
        "h"
    }
    async fn fb() -> &'static str {
        "merged-fallback"
    }

    let r1 = Router::new().route("/r1", get(h));
    let r2 = Router::new().route("/r2", get(h)).fallback(fb);
    let merged = r1.merge(r2).with_state::<()>(()).compile().unwrap();

    let resp = merged.handle_request(make_req("GET", "/missing")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"merged-fallback");
}

#[test]
fn test_merge_two_fallbacks_panics() {
    async fn fb1() -> &'static str {
        "fb1"
    }
    async fn fb2() -> &'static str {
        "fb2"
    }

    let result = std::panic::catch_unwind(|| {
        let r1 = Router::<()>::new().fallback(fb1);
        let r2 = Router::<()>::new().fallback(fb2);
        r1.merge(r2)
    });
    assert!(result.is_err());
}

#[tokio::test]
async fn test_method_router_layer_installs_middleware() {
    async fn handler() -> &'static str {
        "hi"
    }
    async fn tag_response(req: Request<Body>, next: middleware::Next) -> Response<Body> {
        let mut resp = next.run(req).await;
        let _ = resp.headers_mut().insert(
            hyper::header::HeaderName::from_static("x-mr-layer"),
            hyper::header::HeaderValue::from_static("yes"),
        );
        resp
    }

    // `.layer()` on a bare `MethodRouter` — distinct from `Router::layer`,
    // which wraps every registered route's `MethodRouter` the same way,
    // plus the fallback.
    let mr = get(handler).layer(middleware::from_fn(tag_response));
    let app = Router::new()
        .route("/x", mr)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/x")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-mr-layer").expect("header set"), "yes");
}

#[tokio::test]
async fn test_options_head_trace_free_functions() {
    async fn handle_options() -> &'static str {
        "opts"
    }
    async fn handle_trace() -> &'static str {
        "trace"
    }
    async fn handle_head() -> Response<Body> {
        Response::builder()
            .header("x-handler", "head")
            .body(Body::full(Bytes::from_static(b"head-only")))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
    async fn handle_get_for_head() -> Response<Body> {
        Response::builder()
            .header("x-handler", "get")
            .body(Body::full(Bytes::from_static(b"get-for-head")))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
    async fn handle_get_only() -> &'static str {
        "get-only"
    }

    let app = Router::new()
        .route("/opts", options(handle_options))
        .route("/tracer", trace(handle_trace))
        // An explicit HEAD handler must take priority over the implicit
        // GET fallback (see `CompiledRouter::handle_request`'s
        // `falls_back_to_get` logic).
        .route("/headroute", head(handle_head).get(handle_get_for_head))
        // No explicit HEAD handler here, so HEAD must still fall back to GET.
        .route("/getonly", get(handle_get_only))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("OPTIONS", "/opts")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"opts");

    let resp = app.handle_request(make_req("TRACE", "/tracer")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"trace");

    // The explicit HEAD handler must be the one that actually runs.
    let resp = app.handle_request(make_req("HEAD", "/headroute")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-handler")
            .map(hyper::header::HeaderValue::as_bytes),
        Some(&b"head"[..])
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert!(body.is_empty(), "HEAD responses must have an empty body");

    // GET on the same route still goes to the GET handler.
    let get_resp = app.handle_request(make_req("GET", "/headroute")).await;
    assert_eq!(
        get_resp
            .headers()
            .get("x-handler")
            .map(hyper::header::HeaderValue::as_bytes),
        Some(&b"get"[..])
    );
    let get_body = http_body_util::BodyExt::collect(get_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&get_body[..], b"get-for-head");

    // No HEAD handler registered: HEAD must fall back to the GET handler.
    let resp = app.handle_request(make_req("HEAD", "/getonly")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert!(body.is_empty(), "HEAD responses must have an empty body");
}

/// RFC 9110 §9.3.2: `HEAD` reports the same `Content-Length` the `GET` would.
#[tokio::test]
async fn test_head_preserves_content_length() {
    async fn body() -> &'static str {
        "hello world"
    }

    let app = Router::new()
        .route("/x", get(body))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let get_len =
        hyper::body::Body::size_hint(app.handle_request(make_req("GET", "/x")).await.body())
            .exact();
    assert_eq!(get_len, Some(11));

    let head = app.handle_request(make_req("HEAD", "/x")).await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        head.headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("11"),
        "HEAD must report the length GET would have sent"
    );
    assert_eq!(
        hyper::body::Body::size_hint(head.body()).exact(),
        Some(0),
        "HEAD must not carry a body"
    );
}

/// A `Content-Length` the handler set itself is authoritative.
#[tokio::test]
async fn test_head_keeps_explicit_content_length() {
    async fn handler() -> Response<Body> {
        Response::builder()
            .header(hyper::header::CONTENT_LENGTH, "999")
            .body(Body::full(Bytes::from_static(b"short")))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }

    let app = Router::new()
        .route("/x", get(handler))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let head = app.handle_request(make_req("HEAD", "/x")).await;
    assert_eq!(
        head.headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("999")
    );
}

#[tokio::test]
async fn test_method_not_allowed_fallback_overrides_default_405() {
    async fn get_handler() -> &'static str {
        "got"
    }
    async fn custom_405() -> (StatusCode, &'static str) {
        (StatusCode::IM_A_TEAPOT, "custom-405")
    }

    let app = Router::new()
        .route("/x", get(get_handler))
        .method_not_allowed_fallback(custom_405)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    // /x exists but has no POST handler — the custom fallback answers
    // instead of the default bare 405.
    let resp = app.handle_request(make_req("POST", "/x")).await;
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"custom-405");
}

#[tokio::test]
async fn test_layer_wraps_fallback_and_method_not_allowed_fallback() {
    async fn get_handler() -> &'static str {
        "got"
    }
    async fn custom_fallback() -> &'static str {
        "custom-fallback"
    }
    async fn custom_405() -> &'static str {
        "custom-405"
    }
    async fn tag_response(req: Request<Body>, next: middleware::Next) -> Response<Body> {
        let mut resp = next.run(req).await;
        let _ = resp.headers_mut().insert(
            hyper::header::HeaderName::from_static("x-layer"),
            hyper::header::HeaderValue::from_static("wrapped"),
        );
        resp
    }

    // `.fallback()`/`.method_not_allowed_fallback()` must be set *before*
    // `.layer()`, since it only wraps whichever of the two is already
    // installed at the time it runs.
    let app = Router::new()
        .route("/x", get(get_handler))
        .fallback(custom_fallback)
        .method_not_allowed_fallback(custom_405)
        .layer(middleware::from_fn(tag_response))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    // Middleware still runs around a normally-matched route.
    let resp = app.handle_request(make_req("GET", "/x")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-layer").expect("wraps route"),
        "wrapped"
    );

    // Middleware still runs around the custom fallback (unmatched path).
    let resp = app.handle_request(make_req("GET", "/missing")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-layer").expect("wraps fallback"),
        "wrapped"
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"custom-fallback");

    // Middleware still runs around the method-not-allowed fallback too.
    let resp = app.handle_request(make_req("POST", "/x")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-layer").expect("wraps 405 fallback"),
        "wrapped"
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"custom-405");
}

#[test]
fn test_compile_returns_duplicate_route_err() {
    async fn handler() -> &'static str {
        "dup"
    }

    // `Router::route`/`.nest()`/`.merge()` all merge same-path entries via
    // `push_or_merge_route`, so two *identical* path strings can never
    // reach `compile()`'s `routes` `Vec` through the public builder API —
    // see the doc comment on `RouterError::DuplicateRoute`. Constructing
    // the `Router` directly is the only way to exercise this internal
    // invariant check; this test lives inside the `routing` module tree,
    // so it can see the otherwise-private `routes` field to do that.
    let router = Router::<()> {
        routes: vec![
            ("/dup".to_string(), get(handler)),
            ("/dup".to_string(), get(handler)),
        ],
        fallback: None,
        method_not_allowed_fallback: None,
        normalize_trailing_slash: false,
        no_index: false,
        compiled: None,
    };

    let result = router.compile();
    assert!(matches!(result, Err(RouterError::DuplicateRoute(ref p)) if p == "/dup"));
}

#[tokio::test]
async fn test_nest_strips_prefix_preserves_query_string() {
    async fn echo_full(uri: hyper::Uri) -> String {
        uri.query()
            .map_or_else(|| uri.path().to_string(), |q| format!("{}?{q}", uri.path()))
    }

    let api = Router::new().route("/users/{id}", get(echo_full));
    let app = Router::new()
        .nest("/api", api)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app
        .handle_request(make_req("GET", "/api/users/42?active=true"))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"/users/42?active=true");
}

#[tokio::test]
async fn test_normalize_trailing_slash_preserves_query_string() {
    async fn echo_full(uri: hyper::Uri) -> String {
        uri.query()
            .map_or_else(|| uri.path().to_string(), |q| format!("{}?{q}", uri.path()))
    }

    let app = Router::new()
        .route("/about", get(echo_full))
        .normalize_trailing_slash()
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let resp = app.handle_request(make_req("GET", "/about/?x=1")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"/about?x=1");
}

#[tokio::test]
async fn test_normalize_trailing_slash_no_trailing_slash_is_untouched() {
    async fn handler() -> &'static str {
        "no-trailing"
    }

    let app = Router::new()
        .route("/about", get(handler))
        .normalize_trailing_slash()
        .with_state::<()>(())
        .compile()
        .expect("compile");

    // Already has no trailing slash → `strip_trailing_slash`'s
    // early-return branch.
    let resp = app.handle_request(make_req("GET", "/about")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Root `/` is length 1 → also hits the early-return branch, so it's
    // never stripped down to an empty (invalid) path.
    let root_app = Router::new()
        .route("/", get(handler))
        .normalize_trailing_slash()
        .with_state::<()>(())
        .compile()
        .expect("compile");
    let resp = root_app.handle_request(make_req("GET", "/")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
