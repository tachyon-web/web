//! Golden-response parity for edge cases identified in a full parity audit:
//! trailing-slash strictness, lazy/lenient percent-decoding of path params,
//! wildcard catch-all routes, duplicate query keys, the `Form` extractor, and
//! the `Allow` header's exact content on 405 responses.

use axum::routing::{get as axum_get, post as axum_post};
use parity_tests::{assert_same_response, assert_same_status, get_req as get, request};
use serde::{Deserialize, Serialize};
use tachyon_web::{get as t_get, post as t_post, Router};

/// Axum treats `/foo` and `/foo/` as distinct routes — no implicit
/// normalization, no redirect. A request for the registered-without-slash
/// path with an extra trailing slash must 404 on both frameworks.
#[tokio::test]
async fn trailing_slash_is_not_stripped() {
    async fn handler() -> &'static str {
        "ok"
    }
    let axum_app = axum::Router::new().route("/no-slash", axum_get(handler));
    let tachyon_app = Router::new().route("/no-slash", t_get(handler));

    assert_same_status(axum_app, tachyon_app, || get("/no-slash/")).await;
}

/// Mirror case: route registered *with* a trailing slash must not answer a
/// request missing it.
#[tokio::test]
async fn trailing_slash_is_not_added() {
    async fn handler() -> &'static str {
        "ok"
    }
    let axum_app = axum::Router::new().route("/with-slash/", axum_get(handler));
    let tachyon_app = Router::new().route("/with-slash/", t_get(handler));

    assert_same_status(axum_app, tachyon_app, || get("/with-slash")).await;
}

/// A malformed `%` escape in a path segment must not prevent routing from
/// reaching a handler that never reads the path parameter — Axum only
/// percent-decodes lazily, inside the `Path` extractor, so route matching
/// itself can't fail because of how a segment happens to be encoded.
#[tokio::test]
async fn malformed_percent_escape_still_reaches_handler_without_path_extractor() {
    async fn handler() -> &'static str {
        "reached"
    }
    let axum_app = axum::Router::new().route("/items/{id}", axum_get(handler));
    let tachyon_app = Router::new().route("/items/{id}", t_get(handler));

    // "%zz" is not valid hex — dangling/invalid escape.
    assert_same_response(axum_app, tachyon_app, || get("/items/100%zz")).await;
}

/// Same malformed escape, but the handler *does* extract a `Path<String>` —
/// pins down that both frameworks still produce a usable (if literal,
/// undecoded) value rather than a routing-level failure.
#[tokio::test]
async fn malformed_percent_escape_with_path_extractor() {
    #[derive(Deserialize, Serialize)]
    struct IdParam {
        id: String,
    }
    async fn axum_handler(axum::extract::Path(p): axum::extract::Path<IdParam>) -> String {
        p.id
    }
    async fn tachyon_handler(
        tachyon_web::extract::Path(p): tachyon_web::extract::Path<IdParam>,
    ) -> String {
        p.id
    }

    let axum_app = axum::Router::new().route("/items/{id}", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/items/{id}", t_get(tachyon_handler));

    assert_same_status(axum_app, tachyon_app, || get("/items/100%zz")).await;
}

/// Wildcard/catch-all segment (`{*rest}`) must capture the remaining path,
/// including multiple nested segments.
#[tokio::test]
async fn wildcard_catch_all_captures_remaining_segments() {
    async fn axum_handler(axum::extract::Path(rest): axum::extract::Path<String>) -> String {
        rest
    }
    async fn tachyon_handler(
        tachyon_web::extract::Path(rest): tachyon_web::extract::Path<String>,
    ) -> String {
        rest
    }

    let axum_app = axum::Router::new().route("/files/{*rest}", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/files/{*rest}", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/files/a/b/c.txt")).await;
}

/// A wildcard route must not match the bare prefix with nothing after it.
#[tokio::test]
async fn wildcard_catch_all_requires_at_least_one_segment() {
    async fn handler() -> &'static str {
        "reached"
    }
    let axum_app = axum::Router::new().route("/files/{*rest}", axum_get(handler));
    let tachyon_app = Router::new().route("/files/{*rest}", t_get(handler));

    assert_same_status(axum_app, tachyon_app, || get("/files")).await;
}

/// A duplicate query key deserialized into a plain scalar (`String`) field —
/// not a `Vec` — must behave identically on both frameworks. Contrary to a
/// naive "last value wins" assumption, real Axum's `serde_urlencoded`-backed
/// `Query` actually *rejects* a duplicate key for a scalar field with 400,
/// same as it does for the `Vec` case in `query_repeated_key_into_vec_is_rejected_by_both`
/// (extractors.rs) — only the status is a compatibility claim, not the
/// diagnostic wording, so this uses `assert_same_status` like that test does.
#[derive(Deserialize, Serialize)]
struct NameQuery {
    name: String,
}

#[tokio::test]
async fn query_duplicate_key_into_scalar_matches() {
    async fn axum_handler(axum::extract::Query(p): axum::extract::Query<NameQuery>) -> String {
        p.name
    }
    async fn tachyon_handler(
        tachyon_web::extract::Query(p): tachyon_web::extract::Query<NameQuery>,
    ) -> String {
        p.name
    }

    let axum_app = axum::Router::new().route("/dup", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/dup", t_get(tachyon_handler));

    assert_same_status(axum_app, tachyon_app, || get("/dup?name=first&name=second")).await;
}

/// `Form` extractor, `GET` path: reads from the query string, not the body.
#[derive(Deserialize, Serialize)]
struct LoginForm {
    user: String,
}

#[tokio::test]
async fn form_extractor_get_reads_query_string() {
    async fn axum_handler(axum::extract::Form(f): axum::extract::Form<LoginForm>) -> String {
        f.user
    }
    async fn tachyon_handler(
        tachyon_web::extract::Form(f): tachyon_web::extract::Form<LoginForm>,
    ) -> String {
        f.user
    }

    let axum_app = axum::Router::new().route("/login", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/login", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/login?user=alice")).await;
}

/// `Form` extractor, `POST` path: reads `application/x-www-form-urlencoded` body.
#[tokio::test]
async fn form_extractor_post_reads_urlencoded_body() {
    async fn axum_handler(axum::extract::Form(f): axum::extract::Form<LoginForm>) -> String {
        f.user
    }
    async fn tachyon_handler(
        tachyon_web::extract::Form(f): tachyon_web::extract::Form<LoginForm>,
    ) -> String {
        f.user
    }

    let axum_app = axum::Router::new().route("/login", axum_post(axum_handler));
    let tachyon_app = Router::new().route("/login", t_post(tachyon_handler));

    use bytes::Bytes;
    use http_body_util::Full;
    assert_same_response(axum_app, tachyon_app, || {
        hyper::Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from_static(b"user=bob")))
            .unwrap()
    })
    .await;
}

/// `Form` extractor, `POST` with the wrong `Content-Type` — must be rejected
/// on both frameworks (status only; diagnostic wording isn't a compat claim).
#[tokio::test]
async fn form_extractor_post_wrong_content_type_matches() {
    async fn axum_handler(axum::extract::Form(_f): axum::extract::Form<LoginForm>) -> &'static str {
        "unreachable"
    }
    async fn tachyon_handler(
        tachyon_web::extract::Form(_f): tachyon_web::extract::Form<LoginForm>,
    ) -> &'static str {
        "unreachable"
    }

    let axum_app = axum::Router::new().route("/login", axum_post(axum_handler));
    let tachyon_app = Router::new().route("/login", t_post(tachyon_handler));

    use bytes::Bytes;
    use http_body_util::Full;
    assert_same_status(axum_app, tachyon_app, || {
        hyper::Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(b"user=bob")))
            .unwrap()
    })
    .await;
}

/// The `Allow` header on a 405 must list the same set of methods, in the same
/// format (comma-joined, no spaces) — this is an observable part of the API
/// surface a client might parse, not just an internal diagnostic. Notably,
/// `HEAD` must be listed whenever `GET` is registered even without an
/// explicit `HEAD` handler, since a `GET` handler transparently answers
/// `HEAD` too. The 405 response *body* is each framework's own diagnostic
/// prose (Axum's is empty; tachyon's says "Method Not Allowed"), so only the
/// header is asserted here via a direct probe rather than
/// `assert_same_response`.
#[tokio::test]
async fn method_not_allowed_allow_header_matches() {
    async fn get_handler() -> &'static str {
        "g"
    }
    async fn post_handler() -> &'static str {
        "p"
    }
    async fn delete_handler() -> &'static str {
        "d"
    }

    let axum_app = axum::Router::new()
        .route("/res", axum_get(get_handler))
        .route("/res", axum_post(post_handler))
        .route("/res", axum::routing::delete(delete_handler));
    let tachyon_app = Router::new()
        .route("/res", t_get(get_handler))
        .route("/res", t_post(post_handler))
        .route("/res", tachyon_web::delete(delete_handler));

    let axum_probe = parity_tests::axum_probe(axum_app, request("PATCH", "/res")).await;
    let tachyon_probe = parity_tests::tachyon_probe(tachyon_app, request("PATCH", "/res")).await;
    assert_eq!(axum_probe.status, tachyon_probe.status);
    assert_eq!(
        axum_probe.headers.get("allow"),
        tachyon_probe.headers.get("allow"),
        "Allow header content diverged"
    );
}
