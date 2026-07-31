//! Golden-response parity: `Path`, `Query` (including repeated-key `Vec<T>`),
//! and `Json` extractors.

use axum::routing::{get as axum_get, post as axum_post};
use parity_tests::{assert_same_response, assert_same_status, get_req as get, post_json};
use serde::{Deserialize, Serialize};
use tachyon_web::{get as t_get, post as t_post, Router};

#[derive(Deserialize, Serialize)]
struct IdParam {
    id: u32,
}

#[tokio::test]
async fn path_param_extraction_matches() {
    async fn axum_handler(axum::extract::Path(p): axum::extract::Path<IdParam>) -> String {
        format!("id:{}", p.id)
    }
    async fn tachyon_handler(
        tachyon_web::extract::Path(p): tachyon_web::extract::Path<IdParam>,
    ) -> String {
        format!("id:{}", p.id)
    }

    let axum_app = axum::Router::new().route("/users/{id}", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/users/{id}", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/users/42")).await;
}

#[tokio::test]
async fn path_param_type_mismatch_matches() {
    async fn axum_handler(axum::extract::Path(_p): axum::extract::Path<IdParam>) -> String {
        "unreachable".to_string()
    }
    async fn tachyon_handler(
        tachyon_web::extract::Path(_p): tachyon_web::extract::Path<IdParam>,
    ) -> String {
        "unreachable".to_string()
    }

    let axum_app = axum::Router::new().route("/users/{id}", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/users/{id}", t_get(tachyon_handler));

    // "abc" doesn't parse as u32 on either side — only the status (400) is a
    // compatibility claim, not the exact serde error wording in the body.
    assert_same_status(axum_app, tachyon_app, || get("/users/abc")).await;
}

#[derive(Deserialize, Serialize)]
struct SearchQuery {
    q: String,
}

#[tokio::test]
async fn query_scalar_extraction_matches() {
    async fn axum_handler(axum::extract::Query(p): axum::extract::Query<SearchQuery>) -> String {
        p.q
    }
    async fn tachyon_handler(
        tachyon_web::extract::Query(p): tachyon_web::extract::Query<SearchQuery>,
    ) -> String {
        p.q
    }

    let axum_app = axum::Router::new().route("/search", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/search", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/search?q=rust+web")).await;
}

#[derive(Deserialize, Serialize)]
struct TagsQuery {
    tags: Vec<String>,
}

/// Axum's `Query` (backed by `serde_urlencoded`, confirmed via `cargo tree`)
/// does **not** aggregate a repeated key (`?tags=a&tags=b`) into a `Vec<T>`
/// field — it rejects it with 400 ("invalid type: string, expected a
/// sequence"), the same way a single occurrence would. tachyon-web must
/// reject it identically rather than "helpfully" accepting something real
/// Axum doesn't — silently accepting stricter input than the API you're
/// mirroring is itself a compatibility bug, just in the other direction.
#[tokio::test]
async fn query_repeated_key_into_vec_is_rejected_by_both() {
    async fn axum_handler(
        axum::extract::Query(_p): axum::extract::Query<TagsQuery>,
    ) -> &'static str {
        "unreachable"
    }
    async fn tachyon_handler(
        tachyon_web::extract::Query(_p): tachyon_web::extract::Query<TagsQuery>,
    ) -> &'static str {
        "unreachable"
    }

    let axum_app = axum::Router::new().route("/tags", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/tags", t_get(tachyon_handler));

    assert_same_status(axum_app, tachyon_app, || {
        get("/tags?tags=rust&tags=web&tags=fast")
    })
    .await;
}

#[derive(Deserialize, Serialize)]
struct Payload {
    value: String,
}

#[tokio::test]
async fn json_body_extraction_matches() {
    async fn axum_handler(axum::Json(p): axum::Json<Payload>) -> String {
        p.value
    }
    async fn tachyon_handler(
        tachyon_web::extract::Json(p): tachyon_web::extract::Json<Payload>,
    ) -> String {
        p.value
    }

    let axum_app = axum::Router::new().route("/echo", axum_post(axum_handler));
    let tachyon_app = Router::new().route("/echo", t_post(tachyon_handler));

    let body = serde_json::json!({ "value": "hi" });
    assert_same_response(axum_app, tachyon_app, || post_json("/echo", &body)).await;
}

#[tokio::test]
async fn json_malformed_body_matches() {
    async fn axum_handler(axum::Json(_p): axum::Json<Payload>) -> &'static str {
        "unreachable"
    }
    async fn tachyon_handler(
        tachyon_web::extract::Json(_p): tachyon_web::extract::Json<Payload>,
    ) -> &'static str {
        "unreachable"
    }

    let axum_app = axum::Router::new().route("/echo", axum_post(axum_handler));
    let tachyon_app = Router::new().route("/echo", t_post(tachyon_handler));

    // Both frameworks must reject malformed JSON with 400 — the diagnostic
    // message text is not a compatibility claim.
    use bytes::Bytes;
    use http_body_util::Full;
    assert_same_status(axum_app, tachyon_app, || {
        hyper::Request::builder()
            .method("POST")
            .uri("/echo")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(b"{not valid json")))
            .unwrap()
    })
    .await;
}

#[tokio::test]
async fn json_wrong_content_type_matches() {
    async fn axum_handler(axum::Json(_p): axum::Json<Payload>) -> &'static str {
        "unreachable"
    }
    async fn tachyon_handler(
        tachyon_web::extract::Json(_p): tachyon_web::extract::Json<Payload>,
    ) -> &'static str {
        "unreachable"
    }

    let axum_app = axum::Router::new().route("/echo", axum_post(axum_handler));
    let tachyon_app = Router::new().route("/echo", t_post(tachyon_handler));

    use bytes::Bytes;
    use http_body_util::Full;
    assert_same_status(axum_app, tachyon_app, || {
        hyper::Request::builder()
            .method("POST")
            .uri("/echo")
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(b"{\"value\":\"hi\"}")))
            .unwrap()
    })
    .await;
}

#[tokio::test]
async fn raw_query_extraction_matches() {
    async fn axum_handler(axum::extract::RawQuery(q): axum::extract::RawQuery) -> String {
        q.unwrap_or_default()
    }
    async fn tachyon_handler(
        tachyon_web::extract::RawQuery(q): tachyon_web::extract::RawQuery,
    ) -> String {
        q.unwrap_or_default()
    }

    let axum_app = axum::Router::new().route("/raw", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/raw", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/raw?a=1&b=2")).await;
}

#[tokio::test]
async fn raw_query_missing_matches() {
    async fn axum_handler(axum::extract::RawQuery(q): axum::extract::RawQuery) -> String {
        format!("{q:?}")
    }
    async fn tachyon_handler(
        tachyon_web::extract::RawQuery(q): tachyon_web::extract::RawQuery,
    ) -> String {
        format!("{q:?}")
    }

    let axum_app = axum::Router::new().route("/raw", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/raw", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/raw")).await;
}

#[tokio::test]
async fn append_headers_matches() {
    async fn axum_handler() -> impl axum::response::IntoResponse {
        (
            axum::response::AppendHeaders([("x-custom", "1"), ("x-custom", "2")]),
            "body",
        )
    }
    async fn tachyon_handler() -> impl tachyon_web::http::response::IntoResponse {
        (
            tachyon_web::http::response::AppendHeaders([("x-custom", "1"), ("x-custom", "2")]),
            "body",
        )
    }

    let axum_app = axum::Router::new().route("/hdrs", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/hdrs", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/hdrs")).await;
}

#[tokio::test]
async fn missing_extension_returns_500_on_both() {
    #[derive(Clone)]
    struct Marker;

    async fn axum_handler(
        axum::extract::Extension(_m): axum::extract::Extension<Marker>,
    ) -> &'static str {
        "unreachable"
    }
    async fn tachyon_handler(
        tachyon_web::extract::Extension(_m): tachyon_web::extract::Extension<Marker>,
    ) -> &'static str {
        "unreachable"
    }

    let axum_app = axum::Router::new().route("/needs-ext", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/needs-ext", t_get(tachyon_handler));

    assert_same_status(axum_app, tachyon_app, || get("/needs-ext")).await;
}
