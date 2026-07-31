//! Golden-response parity for the two behavioral bugs this effort fixed:
//! `Router::nest()` URI stripping / `OriginalUri`, and `MatchedPath`.
//!
//! Before the fix, tachyon-web's `nest()` only concatenated route *strings*
//! at compile time and never rewrote the request `Uri` at all, so a nested
//! handler saw the full, un-stripped path — silently different from Axum.
//! These tests pin that fix down against the real thing.

use axum::routing::get as axum_get;
use parity_tests::{assert_same_response, get_req as get};
use tachyon_web::{get as t_get, Router};

#[tokio::test]
async fn nested_handler_sees_stripped_uri() {
    async fn axum_handler(uri: axum::http::Uri) -> String {
        uri.path().to_string()
    }
    async fn tachyon_handler(uri: hyper::Uri) -> String {
        uri.path().to_string()
    }

    let axum_app = axum::Router::new().nest(
        "/api",
        axum::Router::new().route("/users/{id}", axum_get(axum_handler)),
    );
    let tachyon_app = Router::new().nest(
        "/api",
        Router::new().route("/users/{id}", t_get(tachyon_handler)),
    );

    assert_same_response(axum_app, tachyon_app, || get("/api/users/42")).await;
}

#[tokio::test]
async fn original_uri_recovers_full_path() {
    async fn axum_handler(axum::extract::OriginalUri(uri): axum::extract::OriginalUri) -> String {
        uri.path().to_string()
    }
    async fn tachyon_handler(
        tachyon_web::extract::OriginalUri(uri): tachyon_web::extract::OriginalUri,
    ) -> String {
        uri.path().to_string()
    }

    let axum_app = axum::Router::new().nest(
        "/api",
        axum::Router::new().route("/users/{id}", axum_get(axum_handler)),
    );
    let tachyon_app = Router::new().nest(
        "/api",
        Router::new().route("/users/{id}", t_get(tachyon_handler)),
    );

    assert_same_response(axum_app, tachyon_app, || get("/api/users/42")).await;
}

#[tokio::test]
async fn two_level_nesting_strips_full_accumulated_prefix() {
    async fn axum_handler(uri: axum::http::Uri) -> String {
        uri.path().to_string()
    }
    async fn tachyon_handler(uri: hyper::Uri) -> String {
        uri.path().to_string()
    }

    let axum_app = axum::Router::new().nest(
        "/api",
        axum::Router::new().nest(
            "/v1",
            axum::Router::new().route("/users", axum_get(axum_handler)),
        ),
    );
    let tachyon_app = Router::new().nest(
        "/api",
        Router::new().nest("/v1", Router::new().route("/users", t_get(tachyon_handler))),
    );

    assert_same_response(axum_app, tachyon_app, || get("/api/v1/users")).await;
}

#[tokio::test]
async fn non_nested_route_uri_is_unaffected() {
    async fn axum_handler(uri: axum::http::Uri) -> String {
        uri.path().to_string()
    }
    async fn tachyon_handler(uri: hyper::Uri) -> String {
        uri.path().to_string()
    }

    let axum_app = axum::Router::new().route("/users/{id}", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/users/{id}", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/users/7")).await;
}

#[tokio::test]
async fn matched_path_returns_route_template() {
    async fn axum_handler(path: axum::extract::MatchedPath) -> String {
        path.as_str().to_string()
    }
    async fn tachyon_handler(path: tachyon_web::extract::MatchedPath) -> String {
        path.as_str().to_string()
    }

    let axum_app = axum::Router::new().route("/users/{id}", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/users/{id}", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/users/99")).await;
}
