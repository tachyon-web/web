//! Golden-response parity: basic routing, method dispatch, 404/405 handling.

use axum::routing::get as axum_get;
use parity_tests::{assert_same_response, assert_same_status, get_req as get, request};
use tachyon_web::{get as t_get, Router};

#[tokio::test]
async fn root_route_matches() {
    async fn handler() -> &'static str {
        "hello"
    }
    let axum_app = axum::Router::new().route("/", axum_get(handler));
    let tachyon_app = Router::new().route("/", t_get(handler));

    assert_same_response(axum_app, tachyon_app, || get("/")).await;
}

#[tokio::test]
async fn not_found_matches() {
    async fn handler() -> &'static str {
        "hello"
    }
    let axum_app = axum::Router::new().route("/", axum_get(handler));
    let tachyon_app = Router::new().route("/", t_get(handler));

    // Both must 404 — the exact body text ("Not Found" wording) is each
    // framework's own diagnostic prose, not a compatibility claim.
    assert_same_status(axum_app, tachyon_app, || get("/nope")).await;
}

#[tokio::test]
async fn method_not_allowed_matches() {
    async fn handler() -> &'static str {
        "hello"
    }
    let axum_app = axum::Router::new().route("/x", axum_get(handler));
    let tachyon_app = Router::new().route("/x", t_get(handler));

    assert_same_status(axum_app, tachyon_app, || request("POST", "/x")).await;
}

#[tokio::test]
async fn any_dispatches_every_method() {
    use axum::routing::any as axum_any;
    use tachyon_web::routing::any;

    async fn handler() -> &'static str {
        "any"
    }
    let axum_app = axum::Router::new().route("/x", axum_any(handler));
    let tachyon_app = Router::new().route("/x", any(handler));

    for method in ["GET", "POST", "PUT", "DELETE", "PATCH"] {
        assert_same_response(axum_app.clone(), tachyon_app.clone(), || {
            request(method, "/x")
        })
        .await;
    }
}

/// Registering the same path twice with different (non-overlapping) methods
/// must merge into a single route answering both — not be rejected as a
/// "duplicate route", which was tachyon-web's old behavior before this was
/// fixed to match Axum's `Router::route` merge semantics.
#[tokio::test]
async fn separate_route_calls_with_different_methods_merge() {
    use axum::routing::post as axum_post;
    use tachyon_web::post as t_post;

    async fn get_handler() -> &'static str {
        "got"
    }
    async fn post_handler() -> &'static str {
        "posted"
    }

    let axum_app = axum::Router::new()
        .route("/merged", axum_get(get_handler))
        .route("/merged", axum_post(post_handler));
    let tachyon_app = Router::new()
        .route("/merged", t_get(get_handler))
        .route("/merged", t_post(post_handler));

    assert_same_response(axum_app.clone(), tachyon_app.clone(), || get("/merged")).await;
    assert_same_response(axum_app, tachyon_app, || request("POST", "/merged")).await;
}

/// Registering the *same* method for the same path twice must panic on both
/// frameworks — Axum panics eagerly with "Overlapping method route"; this
/// proves tachyon-web now does too, instead of silently accepting it or only
/// surfacing a `Result::Err` at a later `.compile()` call.
#[test]
fn overlapping_method_route_panics_on_both() {
    async fn a() -> &'static str {
        "a"
    }
    async fn b() -> &'static str {
        "b"
    }

    let axum_panicked = std::panic::catch_unwind(|| {
        axum::Router::<()>::new()
            .route("/dup", axum_get(a))
            .route("/dup", axum_get(b))
    })
    .is_err();

    let tachyon_panicked = std::panic::catch_unwind(|| {
        Router::<()>::new()
            .route("/dup", t_get(a))
            .route("/dup", t_get(b))
    })
    .is_err();

    assert_eq!(
        axum_panicked, tachyon_panicked,
        "axum and tachyon-web disagree on whether registering the same method \
         twice for the same path panics"
    );
    assert!(axum_panicked, "expected both frameworks to panic here");
}

#[tokio::test]
async fn status_code_response_matches() {
    async fn handler() -> hyper::StatusCode {
        hyper::StatusCode::IM_A_TEAPOT
    }
    let axum_app = axum::Router::new().route("/teapot", axum_get(handler));
    let tachyon_app = Router::new().route("/teapot", t_get(handler));

    assert_same_response(axum_app, tachyon_app, || get("/teapot")).await;
}

/// `Router::merge` must adopt the one fallback present on either side, not
/// silently drop it — an unmatched path on the merged router should still
/// reach it, same as Axum.
#[tokio::test]
async fn merge_adopts_the_one_fallback_present() {
    async fn handler() -> &'static str {
        "h"
    }
    async fn fallback() -> &'static str {
        "custom-fallback"
    }

    let axum_app = axum::Router::new().route("/r1", axum_get(handler)).merge(
        axum::Router::new()
            .route("/r2", axum_get(handler))
            .fallback(fallback),
    );
    let tachyon_app = Router::new().route("/r1", t_get(handler)).merge(
        Router::new()
            .route("/r2", t_get(handler))
            .fallback(fallback),
    );

    assert_same_response(axum_app, tachyon_app, || get("/does-not-exist")).await;
}

/// Merging two routers that both already have a `fallback` configured must
/// panic on both frameworks — matching Axum's "Cannot merge two `Router`s
/// that both have a fallback".
#[test]
fn merge_two_fallbacks_panics_on_both() {
    async fn fb1() -> &'static str {
        "fb1"
    }
    async fn fb2() -> &'static str {
        "fb2"
    }

    let axum_panicked = std::panic::catch_unwind(|| {
        axum::Router::<()>::new()
            .fallback(fb1)
            .merge(axum::Router::<()>::new().fallback(fb2))
    })
    .is_err();

    let tachyon_panicked = std::panic::catch_unwind(|| {
        Router::<()>::new()
            .fallback(fb1)
            .merge(Router::<()>::new().fallback(fb2))
    })
    .is_err();

    assert_eq!(
        axum_panicked, tachyon_panicked,
        "axum and tachyon-web disagree on whether merging two routers that both \
         have a fallback panics"
    );
    assert!(axum_panicked, "expected both frameworks to panic here");
}
