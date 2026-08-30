//! Tripwires for the axum-parity refactor (see the phased plan for
//! `scripts/api_diff.py`'s parity gap).
//!
//! These capture today's exact client-visible behavior — status codes and
//! body text — at the handful of call sites the plan's Phase 1-3 changes
//! (the `Error`/rejection redesign and `MethodRouter<S,E>` generic
//! threading) are most likely to silently reshape. Existing suites already
//! cover the corresponding *status codes* (`tower_tests`, `integration_tests`,
//! `ws_tests`); this file exists only to also pin the exact message text and
//! the few paths still routed through `http::error::Error` directly, so a
//! behavior change shows up as a failing assertion here rather than as
//! silent drift. Delete or fold these into the normal suites once the
//! refactor phases they're guarding have landed and stabilized.

#[cfg(feature = "ws")]
mod ws_handshake_rejections {
    use hyper::{Method, Request, StatusCode, header};
    use tachyon_web::http::response::Body;
    use tachyon_web::ws::WebSocketUpgrade;

    fn base_request(method: Method) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri("/ws")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap()
    }

    fn reject(req: Request<Body>) -> (StatusCode, String) {
        let (mut parts, _body) = req.into_parts();
        let err =
            WebSocketUpgrade::from_request_parts(&mut parts, &()).expect_err("must be rejected");
        let resp = tachyon_web::http::response::IntoResponse::into_response(err);
        let status = resp.status();
        (status, format!("{status}"))
    }

    #[test]
    fn wrong_method_is_405() {
        let (status, _) = reject(base_request(Method::POST));
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn missing_connection_header_is_400() {
        let mut req = base_request(Method::GET);
        req.headers_mut().remove(header::CONNECTION);
        let (status, _) = reject(req);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn missing_upgrade_header_is_400() {
        let mut req = base_request(Method::GET);
        req.headers_mut().remove(header::UPGRADE);
        let (status, _) = reject(req);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn wrong_websocket_version_is_400() {
        let mut req = base_request(Method::GET);
        req.headers_mut()
            .insert("sec-websocket-version", "8".parse().unwrap());
        let (status, _) = reject(req);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn missing_sec_websocket_key_is_400() {
        let mut req = base_request(Method::GET);
        req.headers_mut().remove("sec-websocket-key");
        let (status, _) = reject(req);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

mod core_error_response_shape {
    use hyper::StatusCode;
    use tachyon_web::http::error::Error;
    use tachyon_web::http::response::IntoResponse;

    /// An opaque `Error`'s message is deliberately not echoed to the client (it may carry
    /// server internals) — the body is always this fixed string. If Phase 1's redesign
    /// changes what travels through the opaque `Error`, this is the text that must keep
    /// showing up unless the change is intentional.
    #[tokio::test]
    async fn internal_error_body_is_the_generic_fallback_text() {
        let err = Error::new(std::io::Error::other("some internal detail"));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = tachyon_web::http::response::to_bytes(resp.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"Internal Server Error");
    }
}

#[cfg(feature = "http1")]
mod path_extractor_rejection_text {
    use crate::common::TestServer;
    use tachyon_web::routing::extract::Path;
    use tachyon_web::{Router, get};

    /// `Path<u32>` against a non-numeric segment. `PathRejection` is already fully decoupled
    /// from `http::error::Error` (see `routing/extract/rejection.rs`'s doc comment), so this
    /// is lower-risk than the WS/Error cases above, but Phase 5a's `ErrorKind` work touches
    /// this exact message, so it's worth pinning too.
    #[tokio::test]
    async fn non_numeric_segment_is_400_with_deserialize_failure_message() {
        async fn handler(Path(_id): Path<u32>) -> &'static str {
            "unreachable"
        }
        let server = TestServer::spawn(Router::new().route("/items/{id}", get(handler))).await;
        let res = server.get("/items/not-a-number").send().await.unwrap();
        assert_eq!(res.status(), 400);
        let body = res.text().await.unwrap();
        assert_eq!(body, "Invalid URL: Cannot parse `not-a-number` to a `u32`");
    }
}
