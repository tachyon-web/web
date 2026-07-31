//! Shared harness for golden-response parity tests between real `axum` and
//! `tachyon-web`.
//!
//! The core idea: build the *same* route/handler twice — once wired into a
//! real `axum::Router`, once into a `tachyon_web::Router` — drive both
//! through their actual `tower::Service` implementation with an identical
//! request, and diff status/headers/body. This is a black-box behavioral
//! check, not a compile-only shape check: if tachyon-web's routing,
//! extractors, or response handling ever silently diverge from Axum for a
//! feature this suite covers, one of these tests fails.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use std::collections::BTreeMap;
use tower::ServiceExt;

/// A normalized snapshot of an HTTP response, comparable across the two
/// frameworks' distinct `Response<B>` body types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub status: u16,
    /// Sorted `(lowercase name, value)` pairs, excluding headers whose exact
    /// value is expected to differ or is inherently non-deterministic (see
    /// [`Self::from_response`]).
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Header names excluded from comparison: either genuinely non-deterministic
/// (a real clock/date), a framework-identity detail neither side claims to
/// match (e.g. Axum has no equivalent of a `Server` banner), or — for
/// `content-length` — a wire-protocol detail that a real `hyper` connection
/// computes from the body's `size_hint()` identically for both frameworks at
/// serialization time, but which may or may not already be present on the
/// in-memory `Response` these tests inspect (since `.oneshot()` stops short of
/// actual wire serialization). Framework routing/handler behavior is what
/// these tests check; transport-layer header injection is not.
const IGNORED_HEADERS: &[&str] = &["date", "server", "content-length"];

impl Probe {
    async fn from_response<B>(resp: Response<B>) -> Self
    where
        B: hyper::body::Body<Data = Bytes>,
        B::Error: std::fmt::Debug,
    {
        let status = resp.status().as_u16();
        let (parts, body) = resp.into_parts();
        let mut headers = BTreeMap::new();
        for (name, value) in &parts.headers {
            let name = name.as_str().to_ascii_lowercase();
            if IGNORED_HEADERS.contains(&name.as_str()) {
                continue;
            }
            headers.insert(name, value.to_str().unwrap_or("<non-utf8>").to_string());
        }
        let body = body
            .collect()
            .await
            .expect("collecting response body")
            .to_bytes()
            .to_vec();
        Self {
            status,
            headers,
            body,
        }
    }

    /// Asserts this probe's body deserializes as JSON equal to `expected`,
    /// comparing semantically (field order doesn't matter) rather than byte-for-byte.
    #[track_caller]
    pub fn assert_json_body_eq(&self, expected: serde_json::Value) {
        let actual: serde_json::Value = serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "response body is not valid JSON: {e}\nbody: {}",
                String::from_utf8_lossy(&self.body)
            )
        });
        assert_eq!(actual, expected, "JSON body mismatch");
    }

    /// The body decoded as UTF-8, for plain-text assertions.
    #[track_caller]
    #[must_use]
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).expect("response body is not valid UTF-8")
    }
}

/// Drives a real `axum::Router` with `req` and returns a normalized [`Probe`].
///
/// # Panics
/// Panics if the request or the resulting response cannot be processed —
/// acceptable in test code, where an unexpected panic is a clear test failure.
pub async fn axum_probe(app: axum::Router, req: Request<Full<Bytes>>) -> Probe {
    let req = req.map(axum::body::Body::new);
    let resp = app
        .oneshot(req)
        .await
        .expect("axum::Router::oneshot is infallible");
    Probe::from_response(resp).await
}

/// Drives a tachyon-web router with `req` and returns a normalized [`Probe`],
/// via the same `tower::Service`/`oneshot` path used for `axum` above — down
/// to accepting a plain, uncompiled `Router<()>` with no `.compile()` call,
/// exactly like `axum_probe` accepts a plain `axum::Router`. This is exactly
/// the mechanism a ported Axum test suite would use, unmodified.
///
/// # Panics
/// Panics if the request or the resulting response cannot be processed.
pub async fn tachyon_probe(app: tachyon_web::Router<()>, req: Request<Full<Bytes>>) -> Probe {
    let resp = app
        .oneshot(req)
        .await
        .expect("Router::oneshot is infallible");
    Probe::from_response(resp).await
}

/// Runs the same request against both frameworks and asserts the resulting
/// [`Probe`]s are identical — status, headers, *and* body.
///
/// Use this only where the body is deterministic, framework-agnostic content
/// (a literal string a handler returns, a JSON payload echoed straight back,
/// an extracted path/query value). For responses that carry a framework's own
/// diagnostic wording (a 400/404/405/500 error body), the *status code* is the
/// actual compatibility claim — the prose is an implementation detail neither
/// framework promises byte-for-byte, so use [`assert_same_status`] instead.
///
/// # Panics
/// Panics (via `assert_eq!`) if the two frameworks' responses differ, or if
/// either request/response fails to process.
pub async fn assert_same_response(
    axum_app: axum::Router,
    tachyon_app: tachyon_web::Router<()>,
    make_request: impl Fn() -> Request<Full<Bytes>>,
) {
    let axum_result = axum_probe(axum_app, make_request()).await;
    let tachyon_result = tachyon_probe(tachyon_app, make_request()).await;
    assert_eq!(
        axum_result, tachyon_result,
        "axum and tachyon-web responses diverged for the same request"
    );
}

/// Runs the same request against both frameworks and asserts only the
/// **status code** matches — see [`assert_same_response`]'s docs for when to
/// reach for this instead (error/diagnostic response bodies).
///
/// # Panics
/// Panics (via `assert_eq!`) if the status codes differ, or if either
/// request/response fails to process.
pub async fn assert_same_status(
    axum_app: axum::Router,
    tachyon_app: tachyon_web::Router<()>,
    make_request: impl Fn() -> Request<Full<Bytes>>,
) {
    let axum_result = axum_probe(axum_app, make_request()).await;
    let tachyon_result = tachyon_probe(tachyon_app, make_request()).await;
    assert_eq!(
        axum_result.status, tachyon_result.status,
        "axum and tachyon-web status codes diverged for the same request\naxum body: {}\ntachyon body: {}",
        String::from_utf8_lossy(&axum_result.body),
        String::from_utf8_lossy(&tachyon_result.body),
    );
}

/// Convenience: builds a `Request<Full<Bytes>>` with no body.
#[must_use]
pub fn get_req(uri: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .expect("valid request")
}

/// Convenience: builds a `Request<Full<Bytes>>` with the given method, no body.
#[must_use]
pub fn request(method: &str, uri: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .expect("valid request")
}

/// Convenience: builds a JSON POST request.
#[must_use]
pub fn post_json(uri: &str, json: &serde_json::Value) -> Request<Full<Bytes>> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json.to_string())))
        .expect("valid request")
}
