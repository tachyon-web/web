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
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tachyon_web::Router;
use tachyon_web::http::response::Body;
use tower::Service;

/// A tiny `tower::Service` that echoes back the URI it actually received
/// (path + query), so tests can assert on exactly what `nest_service`
/// forwarded downstream.
#[derive(Clone)]
struct EchoUriService {
    last_uri: Arc<Mutex<String>>,
}

impl Service<Request<Bytes>> for EchoUriService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Bytes>) -> Self::Future {
        let uri = req.uri().to_string();
        self.last_uri.lock().unwrap().clone_from(&uri);
        Box::pin(async move { Ok(Response::new(Full::new(Bytes::from(uri)))) })
    }
}

async fn body_to_string(body: Body) -> String {
    use http_body_util::BodyExt;
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn test_nest_service_preserves_query_string() {
    let last_uri = Arc::new(Mutex::new(String::new()));
    let svc = EchoUriService {
        last_uri: last_uri.clone(),
    };
    let router = Router::new()
        .nest_service("/api", svc)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder()
        .method("GET")
        .uri("/api/users/42?page=2&sort=asc")
        .body(Body::empty())
        .unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let seen = last_uri.lock().unwrap().clone();
    assert_eq!(seen, "/users/42?page=2&sort=asc");
}

#[tokio::test]
async fn test_nest_service_no_query_string() {
    let last_uri = Arc::new(Mutex::new(String::new()));
    let svc = EchoUriService {
        last_uri: last_uri.clone(),
    };
    let router = Router::new()
        .nest_service("/api", svc)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder()
        .method("GET")
        .uri("/api/users/42")
        .body(Body::empty())
        .unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let seen = last_uri.lock().unwrap().clone();
    assert_eq!(seen, "/users/42");
}

/// A percent-encoded `?` inside a path segment must stay part of the path
/// after prefix-stripping — it must never be reinterpreted as introducing a
/// query string the router never saw (the "confused deputy" case).
#[tokio::test]
async fn test_nest_service_does_not_synthesize_query_from_encoded_path() {
    let last_uri = Arc::new(Mutex::new(String::new()));
    let svc = EchoUriService {
        last_uri: last_uri.clone(),
    };
    let router = Router::new()
        .nest_service("/api", svc)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder()
        .method("GET")
        .uri("/api/foo%3Fadmin=1")
        .body(Body::empty())
        .unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let seen = last_uri.lock().unwrap().clone();
    // The raw (still percent-encoded) path is stripped and forwarded as-is —
    // no new query component is synthesized from the encoded path bytes.
    assert_eq!(seen, "/foo%3Fadmin=1");

    let body = body_to_string(resp.into_body()).await;
    assert_eq!(body, "/foo%3Fadmin=1");
}

/// The idiomatic Axum testing pattern — `app.oneshot(request).await` via
/// `tower::ServiceExt` — must work unchanged against a compiled tachyon
/// router, since `CompiledRouter` implements `tower::Service`.
#[tokio::test]
async fn test_compiled_router_oneshot() {
    use tachyon_web::get;
    use tower::ServiceExt;

    async fn hello() -> &'static str {
        "hello from oneshot"
    }

    let router = Router::new()
        .route("/", get(hello))
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    assert_eq!(body, "hello from oneshot");
}

/// A `tower::Service` whose `poll_ready` always errors — exercises the
/// `service.ready().await` `Err` branch shared by `ServiceHandler::call` and
/// `from_tower_layer`.
#[derive(Clone)]
struct AlwaysFailsReady;

impl Service<Request<Bytes>> for AlwaysFailsReady {
    type Response = Response<Full<Bytes>>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Err(std::io::Error::other("never ready")))
    }

    fn call(&mut self, _req: Request<Bytes>) -> Self::Future {
        unreachable!("poll_ready always errors, so ready() never lets call() run")
    }
}

/// A `tower::Service` that's ready immediately but whose `call` future always
/// errors — exercises the `ready.call(req).await` `Err` branch shared by
/// `ServiceHandler::call` and `from_tower_layer`.
#[derive(Clone)]
struct AlwaysFailsCall;

impl Service<Request<Bytes>> for AlwaysFailsCall {
    type Response = Response<Full<Bytes>>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Bytes>) -> Self::Future {
        Box::pin(async { Err(std::io::Error::other("call always fails")) })
    }
}

/// A `tower::Layer` that hands back whatever inner service it's given
/// unchanged — enough to prove `.layer()`/`.route_layer()` actually thread a
/// real `tower::Layer` through `NextService`/`from_tower_layer` end to end.
#[derive(Clone)]
struct PassThroughLayer;

impl<S> tower::Layer<S> for PassThroughLayer {
    type Service = S;
    fn layer(&self, inner: S) -> S {
        inner
    }
}

/// A `tower::Layer` that discards whatever it's wrapping and always hands
/// back `AlwaysFailsReady` — used to drive `.layer()`'s error branches
/// without needing a real failing continuation.
#[derive(Clone)]
struct AlwaysFailsReadyLayer;

impl<S> tower::Layer<S> for AlwaysFailsReadyLayer {
    type Service = AlwaysFailsReady;
    fn layer(&self, _inner: S) -> AlwaysFailsReady {
        AlwaysFailsReady
    }
}

/// Same idea as [`AlwaysFailsReadyLayer`] but for the `call()`-fails branch.
#[derive(Clone)]
struct AlwaysFailsCallLayer;

impl<S> tower::Layer<S> for AlwaysFailsCallLayer {
    type Service = AlwaysFailsCall;
    fn layer(&self, _inner: S) -> AlwaysFailsCall {
        AlwaysFailsCall
    }
}

/// `Router::layer` must actually thread requests through the installed
/// `tower::Layer` (via `from_tower_layer`/`NextService`) rather than just
/// accepting and ignoring it.
#[tokio::test]
async fn test_layer_wraps_every_route_via_tower_layer() {
    use tachyon_web::get;

    async fn hello() -> &'static str {
        "hello from layer"
    }

    let router = Router::new()
        .route("/", get(hello))
        .layer(PassThroughLayer)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    assert_eq!(body, "hello from layer");
}

/// `Router::route_layer` applies to registered routes but must leave the
/// fallback untouched — matching Axum's `.layer()` vs `.route_layer()` split.
#[tokio::test]
async fn test_route_layer_does_not_wrap_the_fallback() {
    use tachyon_web::get;

    async fn hello() -> &'static str {
        "hello from route_layer"
    }
    async fn fallback() -> &'static str {
        "fallback"
    }

    let router = Router::new()
        .route("/", get(hello))
        .fallback(fallback)
        .route_layer(PassThroughLayer)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    assert_eq!(body, "hello from route_layer");

    let miss_req = Request::builder()
        .uri("/nowhere")
        .body(Body::empty())
        .unwrap();
    let miss_resp = router.handle_request(miss_req).await;
    assert_eq!(miss_resp.status(), StatusCode::OK);
    let miss_body = body_to_string(miss_resp.into_body()).await;
    assert_eq!(miss_body, "fallback");
}

/// A `tower::Layer` whose wrapped service's `poll_ready` errors must surface
/// as a 500, driven through `from_tower_layer`'s `service.ready().await` err
/// branch.
#[tokio::test]
async fn test_layer_surfaces_service_not_ready_as_500() {
    use tachyon_web::get;

    async fn hello() -> &'static str {
        "unreachable"
    }

    let router = Router::new()
        .route("/", get(hello))
        .layer(AlwaysFailsReadyLayer)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// A `tower::Layer` whose wrapped service's `call` future errors must also
/// surface as a 500, driven through `from_tower_layer`'s
/// `ready.call(req).await` err branch.
#[tokio::test]
async fn test_layer_surfaces_service_call_failure_as_500() {
    use tachyon_web::get;

    async fn hello() -> &'static str {
        "unreachable"
    }

    let router = Router::new()
        .route("/", get(hello))
        .layer(AlwaysFailsCallLayer)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// `ServiceHandler::call` (the `route_service`/`nest_service`/
/// `fallback_service` path) must reject an oversized body with 413 rather
/// than buffering it unbounded — the same `collect_bytes(limit)` err branch
/// `from_tower_layer` also has.
#[tokio::test]
async fn test_route_service_rejects_oversized_body() {
    let last_uri = Arc::new(Mutex::new(String::new()));
    let svc = EchoUriService { last_uri };
    let router = Router::new()
        .route_service("/echo", svc)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let oversized = vec![0u8; 2 * 1024 * 1024 + 1];
    let req = Request::builder()
        .method("POST")
        .uri("/echo")
        .body(Body::full(Bytes::from(oversized)))
        .unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A raw `tower::Service` mounted via `route_service` whose `poll_ready`
/// errors must surface as a 500 (`ServiceHandler::call`'s
/// `service.ready().await` err branch).
#[tokio::test]
async fn test_route_service_surfaces_service_not_ready_as_500() {
    let router = Router::new()
        .route_service("/svc", AlwaysFailsReady)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder().uri("/svc").body(Body::empty()).unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// A raw `tower::Service` mounted via `route_service` whose `call` future
/// errors must also surface as a 500 (`ServiceHandler::call`'s
/// `ready.call(req).await` err branch).
#[tokio::test]
async fn test_route_service_surfaces_service_call_failure_as_500() {
    let router = Router::new()
        .route_service("/svc", AlwaysFailsCall)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    let req = Request::builder().uri("/svc").body(Body::empty()).unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// `Router::fallback_service` must route any request that doesn't match a
/// registered route to the mounted raw `tower::Service`, exactly like
/// `.fallback()` does for a native handler.
#[tokio::test]
async fn test_fallback_service_routes_unmatched_requests() {
    use tachyon_web::get;

    async fn hello() -> &'static str {
        "hello"
    }

    let last_uri = Arc::new(Mutex::new(String::new()));
    let svc = EchoUriService {
        last_uri: last_uri.clone(),
    };

    let router = Router::new()
        .route("/", get(hello))
        .fallback_service(svc)
        .with_state::<()>(())
        .compile()
        .expect("compile");

    // A registered route is unaffected by the fallback service.
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    assert_eq!(body, "hello");

    // An unmatched path falls through to the tower service, which sees (and
    // echoes back) the untouched request URI.
    let req = Request::builder()
        .uri("/no/such/route?x=1")
        .body(Body::empty())
        .unwrap();
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    assert_eq!(body, "/no/such/route?x=1");

    let seen = last_uri.lock().unwrap().clone();
    assert_eq!(seen, "/no/such/route?x=1");
}
