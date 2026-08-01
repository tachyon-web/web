use crate::common::TestServer;
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use tachyon_web::http::response::{Body, Html, Json};
use tachyon_web::routing::extract::{Cookies, Form};
use tachyon_web::{Router, get, post};

#[derive(Clone, Default)]
struct AppState {
    pub _counter: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct SubmitData {
    username: String,
    age: u8,
}

// 1. Cookies Test
async fn handle_cookies(cookies: Cookies) -> (Cookies, Html<String>) {
    let visited = if let Some(cookie) = cookies.get("visited") {
        cookie.value().to_string()
    } else {
        "no".to_string()
    };

    let cookies = cookies.add(Cookie::new("visited", "yes"));

    (cookies, Html(format!("Visited before: {}", visited)))
}

// 2. Form Extractor Test
async fn handle_form(Form(data): Form<SubmitData>) -> Json<SubmitData> {
    Json(data)
}

// 3. Streaming Body Test
async fn handle_stream() -> hyper::Response<Body> {
    use http_body_util::StreamBody;
    use hyper::body::Frame;
    use tokio_stream::wrappers::ReceiverStream;

    let (sender, receiver) = tokio::sync::mpsc::channel::<
        Result<Frame<bytes::Bytes>, tachyon_web::http::error::Error>,
    >(2);

    let _handle = tokio::spawn(async move {
        sender
            .send(Ok(Frame::data(bytes::Bytes::from("Chunk 1\n"))))
            .await
            .expect("expected result");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        sender
            .send(Ok(Frame::data(bytes::Bytes::from("Chunk 2\n"))))
            .await
            .expect("expected result");
    });

    let body = StreamBody::new(ReceiverStream::new(receiver));

    hyper::Response::builder()
        .status(200)
        .body(Body::stream(body))
        .expect("expected result")
}

#[tokio::test]
async fn test_advanced_features() {
    // Create nested API router
    let api_router = Router::new()
        .route("/form", post(handle_form))
        .route("/stream", get(handle_stream));

    // Create main app router
    let app = Router::new()
        .route("/cookies", get(handle_cookies))
        .nest("/api/v1", api_router)
        .with_state(AppState::default());

    // A cookie-storing client, so the second `/cookies` request sends back what the first set.
    let server = TestServer::spawn_with_cookie_store(app).await;

    // Cookies round-trip across two requests.
    let res = server.get("/cookies").send().await.expect("get /cookies");
    assert_eq!(res.text().await.unwrap(), "Visited before: no");
    let res = server.get("/cookies").send().await.expect("get /cookies");
    assert_eq!(res.text().await.unwrap(), "Visited before: yes");

    // Form extractor, on a nested route.
    let res = server
        .post("/api/v1/form")
        .form(&[("username", "hacer"), ("age", "30")])
        .send()
        .await
        .expect("post form");
    let submitted: SubmitData = res.json().await.expect("json");
    assert_eq!(submitted.username, "hacer");
    assert_eq!(submitted.age, 30);

    // Streaming body, on a nested route.
    let res = server.get("/api/v1/stream").send().await.expect("get stream");
    assert_eq!(res.text().await.unwrap(), "Chunk 1\nChunk 2\n");
}

#[test]
#[cfg(feature = "tls")]
fn test_custom_crypto_provider() {
    use std::sync::Arc;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let _server = tachyon_web::Server::new(Router::new()).crypto_provider(provider);
}

#[tokio::test]
async fn test_hoop_middleware() {
    use hyper::{Request, Response};
    use tachyon_web::routing::middleware::Next;

    async fn add_header(req: Request<Body>, next: Next<()>) -> Response<Body> {
        let mut res = next.run(req).await;
        let _ = res.headers_mut().insert(
            hyper::header::SERVER,
            hyper::header::HeaderValue::from_static("Tachyon"),
        );
        res
    }

    async fn handler() -> &'static str {
        "hello"
    }

    let app = Router::new().route("/hello", get(handler)).hoop(add_header);
    let server = TestServer::spawn(app).await;

    let res = server.get("/hello").send().await.unwrap();

    assert_eq!(res.headers().get("server").unwrap(), "Tachyon");
    assert_eq!(res.text().await.unwrap(), "hello");
}

#[tokio::test]
async fn test_hoop_at_ordering_and_state() {
    use hyper::{Request, Response};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tachyon_web::MiddlewarePosition;
    use tachyon_web::routing::middleware::Next;

    #[derive(Clone)]
    struct OrderState {
        counter: Arc<AtomicUsize>,
    }

    async fn first_mw(req: Request<Body>, next: Next<OrderState>) -> Response<Body> {
        let counter = next.state().counter.fetch_add(1, Ordering::SeqCst);
        let mut res = next.run(req).await;
        let _ = res.headers_mut().insert(
            hyper::header::HeaderName::from_static("x-first-order"),
            hyper::header::HeaderValue::from_str(&counter.to_string()).unwrap(),
        );
        res
    }

    async fn last_mw(req: Request<Body>, next: Next<OrderState>) -> Response<Body> {
        let counter = next.state().counter.fetch_add(1, Ordering::SeqCst);
        let mut res = next.run(req).await;
        let _ = res.headers_mut().insert(
            hyper::header::HeaderName::from_static("x-last-order"),
            hyper::header::HeaderValue::from_str(&counter.to_string()).unwrap(),
        );
        res
    }

    async fn handler() -> &'static str {
        "hello"
    }

    let state = OrderState {
        counter: Arc::new(AtomicUsize::new(0)),
    };

    let app = Router::new()
        .route("/hello", get(handler))
        .hoop_at(MiddlewarePosition::First, first_mw)
        .hoop_at(MiddlewarePosition::Last, last_mw)
        .with_state(state);
    let server = TestServer::spawn(app).await;

    let res = server.get("/hello").send().await.unwrap();

    let first_order = res
        .headers()
        .get("x-first-order")
        .unwrap()
        .to_str()
        .unwrap();
    let last_order = res.headers().get("x-last-order").unwrap().to_str().unwrap();

    assert_eq!(first_order, "0");
    assert_eq!(last_order, "1");
    assert_eq!(res.text().await.unwrap(), "hello");
}

#[tokio::test]
async fn test_eager_polling_safety_and_allocations() {
    use std::sync::Arc;
    use std::time::Duration;
    use tachyon_web::http::Request;
    use tachyon_web::routing::handler::{Handler, ResponseFuture};

    // 1. Dynamic route (arity 0 async fn with no awaits)
    // Should return dynamic values on every call, and should NOT allocate a Box (ResponseFuture::Ready).
    async fn get_time() -> String {
        format!(
            "time: {:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    let req1 = Request::builder().body(Body::empty()).unwrap();
    let res_fut1 = get_time.call(req1, Arc::new(()));
    assert!(
        matches!(res_fut1, ResponseFuture::Ready(_)),
        "Expected Ready for instant route"
    );
    let response1 = res_fut1.await;
    let body1 = response_to_string(response1).await;

    // Sleep for 1ms to ensure timestamp changes
    tokio::time::sleep(Duration::from_millis(1)).await;

    let req2 = Request::builder().body(Body::empty()).unwrap();
    let res_fut2 = get_time.call(req2, Arc::new(()));
    assert!(matches!(res_fut2, ResponseFuture::Ready(_)));
    let response2 = res_fut2.await;
    let body2 = response_to_string(response2).await;

    assert_ne!(
        body1, body2,
        "Dynamic time handler must return different values on different requests"
    );

    // 2. Yielding route (arity 0 async fn with actual await)
    // Should resolve correctly, and MUST return ResponseFuture::Boxed.
    async fn wait_a_bit() -> &'static str {
        tokio::time::sleep(Duration::from_millis(5)).await;
        "done"
    }

    let req3 = Request::builder().body(Body::empty()).unwrap();
    let res_fut3 = wait_a_bit.call(req3, Arc::new(()));
    assert!(
        matches!(res_fut3, ResponseFuture::Boxed(_)),
        "Expected Boxed for yielding route"
    );
    let response3 = res_fut3.await;
    let body3 = response_to_string(response3).await;
    assert_eq!(body3, "done");

    // 3. Synchronous route (arity 0 fn)
    // Should resolve to ResponseFuture::Ready directly.
    fn sync_handler() -> &'static str {
        "sync-ok"
    }

    let req4 = Request::builder().body(Body::empty()).unwrap();
    let res_fut4 = sync_handler.call(req4, Arc::new(()));
    assert!(
        matches!(res_fut4, ResponseFuture::Ready(_)),
        "Expected Ready for sync route"
    );
    let response4 = res_fut4.await;
    let body4 = response_to_string(response4).await;
    assert_eq!(body4, "sync-ok");

    // 4. Synchronous route with parameter extraction (arity 1 fn)
    // The last extractor is `FromRequest`, which is async (it may need to await the
    // body streaming in), so any handler with at least one argument goes through
    // `ResponseFuture::Boxed` — only arity-0 handlers can take the `Ready` fast path.
    use tachyon_web::routing::extract::State;
    fn sync_state_handler(State(state_val): State<String>) -> String {
        format!("state: {}", state_val)
    }

    let req5 = Request::builder().body(Body::empty()).unwrap();
    let res_fut5 = sync_state_handler.call(req5, Arc::new("app-state-value".to_string()));
    assert!(
        matches!(res_fut5, ResponseFuture::Boxed(_)),
        "Expected Boxed for extractor route (last extractor is async)"
    );
    let response5 = res_fut5.await;
    let body5 = response_to_string(response5).await;
    assert_eq!(body5, "state: app-state-value");
}

// Helper function to read body from response
async fn response_to_string(res: hyper::Response<tachyon_web::http::response::Body>) -> String {
    use http_body_util::BodyExt;
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body_bytes.to_vec()).unwrap()
}
