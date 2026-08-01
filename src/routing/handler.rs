//! Handler trait and its implementations for async functions of various arities.
//!
//! This module provides the `Handler` trait, which is implemented automatically for
//! `async fn`s with 0 to 16 extractors. The macro-generated impls are repetitive by
//! necessity – Rust has no variadic generics yet – but are confined here to keep
//! `routing/mod.rs` focused on routing logic.

use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crate::http::response::{Body, IntoResponse};
use crate::routing::extract::{FromRequest, FromRequestParts};

/// A future that might be immediately ready, avoiding heap allocation.
pub enum ResponseFuture {
    /// The response was resolved immediately without any async waiting.
    Ready(Option<Response<Body>>),
    /// The response is pending and boxed.
    Boxed(Pin<Box<dyn Future<Output = Response<Body>> + Send + 'static>>),
}

impl std::fmt::Debug for ResponseFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(res) => f.debug_tuple("Ready").field(res).finish(),
            Self::Boxed(_) => f.debug_tuple("Boxed").field(&"<future>").finish(),
        }
    }
}

impl Future for ResponseFuture {
    type Output = Response<Body>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Ready(res) => res.take().map_or_else(
                || unreachable!("ResponseFuture polled after completion"),
                Poll::Ready,
            ),
            Self::Boxed(fut) => fut.as_mut().poll(cx),
        }
    }
}

fn noop_waker() -> Waker {
    Waker::noop().clone()
}

/// A pinned, boxed, `Send` future returning an HTTP response, or an immediately resolved response.
pub type BoxedFuture = ResponseFuture;

/// A type-erased handler: `Arc<dyn Fn(Request<Body>, Arc<S>) -> BoxedFuture>`.
pub type BoxedHandler<S> =
    Arc<dyn Fn(Request<Body>, Arc<S>) -> BoxedFuture + Send + Sync + 'static>;

/// Marker for asynchronous handlers.
#[derive(Debug)]
pub struct AsyncHandler<T>(std::marker::PhantomData<T>);

/// Marker for synchronous handlers.
#[derive(Debug)]
pub struct SyncHandler<T>(std::marker::PhantomData<T>);

/// Trait for types that can handle an HTTP request.
///
/// This is blanket-implemented for both `async fn`s (which are marked with `AsyncHandler`) and
/// synchronous `fn`/closures (which are marked with `SyncHandler`).
///
/// # Performance & Zero-Allocation Routing
/// - **Arity-0 handlers** (no extractors) take the fast path: synchronous ones return
///   `ResponseFuture::Ready` directly with zero box allocations; async ones are eagerly
///   polled once (the same future instance is kept and reused if it turns out to be
///   pending, never re-invoked, so any side effects before the first `.await` still run
///   exactly once) and only fall back to a boxed future (`ResponseFuture::Boxed`) if they
///   actually yield (i.e. genuinely await something).
/// - **Handlers with ≥1 extractor** always go through `ResponseFuture::Boxed`, sync or async.
///   This is because the last extractor implements [`FromRequest`], which is `async` (bodies
///   may be streamed in rather than already buffered — see [`crate::routing::extract::BodyStream`]),
///   so it can't be resolved before deciding `Ready` vs. `Boxed`.
///
/// # ⚠️ Thread Starvation & Blocking Warning
/// Because Tachyon runs on a cooperative async thread pool (Tokio), blocking any worker thread
/// with long-running synchronous code (e.g. `std::fs::read` or blocking database calls) will stall the event loop.
/// - **DO**: Use sync handlers ONLY for instant CPU operations (e.g., formatting data, static templates, or simple state reads).
/// - **DON'T**: Do heavy or blocking I/O synchronously inside sync handlers. Instead, use async versions or offload
///   blocking calls to `tokio::task::spawn_blocking`.
pub trait Handler<T, S>: Clone + Send + Sync + 'static {
    /// Consume `self` and produce a future that resolves to the response.
    fn call(self, req: Request<Body>, state: Arc<S>) -> BoxedFuture;
}

// ─── arity 0 ─────────────────────────────────────────────────────────────────

// Async version
impl<F, Fut, S, Res> Handler<AsyncHandler<()>, S> for F
where
    F: Fn() -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
    S: Send + Sync + 'static,
{
    fn call(self, _req: Request<Body>, _state: Arc<S>) -> BoxedFuture {
        // Poll the *same* future instance that's returned as `Boxed` on `Pending` —
        // re-invoking `self()` to get a "fresh" future (the previous approach) runs
        // the handler body a second time from scratch, silently double-executing any
        // side effects (logging, counters, mutex work, ...) that happen before the
        // first await point. Pinning via `Box::pin` up front costs one allocation
        // even on the immediately-ready path, but that's the price of only ever
        // running the handler once.
        let mut boxed: Pin<Box<dyn Future<Output = Res> + Send>> = Box::pin(self());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match boxed.as_mut().poll(&mut cx) {
            Poll::Ready(res) => ResponseFuture::Ready(Some(res.into_response())),
            Poll::Pending => {
                ResponseFuture::Boxed(Box::pin(async move { boxed.await.into_response() }))
            }
        }
    }
}

// Sync version
impl<F, S, Res> Handler<SyncHandler<()>, S> for F
where
    F: Fn() -> Res + Clone + Send + Sync + 'static,
    Res: IntoResponse + Send + 'static,
    S: Send + Sync + 'static,
{
    fn call(self, _req: Request<Body>, _state: Arc<S>) -> BoxedFuture {
        ResponseFuture::Ready(Some(self().into_response()))
    }
}

// ─── arities 1-8 (macro-generated) ──────────────────────────────────────────

macro_rules! impl_handler {
    ( $($ty:ident),* ; $last:ident ) => {
        // Async version
        impl<F, Fut, S, Res, $($ty,)* $last> Handler<AsyncHandler<( $($ty,)* $last, )>, S> for F
        where
            F: Fn($($ty,)* $last) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = Res> + Send + 'static,
            Res: IntoResponse + Send + 'static,
            $( $ty: FromRequestParts<S> + Send + 'static, )*
            $last: FromRequest<S> + Send + 'static,
            S: Send + Sync + 'static,
        {
            #[allow(non_snake_case, unused_mut)]
            fn call(self, req: Request<Body>, state: Arc<S>) -> BoxedFuture {
                let (mut parts, body) = req.into_parts();
                $(
                    let $ty = match <$ty as FromRequestParts<S>>::from_request_parts(&mut parts, &*state) {
                        Ok(v) => v,
                        Err(r) => return ResponseFuture::Ready(Some(r.into_response())),
                    };
                )*
                // The last extractor is `FromRequest`, which is `async` (it may need to
                // await the body being streamed in) — so, unlike the parts extractors
                // above, it can't be resolved before deciding Ready vs. Boxed. Every
                // handler with at least one argument therefore goes through `Boxed`.
                ResponseFuture::Boxed(Box::pin(async move {
                    let req = Request::from_parts(parts, body);
                    let $last = match <$last as FromRequest<S>>::from_request(req, &*state).await {
                        Ok(v) => v,
                        Err(r) => return r.into_response(),
                    };
                    self($($ty,)* $last).await.into_response()
                }))
            }
        }

        // Sync version
        impl<F, S, Res, $($ty,)* $last> Handler<SyncHandler<( $($ty,)* $last, )>, S> for F
        where
            F: Fn($($ty,)* $last) -> Res + Clone + Send + Sync + 'static,
            Res: IntoResponse + Send + 'static,
            $( $ty: FromRequestParts<S> + Send + 'static, )*
            $last: FromRequest<S> + Send + 'static,
            S: Send + Sync + 'static,
        {
            #[allow(non_snake_case, unused_mut)]
            fn call(self, req: Request<Body>, state: Arc<S>) -> BoxedFuture {
                let (mut parts, body) = req.into_parts();
                $(
                    let $ty = match <$ty as FromRequestParts<S>>::from_request_parts(&mut parts, &*state) {
                        Ok(v) => v,
                        Err(r) => return ResponseFuture::Ready(Some(r.into_response())),
                    };
                )*
                // See the async version above for why this can't stay on the `Ready` path.
                ResponseFuture::Boxed(Box::pin(async move {
                    let req = Request::from_parts(parts, body);
                    let $last = match <$last as FromRequest<S>>::from_request(req, &*state).await {
                        Ok(v) => v,
                        Err(r) => return r.into_response(),
                    };
                    self($($ty,)* $last).into_response()
                }))
            }
        }
    };
}

impl_handler!(; A1);
impl_handler!(A1; A2);
impl_handler!(A1, A2; A3);
impl_handler!(A1, A2, A3; A4);
impl_handler!(A1, A2, A3, A4; A5);
impl_handler!(A1, A2, A3, A4, A5; A6);
impl_handler!(A1, A2, A3, A4, A5, A6; A7);
impl_handler!(A1, A2, A3, A4, A5, A6, A7; A8);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8; A9);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8, A9; A10);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10; A11);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11; A12);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12; A13);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13; A14);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14; A15);
impl_handler!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15; A16);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    struct FailParts;
    impl<S> FromRequestParts<S> for FailParts {
        type Rejection = crate::http::error::Error;
        fn from_request_parts(
            _parts: &mut hyper::http::request::Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Err(crate::http::error::Error::Rejection {
                status: hyper::StatusCode::BAD_REQUEST,
                message: "parts fail".to_string(),
            })
        }
    }

    struct FailReq;
    impl<S: Sync> FromRequest<S> for FailReq {
        type Rejection = crate::http::error::Error;
        async fn from_request(_req: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
            Err(crate::http::error::Error::Rejection {
                status: hyper::StatusCode::BAD_REQUEST,
                message: "req fail".to_string(),
            })
        }
    }

    struct SucceedParts;
    impl<S> FromRequestParts<S> for SucceedParts {
        type Rejection = crate::http::error::Error;
        fn from_request_parts(
            _parts: &mut hyper::http::request::Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(Self)
        }
    }

    struct SucceedReq;
    impl<S: Sync> FromRequest<S> for SucceedReq {
        type Rejection = crate::http::error::Error;
        async fn from_request(_req: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
            Ok(Self)
        }
    }

    #[tokio::test]
    async fn test_handler_failures() {
        async fn h1(_p: FailParts, _r: FailReq) -> &'static str {
            "ok"
        }

        let req = Request::builder().body(Body::empty()).unwrap();
        let fut = h1.call(req, Arc::new(()));
        let res = fut.await;
        assert_eq!(res.status(), hyper::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_arity0_async_handler_runs_side_effects_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);

        async fn probe() -> &'static str {
            CALLS.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            "ok"
        }

        let req = Request::builder().body(Body::empty()).unwrap();
        let fut = probe.call(req, Arc::new(()));
        let res = fut.await;
        assert_eq!(res.status(), hyper::StatusCode::OK);
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "handler body ran more than once for a single request"
        );
    }

    /// A non-last extractor (`FromRequestParts`) that actually succeeds, paired with a
    /// failing last extractor — covers the `Ok(v) => v` arm of the parts-extraction loop,
    /// which every other test in this suite happens to only exercise via the `Err` arm.
    #[tokio::test]
    async fn test_handler_succeeds_on_parts_then_fails_on_last_extractor() {
        async fn h(_p: SucceedParts, _r: FailReq) -> &'static str {
            "unreachable"
        }

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = h.call(req, Arc::new(())).await;
        assert_eq!(res.status(), hyper::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_async_handler_with_all_extractors_succeeding() {
        async fn h(_p: SucceedParts, _r: SucceedReq) -> &'static str {
            "ok"
        }

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = h.call(req, Arc::new(())).await;
        assert_eq!(res.status(), hyper::StatusCode::OK);
    }

    /// Sync-handler variant of `test_handler_failures` — the parts-extraction `Err` branch
    /// of the *sync* `impl_handler!` arm is otherwise never exercised.
    #[tokio::test]
    async fn test_sync_handler_fails_on_parts_extractor() {
        fn h(_p: FailParts, _r: SucceedReq) -> &'static str {
            "unreachable"
        }

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = h.call(req, Arc::new(())).await;
        assert_eq!(res.status(), hyper::StatusCode::BAD_REQUEST);
    }

    /// Sync-handler variant covering the *sync* `impl_handler!` arm's last-extractor `Err`
    /// branch.
    #[tokio::test]
    async fn test_sync_handler_fails_on_last_extractor() {
        fn h(_p: SucceedParts, _r: FailReq) -> &'static str {
            "unreachable"
        }

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = h.call(req, Arc::new(())).await;
        assert_eq!(res.status(), hyper::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_sync_handler_with_all_extractors_succeeding() {
        fn h(_p: SucceedParts, _r: SucceedReq) -> &'static str {
            "ok"
        }

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = h.call(req, Arc::new(())).await;
        assert_eq!(res.status(), hyper::StatusCode::OK);
    }
}
