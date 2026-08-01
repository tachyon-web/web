use crate::http::response::Body;
use crate::routing::handler::BoxedHandler;
use hyper::{Request, Response};
use std::sync::Arc;

/// The continuation for the next handler or middleware in the chain.
///
/// Middleware functions take `Next` and call `next.run(req).await` to execute
/// the remaining pipeline.
pub struct Next<S> {
    pub(crate) handler: BoxedHandler<S>,
    pub(crate) state: Arc<S>,
}

impl<S> std::fmt::Debug for Next<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Next").finish_non_exhaustive()
    }
}

impl<S: Send + Sync + 'static> Next<S> {
    /// Executes the next handler in the pipeline.
    #[inline]
    pub async fn run(self, req: Request<Body>) -> Response<Body> {
        let Self { handler, state } = self;
        handler(req, state).await
    }

    /// Access the shared application state from within a middleware.
    #[inline]
    #[must_use]
    pub fn state(&self) -> &S {
        &self.state
    }
}

/// A boxed middleware closure.
pub type BoxedMiddleware<S> =
    Arc<dyn Fn(Request<Body>, Next<S>) -> crate::routing::handler::BoxedFuture + Send + Sync>;

/// Position of the middleware in the execution chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiddlewarePosition {
    /// Execute this middleware first (outermost layer).
    First,
    /// Execute this middleware last (innermost layer, right before the route handler).
    Last,
}

/// A wrapper around a route handler and its associated middlewares.
#[derive(Clone)]
pub struct MethodHandler<S> {
    pub(crate) raw: BoxedHandler<S>,
    pub(crate) middlewares: Vec<BoxedMiddleware<S>>,
    pub(crate) compiled: Option<BoxedHandler<S>>,
}

impl<S> std::fmt::Debug for MethodHandler<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodHandler")
            .field("middlewares_count", &self.middlewares.len())
            .field("compiled", &self.compiled.is_some())
            .finish_non_exhaustive()
    }
}

impl<S: Send + Sync + 'static> MethodHandler<S> {
    /// Create a new `MethodHandler`.
    pub fn new(raw: BoxedHandler<S>) -> Self {
        Self {
            raw,
            middlewares: Vec::new(),
            compiled: None,
        }
    }

    /// Folds `middlewares` around `raw` (innermost last) into a single boxed handler.
    fn build_chain(&self) -> BoxedHandler<S> {
        self.middlewares
            .iter()
            .rev()
            .fold(self.raw.clone(), |inner, mw| {
                let mw = mw.clone();
                Arc::new(move |req, state| {
                    let next = Next {
                        handler: inner.clone(),
                        state,
                    };
                    mw(req, next)
                })
            })
    }

    /// Compile the middleware chain into a single boxed handler.
    pub fn compile_in_place(&mut self) {
        if self.compiled.is_none() {
            self.compiled = Some(self.build_chain());
        }
    }

    /// Execute the handler chain.
    ///
    /// Uses the cached chain from [`compile_in_place`](Self::compile_in_place) when present;
    /// otherwise rebuilds it for this call (correct, but allocates per request — every route
    /// reached through a `Router` is compiled at `Router::compile()` time).
    pub async fn call(&self, req: Request<Body>, state: Arc<S>) -> Response<Body> {
        match &self.compiled {
            Some(compiled) => compiled(req, state).await,
            None => self.build_chain()(req, state).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MethodHandler, MiddlewarePosition, Next};
    use crate::http::response::{Body, IntoResponse};
    use crate::routing::handler::{BoxedFuture, BoxedHandler, ResponseFuture};
    use hyper::{Request, Response};
    use std::sync::Arc;

    fn handler_returning(body: &'static str) -> BoxedHandler<()> {
        Arc::new(move |_req, _state| {
            ResponseFuture::Boxed(Box::pin(async move { body.into_response() }))
        })
    }

    fn tag_header_middleware(
        name: &'static str,
    ) -> Arc<dyn Fn(Request<Body>, Next<()>) -> BoxedFuture + Send + Sync> {
        Arc::new(move |req, next| {
            ResponseFuture::Boxed(Box::pin(async move {
                let mut resp = next.run(req).await;
                resp.headers_mut()
                    .append("x-mw", name.parse().expect("valid header value"));
                resp
            }))
        })
    }

    #[test]
    fn middleware_position_variants_are_distinguishable() {
        assert_ne!(MiddlewarePosition::First, MiddlewarePosition::Last);
    }

    #[test]
    fn method_handler_debug_reports_middleware_count_and_compiled_state() {
        let mut mh = MethodHandler::new(handler_returning("hi"));
        assert!(format!("{mh:?}").contains("compiled: false"));

        mh.middlewares.push(tag_header_middleware("a"));
        mh.compile_in_place();
        let debug = format!("{mh:?}");
        assert!(debug.contains("middlewares_count: 1"));
        assert!(debug.contains("compiled: true"));
    }

    /// `call()` must run correctly even before `compile_in_place()` has ever been called —
    /// the uncompiled fallback path rebuilds the chain on every call instead of using the
    /// cached `compiled` handler.
    #[tokio::test]
    async fn call_runs_the_middleware_chain_even_when_not_yet_compiled() {
        let mut mh = MethodHandler::new(handler_returning("body"));
        mh.middlewares.push(tag_header_middleware("outer"));
        mh.middlewares.push(tag_header_middleware("inner"));
        assert!(mh.compiled.is_none());

        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = mh.call(req, Arc::new(())).await;

        let tags: Vec<&str> = resp
            .headers()
            .get_all("x-mw")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        // Middlewares run in registration order (each wraps the next), so the first
        // registered ("outer") is the outermost — its header gets appended last.
        assert_eq!(tags, vec!["inner", "outer"]);
    }

    #[tokio::test]
    async fn call_uses_the_cached_compiled_handler_once_compiled() {
        let mut mh = MethodHandler::new(handler_returning("body"));
        mh.middlewares.push(tag_header_middleware("only"));
        mh.compile_in_place();
        assert!(mh.compiled.is_some());

        let req = Request::builder().body(Body::empty()).unwrap();
        let resp: Response<Body> = mh.call(req, Arc::new(())).await;
        assert_eq!(
            resp.headers().get("x-mw").unwrap().to_str().unwrap(),
            "only"
        );
    }
}
