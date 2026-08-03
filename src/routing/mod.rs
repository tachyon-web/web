//! Axum-compatible routing: [`Router`], [`MethodRouter`], and the per-verb builders.

use bytes::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use std::future::Future;
use std::sync::Arc;

pub mod extract;
pub mod handler;
pub mod middleware;
pub mod static_dir;
#[cfg(feature = "tower")]
pub mod tower_compat;

use crate::http::response::{Body, IntoResponse};
use crate::routing::extract::PathParams;
pub use handler::{BoxedFuture, BoxedHandler, Handler};

const IDX_GET: usize = 0;
const IDX_POST: usize = 1;
const IDX_PUT: usize = 2;
const IDX_DELETE: usize = 3;
const IDX_OPTIONS: usize = 4;
const IDX_HEAD: usize = 5;
const IDX_PATCH: usize = 6;
const IDX_TRACE: usize = 7;
const IDX_CONNECT: usize = 8;
const METHOD_COUNT: usize = 9;

const METHOD_NAMES: [&str; METHOD_COUNT] = [
    "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT",
];

#[inline]
const fn method_index(m: &Method) -> Option<usize> {
    match *m {
        Method::GET => Some(IDX_GET),
        Method::POST => Some(IDX_POST),
        Method::PUT => Some(IDX_PUT),
        Method::DELETE => Some(IDX_DELETE),
        Method::OPTIONS => Some(IDX_OPTIONS),
        Method::HEAD => Some(IDX_HEAD),
        Method::PATCH => Some(IDX_PATCH),
        Method::TRACE => Some(IDX_TRACE),
        Method::CONNECT => Some(IDX_CONNECT),
        _ => None,
    }
}

/// Router that dispatches requests to different handlers based on the HTTP method.
#[derive(Clone)]
pub struct MethodRouter<S> {
    handlers: [Option<middleware::MethodHandler<S>>; METHOD_COUNT],
    /// Path-parameter names in declaration order, populated by `Router::compile()`. Cloning
    /// an `Arc<str>` into `PathParams` is a refcount bump rather than a per-request
    /// allocation.
    param_names: Arc<[Arc<str>]>,
    /// The route pattern this handler is registered under (e.g. `/users/{id}`), exposed via
    /// the [`MatchedPath`](crate::routing::extract::MatchedPath) extractor.
    matched_path: Arc<str>,
    /// The accumulated prefix to strip from the request `Uri` before dispatch, when this
    /// route was reached through one or more [`Router::nest`] calls.
    nest_prefix: Option<Arc<str>>,
}

impl<S> std::fmt::Debug for MethodRouter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("MethodRouter");
        for (name, handler) in METHOD_NAMES.iter().zip(&self.handlers) {
            let _ = dbg.field(name, &handler.is_some());
        }
        let _ = dbg.field("param_names", &self.param_names);
        let _ = dbg.field("matched_path", &self.matched_path);
        let _ = dbg.field("nest_prefix", &self.nest_prefix);
        dbg.finish()
    }
}

impl<S> Default for MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Create a new empty `MethodRouter`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: [const { None }; METHOD_COUNT],
            param_names: Arc::from([]),
            matched_path: Arc::from(""),
            nest_prefix: None,
        }
    }

    fn set<H, T>(mut self, idx: usize, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.handlers[idx] = Some(middleware::MethodHandler::new(Arc::new(
            move |req, state| handler.clone().call(req, state),
        )));
        self
    }

    /// The `Allow` header value listing every registered method, in Axum's format
    /// (comma-joined, no spaces). `HEAD` is listed whenever `GET` is, since a `GET` handler
    /// answers `HEAD` when no explicit one is registered.
    fn allow_header(&self) -> String {
        let mut out = String::with_capacity(56);
        let implicit_head = self.handlers[IDX_GET].is_some() && self.handlers[IDX_HEAD].is_none();
        for (i, name) in METHOD_NAMES.iter().enumerate() {
            if self.handlers[i].is_some() {
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(name);
                if i == IDX_GET && implicit_head {
                    out.push_str(",HEAD");
                }
            }
        }
        out
    }

    /// Merges `other`'s method handlers into `self`: registering the same path twice with
    /// non-overlapping methods combines into a single route, matching Axum.
    ///
    /// # Errors
    /// Returns [`RouterError::MethodOverlap`] if `other` defines a method already present in
    /// `self` — where Axum panics with "Overlapping method route".
    fn merge(mut self, mut other: Self, path: &str) -> Result<Self, RouterError> {
        for (i, (mine, theirs)) in self
            .handlers
            .iter_mut()
            .zip(other.handlers.iter_mut())
            .enumerate()
        {
            if let Some(handler) = theirs.take() {
                if mine.is_some() {
                    return Err(RouterError::MethodOverlap {
                        method: METHOD_NAMES[i],
                        path: path.to_string(),
                    });
                }
                *mine = Some(handler);
            }
        }
        if self.nest_prefix.is_none() {
            self.nest_prefix = other.nest_prefix;
        }
        Ok(self)
    }

    /// Apply a middleware handler to all endpoints registered in this `MethodRouter`.
    ///
    /// Middleware takes a `Request` and a `Next<S>` continuation.
    #[must_use]
    pub fn hoop<F, Fut, Res>(self, middleware: F) -> Self
    where
        F: Fn(Request<Body>, middleware::Next<S>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Res> + Send + 'static,
        Res: IntoResponse + Send + 'static,
    {
        self.hoop_at(middleware::MiddlewarePosition::First, middleware)
    }

    /// Apply a middleware handler to all endpoints registered in this `MethodRouter` at a specific position (First/Last).
    #[must_use]
    pub fn hoop_at<F, Fut, Res>(
        mut self,
        position: middleware::MiddlewarePosition,
        middleware: F,
    ) -> Self
    where
        F: Fn(Request<Body>, middleware::Next<S>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Res> + Send + 'static,
        Res: IntoResponse + Send + 'static,
    {
        let boxed: middleware::BoxedMiddleware<S> = Arc::new(move |req, next| {
            let fut = middleware(req, next);
            crate::routing::handler::ResponseFuture::Boxed(Box::pin(async move {
                fut.await.into_response()
            }))
        });
        for i in 0..METHOD_COUNT {
            if let Some(handler) = &mut self.handlers[i] {
                match position {
                    middleware::MiddlewarePosition::First => {
                        handler.middlewares.insert(0, boxed.clone());
                    }
                    middleware::MiddlewarePosition::Last => {
                        handler.middlewares.push(boxed.clone());
                    }
                }
                handler.compiled = None;
            }
        }
        self
    }

    /// Compile all handler middleware chains in-place.
    pub fn compile_in_place(&mut self) {
        for i in 0..METHOD_COUNT {
            if let Some(handler) = &mut self.handlers[i] {
                handler.compile_in_place();
            }
        }
    }

    /// Capture a state and transition this method router to another state type.
    #[must_use]
    pub fn with_state<S2>(self, state: &Arc<S>) -> MethodRouter<S2>
    where
        S2: Clone + Send + Sync + 'static,
        S: Clone + Send + Sync + 'static,
    {
        let mut new_handlers: [Option<middleware::MethodHandler<S2>>; METHOD_COUNT] =
            [const { None }; METHOD_COUNT];
        for (i, opt_handler) in self.handlers.iter().enumerate() {
            if let Some(handler) = opt_handler {
                let mut compiled_h = handler.clone();
                compiled_h.compile_in_place();
                let compiled_raw = compiled_h.compiled.unwrap_or(compiled_h.raw);
                let state = state.clone();
                let new_h: BoxedHandler<S2> =
                    Arc::new(move |req, _parent_state| compiled_raw(req, state.clone()));
                new_handlers[i] = Some(middleware::MethodHandler::new(new_h));
            }
        }
        MethodRouter {
            handlers: new_handlers,
            param_names: self.param_names,
            matched_path: self.matched_path,
            nest_prefix: self.nest_prefix,
        }
    }
}

/// Generates the nine per-verb `MethodRouter` builder methods (`.get()`, `.post()`, …)
/// and their matching free-function shortcuts (`get(h)`, `post(h)`, …) — one pair per
/// HTTP method, all structurally identical apart from which slot of `handlers` they fill.
macro_rules! method_routes {
    ($( ($name:ident, $idx:ident, $verb:literal) ),+ $(,)?) => {
        impl<S> MethodRouter<S>
        where
            S: Clone + Send + Sync + 'static,
        {
            $(
                #[doc = concat!("Add a handler for HTTP ", $verb, " requests.")]
                #[must_use]
                pub fn $name<H, T>(self, handler: H) -> Self
                where
                    H: Handler<T, S>,
                    T: 'static,
                {
                    self.set($idx, handler)
                }
            )+
        }

        $(
            #[doc = concat!("Helper to construct a ", $verb, "-only route.")]
            pub fn $name<H, T, S>(handler: H) -> MethodRouter<S>
            where
                H: Handler<T, S>,
                T: 'static,
                S: Clone + Send + Sync + 'static,
            {
                MethodRouter::new().$name(handler)
            }
        )+

        /// A route dispatching every HTTP method to `handler`, matching `axum::routing::any`.
        pub fn any<H, T, S>(handler: H) -> MethodRouter<S>
        where
            H: Handler<T, S>,
            T: 'static,
            S: Clone + Send + Sync + 'static,
        {
            let router = MethodRouter::new();
            $( let router = router.$name(handler.clone()); )+
            router
        }
    };
}

method_routes! {
    (get, IDX_GET, "GET"),
    (post, IDX_POST, "POST"),
    (put, IDX_PUT, "PUT"),
    (delete, IDX_DELETE, "DELETE"),
    (options, IDX_OPTIONS, "OPTIONS"),
    (head, IDX_HEAD, "HEAD"),
    (patch, IDX_PATCH, "PATCH"),
    (trace, IDX_TRACE, "TRACE"),
    (connect, IDX_CONNECT, "CONNECT"),
}

/// Axum-like routing table using `matchit` under the hood.
#[derive(Clone)]
pub struct Router<S = ()> {
    routes: Vec<(String, MethodRouter<S>)>,
    fallback: Option<BoxedHandler<S>>,
    method_not_allowed_fallback: Option<BoxedHandler<S>>,
    /// See [`Router::normalize_trailing_slash`].
    normalize_trailing_slash: bool,
    /// See [`Router::no_index`]. Applied at [`compile`](Router::compile) time, so route
    /// registration order doesn't matter.
    no_index: bool,
    /// Populated the first time this `Router` is driven as a `tower::Service`, so `.oneshot()`
    /// works without a separate `.compile()` call while still building the `matchit` tree only
    /// once. Every route-table-mutating builder method resets it to `None`, so mutating after
    /// serving can't dispatch against a stale tree.
    #[cfg(feature = "tower")]
    compiled: Option<CompiledRouter<S>>,
}

impl<S> std::fmt::Debug for Router<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("route_count", &self.routes.len())
            .field("has_fallback", &self.fallback.is_some())
            .field(
                "has_method_not_allowed_fallback",
                &self.method_not_allowed_fallback.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl<S> Default for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps a bare handler (a router's `fallback`/`method_not_allowed_fallback`) in
/// `middleware`, so `.hoop()`/`.hoop_at()` cover them the same way they cover routes.
fn wrap_handler<S, F, Fut, Res>(handler: BoxedHandler<S>, middleware: F) -> BoxedHandler<S>
where
    S: Send + Sync + 'static,
    F: Fn(Request<Body>, middleware::Next<S>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse + Send + 'static,
{
    Arc::new(move |req, state| {
        let next = middleware::Next {
            handler: handler.clone(),
            state,
        };
        let fut = middleware(req, next);
        handler::ResponseFuture::Boxed(Box::pin(async move { fut.await.into_response() }))
    })
}

/// Combines two optional per-router handlers (a `fallback` or
/// `method_not_allowed_fallback`) for [`Router::merge`]: `None` if neither side set one,
/// whichever side's if only one did, or a panic with `panic_msg` if both did — matching
/// Axum's "Cannot merge two `Router`s that both have a fallback".
#[allow(clippy::panic)]
fn merge_optional<T>(a: Option<T>, b: Option<T>, panic_msg: &'static str) -> Option<T> {
    match (a, b) {
        (Some(_), Some(_)) => panic!("{panic_msg}"),
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    }
}

/// Convert an Axum-style `:param` segment to a `matchit` `{param}` segment,
/// and `*wildcard` to `{*wildcard}`.
///
/// Only converts leading `:` and `*` – pure literal segments are left unchanged.
fn normalize_route_pattern(path: &str) -> String {
    if !path.contains(':') && !path.contains('*') {
        return path.to_string();
    }
    let segments: Vec<String> = path
        .split('/')
        .map(|segment| {
            if segment.starts_with(':') && segment.len() > 1 {
                format!("{{{}}}", &segment[1..])
            } else if segment.starts_with('*') && segment.len() > 1 {
                format!("{{{segment}}}")
            } else {
                segment.to_string()
            }
        })
        .collect();
    segments.join("/")
}

/// Builds a `MethodRouter` that dispatches every HTTP method to the same handler —
/// used to mount raw `tower::Service`s, which (unlike native handlers) typically do
/// their own method matching rather than being registered per-verb.
#[cfg(feature = "tower")]
fn all_methods<H, S>(handler: H) -> MethodRouter<S>
where
    H: Handler<tower_compat::TowerServiceMarker, S>,
    S: Clone + Send + Sync + 'static,
{
    any(handler)
}

impl<S> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Create a new empty `Router`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            fallback: None,
            method_not_allowed_fallback: None,
            normalize_trailing_slash: false,
            no_index: false,
            #[cfg(feature = "tower")]
            compiled: None,
        }
    }

    /// Opt in to trailing-slash normalization: strips a single trailing `/`
    /// from the incoming request's path *before* routing, so `/foo` and
    /// `/foo/` reach the same route.
    ///
    /// By default (matching Axum) routing is strict: `/foo` and `/foo/` are distinct routes and
    /// a mismatch 404s. Semantics match `tower_http`'s `NormalizePathLayer` — an in-place
    /// normalization applied once per request, not a redirect.
    ///
    /// Only meaningful on the outermost `Router` you `.compile()` (or hand to a `Server`),
    /// since it runs before any route matching; setting it on a router later merged or nested
    /// into another has no effect.
    #[must_use]
    pub const fn normalize_trailing_slash(mut self) -> Self {
        self.normalize_trailing_slash = true;
        self
    }

    /// Opt out of search-engine indexing — appropriate default hardening for `.onion`/`.i2p`
    /// deployments, where a crawlable mirror is itself an unintentional discovery/deanonymization
    /// leak (some operators don't realize search engines index onion mirrors at all).
    ///
    /// Adds `X-Robots-Tag: noindex, nofollow` to every response from this router (routes and
    /// fallback alike), and — unless the app already registers its own `/robots.txt` route —
    /// serves a blanket `User-agent: *\nDisallow: /` there too.
    ///
    /// Applied at [`compile`](Self::compile) time, so routes registered after this call are
    /// covered too. [`merge`](Self::merge) carries it over from either side;
    /// [`nest`](Self::nest) drops the inner router's setting, as it does for `fallback`.
    ///
    /// # Example
    /// ```rust
    /// use tachyon_web::{Router, get};
    ///
    /// let router: Router = Router::new()
    ///     .route("/", get(|| async { "hi" }))
    ///     .no_index();
    /// ```
    #[must_use]
    pub const fn no_index(mut self) -> Self {
        self.no_index = true;
        self
    }

    fn apply_no_index(mut self) -> Self {
        if !self.no_index {
            return self;
        }
        // Cleared first: keeps `route()` below from recursing, and keeps a second `compile()`
        // from stacking the middleware twice.
        self.no_index = false;
        if !self.routes.iter().any(|(path, _)| path == "/robots.txt") {
            self = self.route(
                "/robots.txt",
                get(|| async { "User-agent: *\nDisallow: /\n" }),
            );
        }
        self.hoop(|req: Request<Body>, next: middleware::Next<S>| async move {
            let mut resp = next.run(req).await;
            let _ = resp.headers_mut().insert(
                hyper::header::HeaderName::from_static("x-robots-tag"),
                hyper::header::HeaderValue::from_static("noindex, nofollow"),
            );
            resp
        })
    }

    /// Set the application state for this router, transitioning it to
    /// another (typically `()`) state type — matching Axum's
    /// `Router<S>::with_state<S2>(self, state: S) -> Router<S2>` signature.
    ///
    /// `S2` is almost always inferred as `()` since a fully-stated router is
    /// normally handed straight to a `Server`, but leaving it generic (rather
    /// than hardcoding `Router<()>`) matches Axum's nested-router pattern,
    /// where an inner router's state is supplied by an outer router before
    /// the two are merged/nested and the outer router still has its own,
    /// different state type to resolve later.
    #[must_use]
    pub fn with_state<S2>(self, state: S) -> Router<S2>
    where
        S2: Clone + Send + Sync + 'static,
    {
        let state_arc = Arc::new(state);

        let new_routes = self
            .routes
            .into_iter()
            .map(|(path, method_router)| (path, method_router.with_state(&state_arc)))
            .collect();

        let rebind = |handler: BoxedHandler<S>| -> BoxedHandler<S2> {
            let state_arc = state_arc.clone();
            Arc::new(move |req, _parent_state| handler(req, state_arc.clone()))
        };
        let new_fallback = self.fallback.map(rebind);
        let new_method_not_allowed_fallback = self.method_not_allowed_fallback.map(rebind);

        Router {
            routes: new_routes,
            fallback: new_fallback,
            method_not_allowed_fallback: new_method_not_allowed_fallback,
            normalize_trailing_slash: self.normalize_trailing_slash,
            no_index: self.no_index,
            #[cfg(feature = "tower")]
            compiled: None,
        }
    }

    /// Inserts `method_router` at `path`, merging it into an already-registered
    /// `MethodRouter` for the same path (combining non-overlapping methods
    /// into one route) rather than always appending a new entry.
    ///
    /// # Panics
    /// Panics if `method_router` defines an HTTP method already registered for `path`,
    /// matching Axum. A route conflict is a build-time bug, not a recoverable condition.
    #[allow(clippy::panic)]
    fn push_or_merge_route(&mut self, path: String, method_router: MethodRouter<S>) {
        #[cfg(feature = "tower")]
        {
            self.compiled = None;
        }
        if let Some(pos) = self.routes.iter().position(|(p, _)| *p == path) {
            let (_, existing) = self.routes.remove(pos);
            let merged = existing
                .merge(method_router, &path)
                .unwrap_or_else(|e| panic!("{e}"));
            self.routes.insert(pos, (path, merged));
        } else {
            self.routes.push((path, method_router));
        }
    }

    /// Add a route to the router.
    ///
    /// Registering the same path more than once merges the method routers —
    /// e.g. `.route("/x", get(a)).route("/x", post(b))` yields one route that
    /// answers both `GET` and `POST` — matching Axum. Registering the *same*
    /// method for the same path twice panics, also matching Axum.
    #[must_use]
    pub fn route(mut self, path: &str, method_router: MethodRouter<S>) -> Self {
        let normalized = normalize_route_pattern(path);
        self.push_or_merge_route(normalized, method_router);
        self
    }

    /// A dummy/compatibility method that returns the router itself, matching Axum's API
    /// when preparing a router to be run with a server listener.
    #[must_use]
    pub const fn into_make_service(self) -> Self {
        self
    }

    /// Serve an entire directory as static files — the simplest, Nginx-like API.
    ///
    /// Serves directly from disk on every request; it does not call
    /// [`static_dir::ServeDir::preload`], so `CacheConfig::enabled`'s default of
    /// `true` has no effect here. Use [`serve_dir`](Self::serve_dir) with a
    /// manually-preloaded `ServeDir` if you want the in-memory RAM cache.
    ///
    /// Do not point `dir_path` at a directory that can ever contain files an
    /// untrusted user chose the bytes of (e.g. an upload folder mixed into the
    /// served tree) — see [`static_dir::ServeDir`]'s docs for why (in short: a
    /// user-supplied `.svg` served this way can carry an executable
    /// `<script>`).
    ///
    /// # Example
    /// ```rust,no_run
    /// use tachyon_web::Router;
    ///
    /// // Serve ./public/ at /, with index.html as the default.
    /// let router = Router::new()
    ///     .serve_static("./public");
    /// # let _ = router.with_state::<()>(());
    /// ```
    #[must_use]
    pub fn serve_static(self, dir_path: impl AsRef<std::path::Path>) -> Self {
        let sd = static_dir::ServeDir::new(&dir_path).index("index.html");
        self.serve_dir("/", sd)
    }

    /// Serve an entire static directory under a URL prefix with full configuration control.
    ///
    /// Registers `prefix/*path` for files, plus the bare `prefix` and `prefix/` so a
    /// directory request reaches the [`index`](static_dir::ServeDir::index) — a `matchit`
    /// `{*path}` never matches an empty remainder, so the wildcard alone can't serve either.
    ///
    /// Use `serve_static()` for the common case of serving a dir at `/`. See
    /// [`static_dir::ServeDir`]'s docs for the upload-safety warning before
    /// serving a directory that can contain user-supplied files.
    #[must_use]
    pub fn serve_dir(mut self, prefix: &str, serve_dir: static_dir::ServeDir) -> Self {
        let prefix = prefix.trim_end_matches('/');
        let exact_route = if prefix.is_empty() { "/" } else { prefix };
        let wildcard_route = format!("{prefix}/*path");

        self = self.route(exact_route, serve_dir.clone().into_method_router_at(prefix));
        // At the root `exact_route` is already `/`; registering it again would be a duplicate.
        if !prefix.is_empty() {
            self = self.route(
                &format!("{prefix}/"),
                serve_dir.clone().into_method_router_at(prefix),
            );
        }
        self = self.route(&wildcard_route, serve_dir.into_method_router_at(prefix));
        self
    }

    /// Natively serve a specific file on a specific route.
    ///
    /// The file is read **once at startup** into a `Bytes` buffer. Every subsequent
    /// request is served from that buffer with **zero I/O and zero allocations**,
    /// rivalling `include_bytes!` without inflating the binary.
    ///
    /// # Errors
    /// Returns an `Err` if the file cannot be read at startup.
    pub fn serve_file(self, path: &str, file_path: &str) -> Result<Self, std::io::Error> {
        let content = std::fs::read(file_path)?;
        let content_bytes = Bytes::from(content);
        let mime_type = static_dir::guess_mime_type(std::path::Path::new(file_path));

        Ok(self.route(
            path,
            get(move |_req: Request<Body>| {
                let body_content = content_bytes.clone();
                async move {
                    let mut resp = Response::new(Body::full(body_content));
                    let mime_val = hyper::header::HeaderValue::from_static(mime_type);
                    let _ = resp
                        .headers_mut()
                        .insert(hyper::header::CONTENT_TYPE, mime_val);
                    resp
                }
            }),
        ))
    }

    /// Natively serve a specific file on a specific route dynamically.
    ///
    /// The file is read from disk on every request. Ideal for large files that
    /// change frequently where startup preloading is undesirable.
    #[must_use]
    pub fn serve_file_dynamic(self, path: &str, file_path: &str) -> Self {
        let file_path_str = file_path.to_string();
        let mime_type = static_dir::guess_mime_type(std::path::Path::new(file_path));

        self.route(
            path,
            get(move |_req: Request<Body>| {
                let fp = file_path_str.clone();
                async move {
                    let Ok(content) = tokio::fs::read(&fp).await else {
                        let mut resp = Response::new(Body::empty());
                        *resp.status_mut() = StatusCode::NOT_FOUND;
                        return resp;
                    };
                    let mut resp = Response::new(Body::full(Bytes::from(content)));
                    let mime_val = hyper::header::HeaderValue::from_static(mime_type);
                    let _ = resp
                        .headers_mut()
                        .insert(hyper::header::CONTENT_TYPE, mime_val);
                    resp
                }
            }),
        )
    }

    /// Nest another router under a given path prefix.
    ///
    /// Merges all routes from the sub-router into this router.
    ///
    /// Matches Axum: handlers inside the nested router see a request `Uri` with
    /// `prefix` stripped (e.g. a request to `/api/users/1` nested under `/api`
    /// sees `/users/1`), while [`crate::routing::extract::OriginalUri`] recovers
    /// the pre-strip, full path. Nesting is resolved once at `compile()` time —
    /// there's no per-request recursive dispatch — so this is exactly as fast as
    /// a flat route table; only the one matched route's prefix is ever stripped.
    ///
    /// # Deviation from Axum: the inner router's own `fallback` is not carried over
    ///
    /// Axum mounts the inner `Router` as a recursive sub-service, so an unmatched path under
    /// `prefix` reaches the *inner* fallback first. Flattening into one route table leaves no
    /// inner dispatch step for that to hook into, so unmatched paths fall straight through to
    /// the outermost router's [`fallback`](Self::fallback) (or the default 404). Use that, or
    /// an explicit catch-all route under `prefix`, for a per-module 404 handler.
    #[must_use]
    pub fn nest(mut self, prefix: &str, mut router: Self) -> Self {
        let prefix = prefix.trim_end_matches('/');
        for (path, mut method_router) in router.routes.drain(..) {
            let nested_path = if path == "/" || path.is_empty() {
                prefix.to_string()
            } else {
                format!("{prefix}{path}")
            };
            let final_path = if nested_path.is_empty() {
                "/".to_string()
            } else {
                nested_path
            };
            let accumulated = method_router.nest_prefix.as_ref().map_or_else(
                || prefix.to_string(),
                |existing| format!("{prefix}{existing}"),
            );
            method_router.nest_prefix = Some(Arc::from(accumulated));
            self.push_or_merge_route(final_path, method_router);
        }
        self
    }

    /// Merge another router's routes into this router.
    ///
    /// If exactly one of the two routers has a [`fallback`](Self::fallback) (or a
    /// [`method_not_allowed_fallback`](Self::method_not_allowed_fallback)), the merged router
    /// adopts it, matching Axum. Unlike [`nest`](Self::nest), `merge` treats both routers as
    /// peers, so dropping one side's fallback would change which handler answers unmatched
    /// requests.
    ///
    /// # Panics
    /// Panics if `other` defines a method for a path already registered in `self`, or if
    /// both routers already have a `fallback`/`method_not_allowed_fallback` configured —
    /// matching Axum's `Router::merge`.
    #[must_use]
    pub fn merge(mut self, mut other: Self) -> Self {
        #[cfg(feature = "tower")]
        {
            self.compiled = None;
        }
        for (path, method_router) in other.routes.drain(..) {
            self.push_or_merge_route(path, method_router);
        }
        self.fallback = merge_optional(
            self.fallback.take(),
            other.fallback.take(),
            "Cannot merge two `Router`s that both have a fallback",
        );
        self.method_not_allowed_fallback = merge_optional(
            self.method_not_allowed_fallback.take(),
            other.method_not_allowed_fallback.take(),
            "Cannot merge two `Router`s that both have a method_not_allowed_fallback",
        );
        // Peers, so an opt-out either side asked for survives the merge.
        self.no_index |= other.no_index;
        self
    }

    /// Mount a raw `tower::Service` at `path`, handling every HTTP method.
    ///
    /// Requires the `tower` feature. Prefer `.route(path, get(handler))` with a native
    /// handler where possible — this exists to bridge in pre-built Tower/tower-http
    /// services (e.g. `tower_http::services::ServeFile`) without a rewrite.
    #[cfg(feature = "tower")]
    #[must_use]
    pub fn route_service<Svc, RespBody>(self, path: &str, service: Svc) -> Self
    where
        Svc: tower::Service<Request<Bytes>, Response = Response<RespBody>>
            + Clone
            + Send
            + Sync
            + 'static,
        Svc::Future: Send + 'static,
        Svc::Error: Into<crate::http::error::Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<crate::http::error::Error>,
    {
        let handler = tower_compat::ServiceHandler {
            service,
            strip_prefix: None,
        };
        self.route(path, all_methods(handler))
    }

    /// Nest a raw `tower::Service` under `prefix`, with the mounted path rewritten
    /// relative to `prefix` before the service sees it (matching Axum's `nest_service`).
    ///
    /// Requires the `tower` feature.
    #[must_use]
    #[cfg(feature = "tower")]
    pub fn nest_service<Svc, RespBody>(self, prefix: &str, service: Svc) -> Self
    where
        Svc: tower::Service<Request<Bytes>, Response = Response<RespBody>>
            + Clone
            + Send
            + Sync
            + 'static,
        Svc::Future: Send + 'static,
        Svc::Error: Into<crate::http::error::Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<crate::http::error::Error>,
    {
        let prefix = prefix.trim_end_matches('/');
        let exact = if prefix.is_empty() { "/" } else { prefix };
        let wildcard = format!("{prefix}/*__tachyon_nest_rest");
        let handler = tower_compat::ServiceHandler {
            service,
            strip_prefix: Some(Arc::from(prefix)),
        };
        self.route(exact, all_methods(handler.clone()))
            .route(&wildcard, all_methods(handler))
    }

    /// Set a raw `tower::Service` as the fallback for unmatched paths.
    ///
    /// Requires the `tower` feature.
    #[must_use]
    #[cfg(feature = "tower")]
    pub fn fallback_service<Svc, RespBody>(mut self, service: Svc) -> Self
    where
        Svc: tower::Service<Request<Bytes>, Response = Response<RespBody>>
            + Clone
            + Send
            + Sync
            + 'static,
        Svc::Future: Send + 'static,
        Svc::Error: Into<crate::http::error::Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<crate::http::error::Error>,
    {
        let handler = tower_compat::ServiceHandler {
            service,
            strip_prefix: None,
        };
        self.fallback = Some(Arc::new(move |req, state| handler.clone().call(req, state)));
        self.compiled = None;
        self
    }

    /// Apply a `tower::Layer` to every route **and** the fallback in this router.
    ///
    /// Requires the `tower` feature. Prefer `.hoop()`/`.hoop_at()` for new code — this
    /// exists to bridge in existing Tower/tower-http layers (tracing, compression,
    /// timeouts) without rewriting them as native middleware.
    #[must_use]
    #[cfg(feature = "tower")]
    pub fn layer<L, RespBody>(self, layer: L) -> Self
    where
        L: tower::Layer<tower_compat::NextService<S>> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<Request<Bytes>, Response = Response<RespBody>> + Send + 'static,
        <L::Service as tower::Service<Request<Bytes>>>::Future: Send + 'static,
        <L::Service as tower::Service<Request<Bytes>>>::Error:
            Into<crate::http::error::Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<crate::http::error::Error>,
    {
        self.hoop_at(
            middleware::MiddlewarePosition::First,
            tower_compat::from_tower_layer(layer),
        )
    }

    /// Apply a `tower::Layer` to every registered route, but *not* the fallback —
    /// matching Axum's distinction between `.layer()` and `.route_layer()`.
    ///
    /// Requires the `tower` feature.
    #[must_use]
    #[cfg(feature = "tower")]
    pub fn route_layer<L, RespBody>(mut self, layer: L) -> Self
    where
        L: tower::Layer<tower_compat::NextService<S>> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<Request<Bytes>, Response = Response<RespBody>> + Send + 'static,
        <L::Service as tower::Service<Request<Bytes>>>::Future: Send + 'static,
        <L::Service as tower::Service<Request<Bytes>>>::Error:
            Into<crate::http::error::Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<crate::http::error::Error>,
    {
        let mw = tower_compat::from_tower_layer(layer);
        for (_path, method_router) in &mut self.routes {
            let m = mw.clone();
            let old_mr = std::mem::take(method_router);
            *method_router = old_mr.hoop_at(middleware::MiddlewarePosition::Last, m);
        }
        self.compiled = None;
        self
    }

    /// Set a custom fallback handler for requests that don't match any route.
    #[must_use]
    pub fn fallback<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.fallback = Some(Arc::new(move |req, state| {
            let handler = handler.clone();
            handler.call(req, state)
        }));
        #[cfg(feature = "tower")]
        {
            self.compiled = None;
        }
        self
    }

    /// Set a custom fallback handler for requests whose path matches a route but
    /// whose method has no registered handler (the default is a bare `405 Method
    /// Not Allowed` with an `Allow` header).
    #[must_use]
    pub fn method_not_allowed_fallback<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.method_not_allowed_fallback = Some(Arc::new(move |req, state| {
            let handler = handler.clone();
            handler.call(req, state)
        }));
        #[cfg(feature = "tower")]
        {
            self.compiled = None;
        }
        self
    }

    /// Apply a middleware handler to ALL routes and the fallback registered in this `Router`.
    #[must_use]
    pub fn hoop<F, Fut, Res>(self, middleware: F) -> Self
    where
        F: Fn(Request<Body>, middleware::Next<S>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Res> + Send + 'static,
        Res: IntoResponse + Send + 'static,
    {
        self.hoop_at(middleware::MiddlewarePosition::First, middleware)
    }

    /// Apply a middleware handler at a specific position (First/Last) to ALL routes and the fallback.
    #[must_use]
    pub fn hoop_at<F, Fut, Res>(
        mut self,
        position: middleware::MiddlewarePosition,
        middleware: F,
    ) -> Self
    where
        F: Fn(Request<Body>, middleware::Next<S>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Res> + Send + 'static,
        Res: IntoResponse + Send + 'static,
    {
        #[cfg(feature = "tower")]
        {
            self.compiled = None;
        }
        for (_path, method_router) in &mut self.routes {
            let mw = middleware.clone();
            let old_mr = std::mem::take(method_router);
            *method_router = old_mr.hoop_at(position, mw);
        }

        self.fallback = self
            .fallback
            .take()
            .map(|h| wrap_handler(h, middleware.clone()));
        self.method_not_allowed_fallback = self
            .method_not_allowed_fallback
            .take()
            .map(|h| wrap_handler(h, middleware));

        self
    }

    /// Route an incoming request directly, compiling the router on the fly.
    /// Primarily useful for testing.
    ///
    /// # Panics
    /// Panics if router compilation fails (e.g. a duplicate route was registered).
    #[allow(clippy::expect_used)]
    pub async fn handle_request(&self, req: Request<Body>) -> Response<Body>
    where
        S: Default,
    {
        let compiled = self.clone().compile().expect("Router compilation failed");
        compiled.handle_request(req).await
    }

    /// Build and compile the routing tree, returning a `CompiledRouter`.
    ///
    /// # Errors
    /// Returns [`RouterError::DuplicateRoute`] if the same literal path reaches `compile()`
    /// twice. `route()`/`nest()`/`merge()` all merge same-path entries, so this is an internal
    /// invariant check rather than a condition callers need to handle.
    pub fn compile(self) -> Result<CompiledRouter<S>, RouterError>
    where
        S: Default,
    {
        let this = self.apply_no_index();
        let mut matcher: matchit::Router<MethodRouter<S>> = matchit::Router::new();

        let mut seen = std::collections::HashSet::new();
        for (path, mut method_router) in this.routes {
            if !seen.insert(path.clone()) {
                return Err(RouterError::DuplicateRoute(path));
            }
            method_router.compile_in_place();
            method_router.param_names = extract_param_names(&path);
            method_router.matched_path = Arc::from(path.as_str());
            matcher.insert(path, method_router)?;
        }

        Ok(CompiledRouter {
            matcher,
            fallback: this.fallback,
            method_not_allowed_fallback: this.method_not_allowed_fallback,
            state: Arc::new(S::default()),
            normalize_trailing_slash: this.normalize_trailing_slash,
        })
    }
}

/// Errors that can occur during router construction or compilation.
#[derive(Debug)]
pub enum RouterError {
    /// Duplicate route registered.
    DuplicateRoute(String),
    /// The same path was registered with the same HTTP method more than once. Registering the
    /// same path with *different* methods merges into one route, matching Axum.
    MethodOverlap {
        /// The HTTP method that was registered twice.
        method: &'static str,
        /// The path it was registered twice for.
        path: String,
    },
    /// matchit insert error.
    Insert(matchit::InsertError),
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateRoute(path) => write!(f, "Duplicate route path registered: '{path}'"),
            Self::MethodOverlap { method, path } => {
                write!(
                    f,
                    "Overlapping method route: {method} {path} already exists"
                )
            }
            Self::Insert(e) => write!(f, "Router insert error: {e}"),
        }
    }
}

impl std::error::Error for RouterError {}

impl From<matchit::InsertError> for RouterError {
    fn from(e: matchit::InsertError) -> Self {
        Self::Insert(e)
    }
}

/// A compiled routing table ready to serve requests.
#[derive(Clone)]
pub struct CompiledRouter<S> {
    matcher: matchit::Router<MethodRouter<S>>,
    fallback: Option<BoxedHandler<S>>,
    method_not_allowed_fallback: Option<BoxedHandler<S>>,
    state: Arc<S>,
    normalize_trailing_slash: bool,
}

impl<S> std::fmt::Debug for CompiledRouter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRouter")
            .field("has_fallback", &self.fallback.is_some())
            .field(
                "has_method_not_allowed_fallback",
                &self.method_not_allowed_fallback.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Parses the `{name}` / `{*name}` placeholders out of a route pattern, in the order
/// `matchit` yields them in `Match::params`. Computed once per route at `compile()` time so
/// `resolve()` never allocates a `String` for a param key.
fn extract_param_names(path: &str) -> Arc<[Arc<str>]> {
    let mut names = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(end) = path[i + 1..].find('}')
        {
            let inner = &path[i + 1..i + 1 + end];
            let name = inner.strip_prefix('*').unwrap_or(inner);
            names.push(Arc::from(name));
            i += 1 + end + 1;
        } else {
            i += 1;
        }
    }
    Arc::from(names)
}

/// Zero-allocation percent-decoding helper for path parameters.
///
/// Returns `None` if the input contains invalid percent encoding.
pub(crate) fn percent_decode(s: &str) -> Option<std::borrow::Cow<'_, str>> {
    let bytes = s.as_bytes();
    if !bytes.contains(&b'%') {
        return Some(std::borrow::Cow::Borrowed(s));
    }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 < bytes.len() {
                let hex = &bytes[i + 1..i + 3];
                if let Ok(hex_str) = std::str::from_utf8(hex)
                    && let Ok(val) = u8::from_str_radix(hex_str, 16)
                {
                    decoded.push(val);
                    i += 3;
                    continue;
                }
            }
            return None; // invalid percent encoding
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    let s = String::from_utf8(decoded).ok()?;
    Some(std::borrow::Cow::Owned(s))
}

/// Strips `prefix` from `req`'s `Uri` path in place, used by nested routers
/// (native [`Router::nest`] and [`tower_compat::ServiceHandler`]'s
/// `nest_service`) to match Axum's nested-router URI rewriting.
///
/// The prefix is stripped from the raw (still percent-encoded) `path()`, and the query string
/// is carried over untouched. Reconstructing the URI from a percent-*decoded* segment would
/// let a client smuggle a `?`/`#` past routing (`/api/foo%3Fadmin=1` becoming a synthesized
/// `?admin=1` query the router never evaluated).
pub(crate) fn strip_uri_prefix(req: &mut Request<Body>, prefix: &str) {
    let path = req.uri().path();
    let stripped = path.strip_prefix(prefix).unwrap_or(path);
    let new_path = if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{stripped}")
    };
    set_uri_path(req, &new_path);
}

/// Replaces `req`'s URI path with `new_path`, carrying the original query string over
/// untouched. Shared by the two in-place path rewrites the router performs
/// ([`strip_uri_prefix`] and [`strip_trailing_slash`]); a URI that won't reparse is left
/// as-is rather than being replaced with something malformed.
fn set_uri_path(req: &mut Request<Body>, new_path: &str) {
    let path_and_query = match req.uri().query() {
        Some(q) if !q.is_empty() => format!("{new_path}?{q}"),
        _ => new_path.to_string(),
    };
    let mut parts = req.uri().clone().into_parts();
    if let Ok(pq) = path_and_query.parse() {
        parts.path_and_query = Some(pq);
    }
    if let Ok(new_uri) = hyper::Uri::from_parts(parts) {
        *req.uri_mut() = new_uri;
    }
}

/// Strips a single trailing `/` from `req`'s `Uri` path in place for
/// [`Router::normalize_trailing_slash`], preserving the query string and never stripping the
/// root `/` itself.
fn strip_trailing_slash(req: &mut Request<Body>) {
    let path = req.uri().path();
    if path.len() <= 1 || !path.ends_with('/') {
        return;
    }
    let new_path = path[..path.len() - 1].to_string();
    set_uri_path(req, &new_path);
}

/// Empties a `HEAD` response body, keeping the `Content-Length` the `GET` would have reported.
///
/// RFC 9110 §9.3.2 wants the `GET`'s headers here, and hyper derives `Content-Length` from the
/// body's `size_hint` — so dropping the body without pinning the length first makes every
/// `HEAD` advertise zero. Streams have no exact length to keep; a header the handler set wins.
fn discard_body_for_head(resp: &mut Response<Body>) {
    let known_length = hyper::body::Body::size_hint(resp.body()).exact();
    *resp.body_mut() = Body::empty();

    if resp.headers().contains_key(hyper::header::CONTENT_LENGTH) {
        return;
    }
    if let Some(len) = known_length
        && let Ok(value) = hyper::header::HeaderValue::try_from(len.to_string())
    {
        let _ = resp
            .headers_mut()
            .insert(hyper::header::CONTENT_LENGTH, value);
    }
}

impl<S> CompiledRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Route an incoming request, returning the resulting HTTP response.
    ///
    /// Routes match **exactly**, as in Axum: `/foo` and `/foo/` are distinct and neither falls
    /// back to the other unless [`Router::normalize_trailing_slash`] was set. Paths are
    /// case-sensitive.
    ///
    /// This is the hot path: an `O(path_len)` `matchit` lookup, one prefix check, and an array
    /// index for method dispatch — zero-allocation on the happy path.
    #[inline]
    pub async fn handle_request(&self, req: Request<Body>) -> Response<Body> {
        let mut req = req;

        if self.normalize_trailing_slash {
            strip_trailing_slash(&mut req);
        }

        let path = req.uri().path();

        #[cfg(feature = "lets-encrypt")]
        if path.starts_with("/.well-known/acme-challenge/") {
            use hyper::StatusCode;
            let token = path
                .strip_prefix("/.well-known/acme-challenge/")
                .unwrap_or("");
            if let Some(key_auth) = crate::tls::acme::get_challenge(token) {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "text/plain")
                    .body(Body::full(Bytes::copy_from_slice(key_auth.as_bytes())))
                    .unwrap_or_else(|_| Response::new(Body::empty()));
            }
        }

        let (method_router, params): RouteResolution<'_, S> = match self.resolve(path) {
            Some(r) => r,
            None => {
                return if let Some(fb) = &self.fallback {
                    fb(req, self.state.clone()).await
                } else {
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::full(Bytes::from_static(b"Not Found")))
                        .unwrap_or_else(|_| Response::new(Body::empty()))
                };
            }
        };

        // Skipped entirely on parameterless routes, the common case.
        if !params.is_empty() {
            let _ = req.extensions_mut().insert(PathParams(params));
        }

        #[cfg(feature = "matched-path")]
        {
            let _ = req
                .extensions_mut()
                .insert(crate::routing::extract::MatchedPath(
                    method_router.matched_path.clone(),
                ));
        }

        // Nested routes see a prefix-stripped `Uri`, with the full path preserved via
        // `OriginalUri`, matching Axum.
        if let Some(prefix) = &method_router.nest_prefix {
            #[cfg(feature = "original-uri")]
            {
                let original_uri = req.uri().clone();
                let _ = req
                    .extensions_mut()
                    .insert(crate::routing::extract::OriginalUri(original_uri));
            }
            strip_uri_prefix(&mut req, prefix);
        }

        let method = req.method();
        let idx = method_index(method);

        // HEAD uses an explicit HEAD handler when registered; otherwise it
        // falls back to the GET handler, with the body discarded afterwards.
        let is_head = *method == Method::HEAD;
        let falls_back_to_get =
            is_head && method_router.handlers[IDX_HEAD].is_none() && idx == Some(IDX_HEAD);
        let effective_idx = if falls_back_to_get {
            Some(IDX_GET)
        } else {
            idx
        };

        let handler = effective_idx.and_then(|i| method_router.handlers[i].as_ref());

        if let Some(h) = handler {
            let mut resp = h.call(req, self.state.clone()).await;
            // Per HTTP semantics, a HEAD response must never carry a body,
            // regardless of whether it came from an explicit HEAD handler or
            // the implicit GET fallback.
            if is_head {
                discard_body_for_head(&mut resp);
            }
            resp
        } else if let Some(fb) = &self.method_not_allowed_fallback {
            // Route exists but this method has no handler, and a custom fallback
            // was configured for that case via `Router::method_not_allowed_fallback`.
            fb(req, self.state.clone()).await
        } else {
            // Route exists but this method has no handler → 405 with Allow header.
            let allow = method_router.allow_header();
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(hyper::header::ALLOW, &allow)
                .body(Body::full(Bytes::from_static(b"Method Not Allowed")))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
    }

    /// Internal: attempt to match `path`, returning `RouteResolution`.
    #[inline]
    fn resolve(&self, path: &str) -> Option<RouteResolution<'_, S>> {
        let m = self.matcher.at(path).ok()?;
        let params = if m.params.is_empty() {
            extract::PathParamsVec::new()
        } else {
            let names = &m.value.param_names;
            let mut p = extract::PathParamsVec::with_capacity(m.params.len());
            for (name, (_, v)) in names.iter().zip(m.params.iter()) {
                let decoded =
                    percent_decode(v).map_or_else(|| v.to_string(), std::borrow::Cow::into_owned);
                p.push((name.clone(), decoded));
            }
            p
        };
        Some((m.value, params))
    }
}

/// Type alias for matched route results to keep signatures clean.
pub type RouteResolution<'a, S> = (&'a MethodRouter<S>, extract::PathParamsVec);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::routing::extract::Path;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct IdParam {
        id: u32,
    }

    async fn handle_root() -> &'static str {
        "root"
    }
    async fn handle_id(Path(p): Path<IdParam>) -> String {
        format!("id:{}", p.id)
    }
    async fn handle_post() -> &'static str {
        "post"
    }
    async fn handle_delete() -> &'static str {
        "deleted"
    }

    fn make_req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("valid request")
    }

    fn compile_app() -> CompiledRouter<()> {
        Router::new()
            .route("/", get(handle_root))
            .route(
                "/user/:id",
                get(handle_id).post(handle_post).delete(handle_delete),
            )
            .with_state::<()>(())
            .compile()
            .expect("compile router")
    }

    #[tokio::test]
    async fn test_path_param_extraction() {
        use http_body_util::BodyExt;
        let router = compile_app();
        let resp = router.handle_request(make_req("GET", "/user/42")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"id:42");
    }

    #[tokio::test]
    async fn test_not_found() {
        let router = compile_app();
        let resp = router.handle_request(make_req("GET", "/nonexistent")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_method_not_allowed_has_allow_header() {
        let router = compile_app();
        // /user/:id has GET, POST, DELETE — PATCH is not registered
        let resp = router.handle_request(make_req("PATCH", "/user/1")).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let allow = resp
            .headers()
            .get(hyper::header::ALLOW)
            .expect("Allow header must be present");
        let allow_str = allow.to_str().expect("valid utf8");
        assert!(allow_str.contains("GET"), "Allow: {allow_str}");
        assert!(allow_str.contains("POST"), "Allow: {allow_str}");
        assert!(allow_str.contains("DELETE"), "Allow: {allow_str}");
        assert!(!allow_str.contains("PATCH"), "Allow: {allow_str}");
    }

    /// `/foo` and `/foo/` are distinct routes in both directions, matching Axum.
    #[tokio::test]
    async fn test_trailing_slash_is_significant() {
        let router = compile_app();
        let resp = router.handle_request(make_req("GET", "/user/5/")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let router = Router::new()
            .route("/about/", get(handle_root))
            .with_state::<()>(())
            .compile()
            .expect("compile");
        let resp = router.handle_request(make_req("GET", "/about")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_case_sensitive_routing() {
        // Paths must match exactly — no silent case-folding.
        let router = compile_app();
        let resp = router.handle_request(make_req("GET", "/User/1")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_custom_fallback() {
        let router = Router::new()
            .route("/", get(handle_root))
            .fallback(|_req: Request<Body>| async { (StatusCode::FOUND, "redirected") })
            .with_state::<()>(())
            .compile()
            .expect("compile");
        let resp = router.handle_request(make_req("GET", "/missing")).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn test_overlapping_method_route_panics() {
        async fn v1() -> &'static str {
            "v1"
        }
        async fn v2() -> &'static str {
            "v2"
        }

        // Registering the same method for the same path twice panics,
        // matching Axum's "Overlapping method route" panic.
        let result = std::panic::catch_unwind(|| {
            Router::<()>::new()
                .route("/dup", get(v1))
                .route("/dup", get(v2))
        });
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_non_overlapping_methods_on_same_path_merge() {
        async fn handle_get() -> &'static str {
            "got"
        }
        async fn handle_post() -> &'static str {
            "posted"
        }

        // Registering different methods for the same path across separate
        // `.route()` calls merges into a single route answering both —
        // matching Axum, not tachyon-web's previous "any repeat path errors"
        // behavior.
        let app = Router::new()
            .route("/x", get(handle_get))
            .route("/x", post(handle_post))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let get_resp = app.handle_request(make_req("GET", "/x")).await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let get_body = http_body_util::BodyExt::collect(get_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&get_body[..], b"got");

        let post_resp = app.handle_request(make_req("POST", "/x")).await;
        assert_eq!(post_resp.status(), StatusCode::OK);
        let post_body = http_body_util::BodyExt::collect(post_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&post_body[..], b"posted");
    }

    #[test]
    fn test_normalize_route_pattern() {
        for (input, expected) in [
            ("/static/path", "/static/path"),
            ("/user/:id", "/user/{id}"),
            ("/files/*path", "/files/{*path}"),
            ("/api/:version/files/*rest", "/api/{version}/files/{*rest}"),
        ] {
            assert_eq!(normalize_route_pattern(input), expected, "input: {input}");
        }
    }

    /// A nested route is reachable at `prefix + path`, including when the inner path is `/`
    /// (which mounts at the bare prefix).
    #[tokio::test]
    async fn test_nested_routes_are_reachable() {
        let app = Router::new()
            .nest("/api/v1", Router::new().route("/status", get(handle_root)))
            .nest("/api", Router::new().route("/", get(handle_root)))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        for path in ["/api/v1/status", "/api"] {
            let resp = app.handle_request(make_req("GET", path)).await;
            assert_eq!(resp.status(), StatusCode::OK, "path: {path}");
        }
    }

    #[tokio::test]
    async fn test_nest_strips_prefix_from_uri() {
        use hyper::Uri;

        async fn echo_uri(uri: Uri) -> String {
            uri.path().to_string()
        }

        let api = Router::new().route("/users/{id}", get(echo_uri));
        let app = Router::new()
            .nest("/api", api)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/api/users/42")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        // Matches Axum: the nested handler sees the prefix-stripped path.
        assert_eq!(&body[..], b"/users/42");
    }

    #[cfg(feature = "original-uri")]
    #[tokio::test]
    async fn test_nest_original_uri_preserves_full_path() {
        use crate::routing::extract::OriginalUri;

        async fn echo_original(OriginalUri(uri): OriginalUri) -> String {
            uri.path().to_string()
        }

        let api = Router::new().route("/users/{id}", get(echo_original));
        let app = Router::new()
            .nest("/api", api)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/api/users/42")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        // OriginalUri recovers the full, pre-strip path.
        assert_eq!(&body[..], b"/api/users/42");
    }

    #[tokio::test]
    async fn test_nest_two_levels_accumulates_prefix() {
        async fn echo_uri(uri: hyper::Uri) -> String {
            uri.path().to_string()
        }

        let innermost = Router::new().route("/users", get(echo_uri));
        let v1 = Router::new().nest("/v1", innermost);
        let app = Router::new()
            .nest("/api", v1)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/api/v1/users")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"/users");
    }

    #[tokio::test]
    async fn test_non_nested_route_uri_unaffected() {
        // A route registered directly (no `.nest()`) must see its Uri untouched.
        async fn echo_uri(uri: hyper::Uri) -> String {
            uri.path().to_string()
        }
        let app = Router::new()
            .route("/users/{id}", get(echo_uri))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/users/7")).await;
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"/users/7");
    }

    #[cfg(feature = "matched-path")]
    #[tokio::test]
    async fn test_matched_path_returns_route_pattern() {
        use crate::routing::extract::MatchedPath;

        async fn handler(path: MatchedPath) -> String {
            path.as_str().to_string()
        }

        let app = Router::new()
            .route("/users/{id}", get(handler))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/users/99")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"/users/{id}");
    }

    #[cfg(feature = "matched-path")]
    #[tokio::test]
    async fn test_matched_path_missing_returns_500() {
        use crate::routing::extract::{FromRequestParts, MatchedPath};
        // Directly exercising the extractor without going through the router at
        // all (no `MatchedPath` extension present) must reject with 500.
        let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
        let res = MatchedPath::from_request_parts(&mut parts, &());
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_any_dispatches_every_method() {
        async fn handler() -> &'static str {
            "any"
        }
        let app = Router::new()
            .route("/x", any(handler))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        for method in [
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
        ] {
            let resp = app.handle_request(make_req(method, "/x")).await;
            assert_eq!(resp.status(), StatusCode::OK, "method: {method}");
        }
    }

    #[tokio::test]
    async fn test_connect_route() {
        async fn handler() -> &'static str {
            "connected"
        }
        let app = Router::new()
            .route("/tunnel", connect(handler))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("CONNECT", "/tunnel")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Route patterns that `matchit` can't disambiguate (a named param and a wildcard at the
    /// same position) must surface as a compile error, not a silent mis-route.
    #[test]
    fn test_conflicting_route_patterns_fail_to_compile() {
        async fn dummy() -> &'static str {
            "ok"
        }
        let err = Router::new()
            .route("/user/:id", get(dummy))
            .route("/user/*path", get(dummy))
            .with_state::<()>(())
            .compile()
            .expect_err("conflicting patterns must not compile");
        assert!(err.to_string().contains("Router insert error"), "{err}");
    }

    #[tokio::test]
    async fn test_serve_file_dynamic_reads_on_each_request() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("dynamic.txt");
        std::fs::write(&file, "hello dynamic").unwrap();

        let app = Router::new()
            .serve_file_dynamic("/dyn", file.to_str().unwrap())
            .serve_file_dynamic("/missing", "/nonexistent/file")
            .with_state::<()>(())
            .compile()
            .unwrap();

        let resp = app.handle_request(make_req("GET", "/dyn")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"hello dynamic");

        // Content is re-read per request, so an edit is visible without a restart.
        std::fs::write(&file, "edited").unwrap();
        let resp = app.handle_request(make_req("GET", "/dyn")).await;
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"edited");

        let resp = app.handle_request(make_req("GET", "/missing")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A `ServeDir` under a non-root prefix serves the index for both directory-request forms,
    /// not just the files beneath it.
    #[tokio::test]
    async fn test_serve_dir_under_a_prefix_serves_index_and_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<h1>idx</h1>").unwrap();
        std::fs::write(dir.path().join("app.css"), b"body{}").unwrap();
        std::fs::create_dir(dir.path().join("deep")).unwrap();
        std::fs::write(dir.path().join("deep/index.html"), b"<h1>deep</h1>").unwrap();

        let sd = static_dir::ServeDir::new(dir.path()).index("index.html");
        let app = Router::new()
            .serve_dir("/assets", sd)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        for (path, expected) in [
            ("/assets", &b"<h1>idx</h1>"[..]),
            ("/assets/", &b"<h1>idx</h1>"[..]),
            ("/assets/app.css", &b"body{}"[..]),
            ("/assets/deep/", &b"<h1>deep</h1>"[..]),
        ] {
            let resp = app.handle_request(make_req("GET", path)).await;
            assert_eq!(resp.status(), StatusCode::OK, "path: {path}");
            let body = http_body_util::BodyExt::collect(resp.into_body())
                .await
                .unwrap()
                .to_bytes();
            assert_eq!(&body[..], expected, "path: {path}");
        }
    }

    /// At the root the bare-prefix and trailing-slash routes collapse into one `/` entry
    /// rather than colliding.
    #[tokio::test]
    async fn test_serve_dir_at_root_serves_the_index() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<h1>root</h1>").unwrap();

        let app = Router::new()
            .serve_static(dir.path())
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"<h1>root</h1>");
    }

    /// Applied at compile time, so it covers routes registered after the call too.
    #[tokio::test]
    async fn test_no_index_covers_routes_registered_in_either_order() {
        async fn handler() -> &'static str {
            "hi"
        }

        for app in [
            Router::new().route("/before", get(handler)).no_index(),
            Router::new().no_index().route("/before", get(handler)),
        ] {
            let app = app.with_state::<()>(()).compile().expect("compile");

            let resp = app.handle_request(make_req("GET", "/before")).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers().get("x-robots-tag").expect("header set"),
                "noindex, nofollow"
            );

            let resp = app.handle_request(make_req("GET", "/robots.txt")).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = http_body_util::BodyExt::collect(resp.into_body())
                .await
                .unwrap()
                .to_bytes();
            assert_eq!(&body[..], b"User-agent: *\nDisallow: /\n");
        }
    }

    /// An app that registers its own `/robots.txt` keeps it — `.no_index()` only fills the gap.
    #[tokio::test]
    async fn test_no_index_does_not_clobber_a_custom_robots_txt() {
        let app = Router::new()
            .no_index()
            .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/robots.txt")).await;
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"User-agent: *\nAllow: /\n");
    }

    #[tokio::test]
    async fn test_merge_and_empty_prefix_nest_combine_route_tables() {
        async fn dummy() -> &'static str {
            "ok"
        }
        let app = Router::new()
            .route("/r1", get(dummy))
            .merge(Router::new().route("/r2", get(dummy)))
            .nest("", Router::new().route("/nested", get(dummy)))
            .with_state::<()>(())
            .compile()
            .unwrap();

        for path in ["/r1", "/r2", "/nested"] {
            let resp = app.handle_request(make_req("GET", path)).await;
            assert_eq!(resp.status(), StatusCode::OK, "path: {path}");
        }
    }

    #[tokio::test]
    async fn test_merge_adopts_the_one_fallback_present() {
        async fn h() -> &'static str {
            "h"
        }
        async fn fb() -> &'static str {
            "merged-fallback"
        }

        let r1 = Router::new().route("/r1", get(h));
        let r2 = Router::new().route("/r2", get(h)).fallback(fb);
        let merged = r1.merge(r2).with_state::<()>(()).compile().unwrap();

        let resp = merged.handle_request(make_req("GET", "/missing")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"merged-fallback");
    }

    #[test]
    fn test_merge_two_fallbacks_panics() {
        async fn fb1() -> &'static str {
            "fb1"
        }
        async fn fb2() -> &'static str {
            "fb2"
        }

        let result = std::panic::catch_unwind(|| {
            let r1 = Router::<()>::new().fallback(fb1);
            let r2 = Router::<()>::new().fallback(fb2);
            r1.merge(r2)
        });
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_method_router_hoop_installs_middleware() {
        async fn handler() -> &'static str {
            "hi"
        }
        async fn tag_response(req: Request<Body>, next: middleware::Next<()>) -> Response<Body> {
            let mut resp = next.run(req).await;
            let _ = resp.headers_mut().insert(
                hyper::header::HeaderName::from_static("x-mr-hoop"),
                hyper::header::HeaderValue::from_static("yes"),
            );
            resp
        }

        // `.hoop()` on a bare `MethodRouter` — distinct from `Router::hoop`,
        // which never calls through to `MethodRouter::hoop`; it calls
        // `MethodRouter::hoop_at` directly on every registered route instead.
        let mr = get(handler).hoop(tag_response);
        let app = Router::new()
            .route("/x", mr)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/x")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-mr-hoop").expect("header set"), "yes");
    }

    #[tokio::test]
    async fn test_options_head_trace_free_functions() {
        async fn handle_options() -> &'static str {
            "opts"
        }
        async fn handle_trace() -> &'static str {
            "trace"
        }
        async fn handle_head() -> Response<Body> {
            Response::builder()
                .header("x-handler", "head")
                .body(Body::full(Bytes::from_static(b"head-only")))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
        async fn handle_get_for_head() -> Response<Body> {
            Response::builder()
                .header("x-handler", "get")
                .body(Body::full(Bytes::from_static(b"get-for-head")))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
        async fn handle_get_only() -> &'static str {
            "get-only"
        }

        let app = Router::new()
            .route("/opts", options(handle_options))
            .route("/tracer", trace(handle_trace))
            // An explicit HEAD handler must take priority over the implicit
            // GET fallback (see `CompiledRouter::handle_request`'s
            // `falls_back_to_get` logic).
            .route("/headroute", head(handle_head).get(handle_get_for_head))
            // No explicit HEAD handler here, so HEAD must still fall back to GET.
            .route("/getonly", get(handle_get_only))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("OPTIONS", "/opts")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"opts");

        let resp = app.handle_request(make_req("TRACE", "/tracer")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"trace");

        // The explicit HEAD handler must be the one that actually runs.
        let resp = app.handle_request(make_req("HEAD", "/headroute")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-handler")
                .map(hyper::header::HeaderValue::as_bytes),
            Some(&b"head"[..])
        );
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert!(body.is_empty(), "HEAD responses must have an empty body");

        // GET on the same route still goes to the GET handler.
        let get_resp = app.handle_request(make_req("GET", "/headroute")).await;
        assert_eq!(
            get_resp
                .headers()
                .get("x-handler")
                .map(hyper::header::HeaderValue::as_bytes),
            Some(&b"get"[..])
        );
        let get_body = http_body_util::BodyExt::collect(get_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&get_body[..], b"get-for-head");

        // No HEAD handler registered: HEAD must fall back to the GET handler.
        let resp = app.handle_request(make_req("HEAD", "/getonly")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert!(body.is_empty(), "HEAD responses must have an empty body");
    }

    /// RFC 9110 §9.3.2: `HEAD` reports the same `Content-Length` the `GET` would.
    #[tokio::test]
    async fn test_head_preserves_content_length() {
        async fn body() -> &'static str {
            "hello world"
        }

        let app = Router::new()
            .route("/x", get(body))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let get_len =
            hyper::body::Body::size_hint(app.handle_request(make_req("GET", "/x")).await.body())
                .exact();
        assert_eq!(get_len, Some(11));

        let head = app.handle_request(make_req("HEAD", "/x")).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("11"),
            "HEAD must report the length GET would have sent"
        );
        assert_eq!(
            hyper::body::Body::size_hint(head.body()).exact(),
            Some(0),
            "HEAD must not carry a body"
        );
    }

    /// A `Content-Length` the handler set itself is authoritative.
    #[tokio::test]
    async fn test_head_keeps_explicit_content_length() {
        async fn handler() -> Response<Body> {
            Response::builder()
                .header(hyper::header::CONTENT_LENGTH, "999")
                .body(Body::full(Bytes::from_static(b"short")))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }

        let app = Router::new()
            .route("/x", get(handler))
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let head = app.handle_request(make_req("HEAD", "/x")).await;
        assert_eq!(
            head.headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("999")
        );
    }

    #[tokio::test]
    async fn test_method_not_allowed_fallback_overrides_default_405() {
        async fn get_handler() -> &'static str {
            "got"
        }
        async fn custom_405() -> (StatusCode, &'static str) {
            (StatusCode::IM_A_TEAPOT, "custom-405")
        }

        let app = Router::new()
            .route("/x", get(get_handler))
            .method_not_allowed_fallback(custom_405)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        // /x exists but has no POST handler — the custom fallback answers
        // instead of the default bare 405.
        let resp = app.handle_request(make_req("POST", "/x")).await;
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"custom-405");
    }

    #[tokio::test]
    async fn test_hoop_wraps_fallback_and_method_not_allowed_fallback() {
        async fn get_handler() -> &'static str {
            "got"
        }
        async fn custom_fallback() -> &'static str {
            "custom-fallback"
        }
        async fn custom_405() -> &'static str {
            "custom-405"
        }
        async fn tag_response(req: Request<Body>, next: middleware::Next<()>) -> Response<Body> {
            let mut resp = next.run(req).await;
            let _ = resp.headers_mut().insert(
                hyper::header::HeaderName::from_static("x-hoop"),
                hyper::header::HeaderValue::from_static("wrapped"),
            );
            resp
        }

        // `.fallback()`/`.method_not_allowed_fallback()` must be set *before*
        // `.hoop()`, since `Router::hoop_at` only wraps whichever of the two
        // is already installed at the time it runs.
        let app = Router::new()
            .route("/x", get(get_handler))
            .fallback(custom_fallback)
            .method_not_allowed_fallback(custom_405)
            .hoop(tag_response)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        // Middleware still runs around a normally-matched route.
        let resp = app.handle_request(make_req("GET", "/x")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-hoop").expect("wraps route"),
            "wrapped"
        );

        // Middleware still runs around the custom fallback (unmatched path).
        let resp = app.handle_request(make_req("GET", "/missing")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-hoop").expect("wraps fallback"),
            "wrapped"
        );
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"custom-fallback");

        // Middleware still runs around the method-not-allowed fallback too.
        let resp = app.handle_request(make_req("POST", "/x")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-hoop").expect("wraps 405 fallback"),
            "wrapped"
        );
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"custom-405");
    }

    #[test]
    fn test_compile_returns_duplicate_route_err() {
        async fn handler() -> &'static str {
            "dup"
        }

        // `Router::route`/`.nest()`/`.merge()` all merge same-path entries via
        // `push_or_merge_route`, so two *identical* path strings can never
        // reach `compile()`'s `routes` `Vec` through the public builder API —
        // see the doc comment on `RouterError::DuplicateRoute`. Constructing
        // the `Router` directly is the only way to exercise this internal
        // invariant check; this test lives inside the `routing` module tree,
        // so it can see the otherwise-private `routes` field to do that.
        let router = Router::<()> {
            routes: vec![
                ("/dup".to_string(), get(handler)),
                ("/dup".to_string(), get(handler)),
            ],
            fallback: None,
            method_not_allowed_fallback: None,
            normalize_trailing_slash: false,
            no_index: false,
            #[cfg(feature = "tower")]
            compiled: None,
        };

        let result = router.compile();
        assert!(matches!(result, Err(RouterError::DuplicateRoute(ref p)) if p == "/dup"));
    }

    #[tokio::test]
    async fn test_nest_strips_prefix_preserves_query_string() {
        async fn echo_full(uri: hyper::Uri) -> String {
            uri.query()
                .map_or_else(|| uri.path().to_string(), |q| format!("{}?{q}", uri.path()))
        }

        let api = Router::new().route("/users/{id}", get(echo_full));
        let app = Router::new()
            .nest("/api", api)
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app
            .handle_request(make_req("GET", "/api/users/42?active=true"))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"/users/42?active=true");
    }

    #[tokio::test]
    async fn test_normalize_trailing_slash_preserves_query_string() {
        async fn echo_full(uri: hyper::Uri) -> String {
            uri.query()
                .map_or_else(|| uri.path().to_string(), |q| format!("{}?{q}", uri.path()))
        }

        let app = Router::new()
            .route("/about", get(echo_full))
            .normalize_trailing_slash()
            .with_state::<()>(())
            .compile()
            .expect("compile");

        let resp = app.handle_request(make_req("GET", "/about/?x=1")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"/about?x=1");
    }

    #[tokio::test]
    async fn test_normalize_trailing_slash_no_trailing_slash_is_untouched() {
        async fn handler() -> &'static str {
            "no-trailing"
        }

        let app = Router::new()
            .route("/about", get(handler))
            .normalize_trailing_slash()
            .with_state::<()>(())
            .compile()
            .expect("compile");

        // Already has no trailing slash → `strip_trailing_slash`'s
        // early-return branch.
        let resp = app.handle_request(make_req("GET", "/about")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Root `/` is length 1 → also hits the early-return branch, so it's
        // never stripped down to an empty (invalid) path.
        let root_app = Router::new()
            .route("/", get(handler))
            .normalize_trailing_slash()
            .with_state::<()>(())
            .compile()
            .expect("compile");
        let resp = root_app.handle_request(make_req("GET", "/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
