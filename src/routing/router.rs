//! [`Router`]: the main route-table builder API, plus [`RouterError`].

use bytes::Bytes;
use hyper::{Request, Response};
use std::sync::Arc;

use crate::http::response::Body;
use crate::routing::compiled::{CompiledRouter, extract_param_names};
use crate::routing::handler::Handler;
use crate::routing::method_router::{BoxedIntoRoute, CompiledMethodRouter, MethodRouter, any, get};
use crate::routing::tower_compat::Route;
use crate::routing::{middleware, static_dir, tower_compat};

/// Axum-like routing table using `matchit` under the hood.
///
/// *Axum compatibility: drop-in replacement for `axum::Router`.*
#[derive(Clone)]
pub struct Router<S = ()> {
    pub(crate) routes: Vec<(String, MethodRouter<S>)>,
    pub(crate) fallback: Option<BoxedIntoRoute<S>>,
    pub(crate) method_not_allowed_fallback: Option<BoxedIntoRoute<S>>,
    /// See [`Router::normalize_trailing_slash`].
    pub(crate) normalize_trailing_slash: bool,
    /// See [`Router::no_index`]. Applied at [`compile`](Router::compile) time, so route
    /// registration order doesn't matter.
    pub(crate) no_index: bool,
    /// Populated the first time this `Router` is driven as a `tower::Service`, so `.oneshot()`
    /// works without a separate `.compile()` call while still building the `matchit` tree only
    /// once. Every route-table-mutating builder method resets it to `None`, so mutating after
    /// serving can't dispatch against a stale tree.
    pub(crate) compiled: Option<CompiledRouter<S>>,
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
pub(crate) fn normalize_route_pattern(path: &str) -> String {
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
        self.layer(middleware::from_fn(
            |req: Request<Body>, next: middleware::Next| async move {
                let mut resp = next.run(req).await;
                let _ = resp.headers_mut().insert(
                    hyper::header::HeaderName::from_static("x-robots-tag"),
                    hyper::header::HeaderValue::from_static("noindex, nofollow"),
                );
                resp
            },
        ))
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

        let rebind = |into_route: BoxedIntoRoute<S>| -> BoxedIntoRoute<S2> {
            let state_arc = state_arc.clone();
            Arc::new(move |_new_state: Arc<S2>| into_route(state_arc.clone()))
        };
        let new_fallback = self.fallback.map(rebind);
        let new_method_not_allowed_fallback = self.method_not_allowed_fallback.map(rebind);

        Router {
            routes: new_routes,
            fallback: new_fallback,
            method_not_allowed_fallback: new_method_not_allowed_fallback,
            normalize_trailing_slash: self.normalize_trailing_slash,
            no_index: self.no_index,
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
        self.compiled = None;
        if let Some(pos) = self.routes.iter().position(|(p, _)| *p == path) {
            let (_, existing) = self.routes.remove(pos);
            let merged = existing
                .merge_at(method_router, &path)
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

    /// Converts this router into a `tower::make::MakeService`, matching
    /// `axum::routing::Router::into_make_service`. Only meaningful once `S = ()` (i.e. after
    /// [`Router::with_state`], if the router uses [`State`](crate::routing::extract::State)
    /// extractors at all) — that's also where [`Router<()>`] already implements
    /// `tower::Service` directly, which [`tower_compat::IntoMakeService`] just clones out
    /// per connection.
    #[must_use]
    pub const fn into_make_service(self) -> tower_compat::IntoMakeService<Self> {
        tower_compat::IntoMakeService::new(self)
    }

    /// Converts this router into a `tower::make::MakeService` that also derives a
    /// [`ConnectInfo<C>`](crate::routing::extract::ConnectInfo) from each accepted connection,
    /// matching `axum::routing::Router::into_make_service_with_connect_info`. Only meaningful
    /// once `S = ()` — see [`Router::into_make_service`]'s docs.
    ///
    /// [`Server`](crate::server::Server) doesn't need this — it injects `ConnectInfo` directly
    /// on every request as it accepts each connection. This exists for embedding a bare
    /// `Router` under a different accept loop that only hands you the raw socket addresses.
    #[must_use]
    pub const fn into_make_service_with_connect_info<C>(
        self,
    ) -> tower_compat::IntoMakeServiceWithConnectInfo<Self, C> {
        tower_compat::IntoMakeServiceWithConnectInfo::new(self)
    }

    /// Converts this router into a borrowed `tower::Service` with a fixed body type `B`,
    /// matching `axum::routing::Router::as_service`. Useful for calling a router directly
    /// (e.g. via `tower::ServiceExt::oneshot`) without going through a real server — see
    /// [`Router::into_service`] for an owned equivalent.
    #[must_use]
    pub fn as_service<B>(&mut self) -> tower_compat::RouterAsService<'_, B, S> {
        tower_compat::RouterAsService::new(self)
    }

    /// Converts this router into an owned `tower::Service` with a fixed body type `B`,
    /// matching `axum::routing::Router::into_service`. See [`Router::as_service`] for a
    /// borrowed equivalent.
    #[must_use]
    pub fn into_service<B>(self) -> tower_compat::RouterIntoService<B, S> {
        tower_compat::RouterIntoService::new(self)
    }

    /// Serve an entire directory as static files — the simplest, Nginx-like API.
    ///
    /// Files are streamed from disk by `tower-http`, including range and conditional request
    /// handling.
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
        let sd = static_dir::ServeDir::new(dir_path).append_index_html_on_directories(true);
        self.serve_dir("/", sd)
    }

    /// Serve an entire static directory under a URL prefix with full configuration control.
    ///
    /// Use `serve_static()` for the common case of serving a dir at `/`. See
    /// [`tower_http::services::ServeDir`]'s docs before serving a directory that can contain
    /// user-supplied files.
    #[must_use]
    pub fn serve_dir(self, prefix: &str, serve_dir: static_dir::ServeDir) -> Self {
        let prefix = prefix.trim_end_matches('/');
        let exact = if prefix.is_empty() { "/" } else { prefix };
        let handler = tower_compat::ServiceHandler {
            service: serve_dir,
            strip_prefix: Some(Arc::from(prefix)),
        };
        let router = self.route(exact, all_methods(handler.clone()));
        let router = if prefix.is_empty() {
            router
        } else {
            router.route(&format!("{prefix}/"), all_methods(handler.clone()))
        };
        router.route(
            &format!("{prefix}/*__tachyon_static_rest"),
            all_methods(handler),
        )
    }

    /// Natively serve a specific file on a specific route.
    ///
    /// # Errors
    /// Returns an `Err` if the path does not name a regular file at startup.
    pub fn serve_file(self, path: &str, file_path: &str) -> Result<Self, std::io::Error> {
        let metadata = std::fs::metadata(file_path)?;
        if !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "static file path is not a regular file",
            ));
        }
        Ok(self.route(
            path,
            crate::routing::get_service(static_dir::ServeFile::new(file_path)),
        ))
    }

    /// Natively serve a specific file on a specific route dynamically.
    ///
    /// The file is read from disk on every request. Ideal for large files that
    /// change frequently where startup preloading is undesirable.
    #[must_use]
    pub fn serve_file_dynamic(self, path: &str, file_path: &str) -> Self {
        self.route(
            path,
            crate::routing::get_service(static_dir::ServeFile::new(file_path)),
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
    pub fn merge<R: Into<Self>>(mut self, other: R) -> Self {
        let mut other = other.into();
        self.compiled = None;
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
    /// Prefer `.route(path, get(handler))` with a native handler where possible —
    /// this exists to bridge in pre-built Tower/tower-http services (e.g.
    /// `tower_http::services::ServeFile`) without a rewrite.
    #[must_use]
    pub fn route_service<Svc, RespBody>(self, path: &str, service: Svc) -> Self
    where
        Svc: tower::Service<Request<Body>, Response = Response<RespBody>>
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
    #[must_use]
    pub fn nest_service<Svc, RespBody>(self, prefix: &str, service: Svc) -> Self
    where
        Svc: tower::Service<Request<Body>, Response = Response<RespBody>>
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
    #[must_use]
    pub fn fallback_service<Svc, RespBody>(mut self, service: Svc) -> Self
    where
        Svc: tower::Service<Request<Body>, Response = Response<RespBody>>
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
        self.fallback = Some(Arc::new(move |state| {
            Route::from_handler(handler.clone(), &state)
        }));
        self.compiled = None;
        self
    }

    /// Apply a `tower::Layer` to every route **and** the fallback (and
    /// [`method_not_allowed_fallback`](Self::method_not_allowed_fallback), a
    /// tachyon addition Axum has no equivalent of) registered **so far** in
    /// this router — matching `axum::Router::layer`.
    #[must_use]
    pub fn layer<L, RespBody>(mut self, layer: L) -> Self
    where
        L: tower::Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<Request<Body>, Response = Response<RespBody>>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as tower::Service<Request<Body>>>::Future: Send + 'static,
        <L::Service as tower::Service<Request<Body>>>::Error:
            Into<crate::http::error::Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<crate::http::error::Error>,
    {
        self.routes = self
            .routes
            .into_iter()
            .map(|(path, mr)| {
                (
                    path,
                    mr.layer((tower_compat::ResponseAxumBodyLayer::new(), layer.clone())),
                )
            })
            .collect();
        if let Some(old) = self.fallback.take() {
            let layer = layer.clone();
            self.fallback = Some(Arc::new(move |state| {
                old(state).layer(&(tower_compat::ResponseAxumBodyLayer::new(), layer.clone()))
            }));
        }
        if let Some(old) = self.method_not_allowed_fallback.take() {
            self.method_not_allowed_fallback = Some(Arc::new(move |state| {
                old(state).layer(&(tower_compat::ResponseAxumBodyLayer::new(), layer.clone()))
            }));
        }
        self.compiled = None;
        self
    }

    /// Apply a `tower::Layer` to every registered route, but *not* the fallback —
    /// matching Axum's distinction between `.layer()` and `.route_layer()`.
    #[must_use]
    pub fn route_layer<L, RespBody>(mut self, layer: L) -> Self
    where
        L: tower::Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<Request<Body>, Response = Response<RespBody>>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as tower::Service<Request<Body>>>::Future: Send + 'static,
        <L::Service as tower::Service<Request<Body>>>::Error:
            Into<crate::http::error::Error> + Send,
        RespBody: hyper::body::Body<Data = Bytes> + Send + 'static,
        RespBody::Error: Into<crate::http::error::Error>,
    {
        self.routes = self
            .routes
            .into_iter()
            .map(|(path, mr)| {
                (
                    path,
                    mr.layer((tower_compat::ResponseAxumBodyLayer::new(), layer.clone())),
                )
            })
            .collect();
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
        self.fallback = Some(Arc::new(move |state| {
            Route::from_handler(handler.clone(), &state)
        }));
        self.compiled = None;
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
        self.method_not_allowed_fallback = Some(Arc::new(move |state| {
            Route::from_handler(handler.clone(), &state)
        }));
        self.compiled = None;
        self
    }

    /// Clears any fallback set via [`Router::fallback`]/[`Router::fallback_service`], reverting
    /// to the default `404 Not Found`.
    #[must_use]
    pub fn reset_fallback(mut self) -> Self {
        self.fallback = None;
        self.compiled = None;
        self
    }

    /// Whether this router has any routes registered.
    #[must_use]
    pub const fn has_routes(&self) -> bool {
        !self.routes.is_empty()
    }

    /// A no-op builder method, matching `axum::routing::Router::without_v07_checks`.
    ///
    /// Axum 0.8 added a stricter path-conflict check on top of 0.7's, and this opts back
    /// out of it; this crate's `matchit`-backed router only ever had the one (equivalent
    /// to 0.8's) conflict check, so there is no looser mode to opt into.
    #[must_use]
    pub const fn without_v07_checks(self) -> Self {
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
        let state = Arc::new(S::default());
        let mut matcher: matchit::Router<CompiledMethodRouter> = matchit::Router::new();

        let mut seen = std::collections::HashSet::new();
        for (path, mut method_router) in this.routes {
            if !seen.insert(path.clone()) {
                return Err(RouterError::DuplicateRoute(path));
            }
            method_router.param_names = extract_param_names(&path);
            method_router.matched_path = Arc::from(path.as_str());
            let compiled = method_router.materialize(&state);
            matcher.insert(path, compiled)?;
        }

        Ok(CompiledRouter {
            matcher,
            fallback: this.fallback.map(|f| f(state.clone())),
            method_not_allowed_fallback: this.method_not_allowed_fallback.map(|f| f(state.clone())),
            normalize_trailing_slash: this.normalize_trailing_slash,
            _marker: std::marker::PhantomData,
        })
    }
}

/// Errors that can occur during router construction or compilation.
///
/// *Tachyon extension: no `axum` equivalent.*
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
