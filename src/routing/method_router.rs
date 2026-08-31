//! Per-method dispatch table: [`MethodRouter`], the per-verb builder methods
//! (`.get()`, `.post()`, …), and [`MethodFilter`]/[`on`]/[`on_service`].

use crate::http::Request;
use hyper::Method;
use std::sync::Arc;

use crate::routing::handler::Handler;
use crate::routing::router::RouterError;
use crate::routing::tower_compat::Route;
#[cfg(feature = "early-hints")]
use crate::routing::{fire_early_hints, middleware};

pub(crate) const IDX_GET: usize = 0;
const IDX_POST: usize = 1;
const IDX_PUT: usize = 2;
const IDX_DELETE: usize = 3;
const IDX_OPTIONS: usize = 4;
pub(crate) const IDX_HEAD: usize = 5;
const IDX_PATCH: usize = 6;
const IDX_TRACE: usize = 7;
const IDX_CONNECT: usize = 8;
pub(crate) const METHOD_COUNT: usize = 9;

const METHOD_NAMES: [&str; METHOD_COUNT] = [
    "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT",
];

#[inline]
pub(crate) const fn method_index(m: &Method) -> Option<usize> {
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

/// Builds a [`Route`] once `state` is known — every method-router slot and
/// router-level fallback is one of these until [`Router::compile`] (or
/// [`Router::with_state`], which rebinds it) finally has a concrete state to
/// call it with. Applying a `.layer()` before that point wraps this closure
/// rather than a `Route` directly, deferring the actual `tower::Layer::layer()`
/// call to materialization time — the same reason Axum's own `MethodRouter`
/// keeps handlers boxed-but-unbound until `with_state`.
pub(crate) type BoxedIntoRoute<S, E = std::convert::Infallible> =
    Arc<dyn Fn(Arc<S>) -> Route<E> + Send + Sync>;

/// Router that dispatches requests to different handlers based on the HTTP method.
///
/// `E` matches axum's `MethodRouter<S, E = Infallible>` shape and is a real, propagated
/// error type for raw-`tower::Service` slots (built via `*_service`/`on_service`/
/// `any_service`): the service's error survives unconverted all the way up to
/// [`crate::routing::Router::route`], which — like axum — only accepts a `MethodRouter`
/// once `E = Infallible`. `Handler`-based slots (`.get()`/`.post()`/…) never carry a live
/// `E` at all, since [`Handler`] has no `Error` type — every handler call already resolves
/// to a `Response` before it reaches a [`Route`].
///
/// *Axum compatibility: drop-in replacement for `axum::routing::MethodRouter`.*
pub struct MethodRouter<S = (), E = std::convert::Infallible> {
    pub(crate) handlers: [Option<BoxedIntoRoute<S, E>>; METHOD_COUNT],
    /// Path-parameter names in declaration order, populated by `Router::compile()`. Cloning
    /// an `Arc<str>` into `PathParams` is a refcount bump rather than a per-request
    /// allocation.
    pub(crate) param_names: Arc<[Arc<str>]>,
    /// The route pattern this handler is registered under (e.g. `/users/{id}`), exposed via
    /// the [`MatchedPath`](crate::routing::extract::MatchedPath) extractor.
    pub(crate) matched_path: Arc<str>,
    /// The accumulated prefix to strip from the request `Uri` before dispatch, when this
    /// route was reached through one or more [`Router::nest`] calls.
    pub(crate) nest_prefix: Option<Arc<str>>,
    _marker: std::marker::PhantomData<fn() -> E>,
}

impl<S, E> Clone for MethodRouter<S, E> {
    fn clone(&self) -> Self {
        Self {
            handlers: self.handlers.clone(),
            param_names: self.param_names.clone(),
            matched_path: self.matched_path.clone(),
            nest_prefix: self.nest_prefix.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S, E> std::fmt::Debug for MethodRouter<S, E> {
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

impl<S, E> Default for MethodRouter<S, E>
where
    S: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S, E> MethodRouter<S, E>
where
    S: Clone,
{
    /// Create a new empty `MethodRouter`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: [const { None }; METHOD_COUNT],
            param_names: Arc::from([]),
            matched_path: Arc::from(""),
            nest_prefix: None,
            _marker: std::marker::PhantomData,
        }
    }

    /// Registers a raw `tower::Service` at `idx`, storing a genuinely fallible `Route<E>` —
    /// used by the `*_service`/`on_service`/`any_service` constructors. Unlike [`Self::set`]
    /// (Handler-based, always infallible), this never routes through [`Handler`].
    fn set_service<Svc>(mut self, idx: usize, service: Svc) -> Self
    where
        Svc: tower::Service<Request, Error = E> + Clone + Send + Sync + 'static,
        Svc::Response: crate::http::response::IntoResponse + 'static,
        Svc::Future: Send + 'static,
    {
        if let Some(slot) = self.handlers.get_mut(idx) {
            *slot = Some(Arc::new(move |_state: Arc<S>| Route::new(service.clone())));
        }
        self
    }

    /// Merges `other`'s method handlers into `self`: registering the same path twice with
    /// non-overlapping methods combines into a single route, matching Axum.
    ///
    /// # Errors
    /// Returns [`RouterError::MethodOverlap`] if `other` defines a method already present in
    /// `self` — where Axum panics with "Overlapping method route".
    pub(crate) fn merge(mut self, mut other: Self, path: &str) -> Result<Self, RouterError> {
        for (i, (mine, theirs)) in self
            .handlers
            .iter_mut()
            .zip(other.handlers.iter_mut())
            .enumerate()
        {
            if let Some(handler) = theirs.take() {
                if mine.is_some() {
                    return Err(RouterError::MethodOverlap {
                        method: METHOD_NAMES.get(i).copied().unwrap_or("UNKNOWN"),
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

    /// Apply a `tower::Layer` to every endpoint registered in this
    /// `MethodRouter` **so far** — matching `axum::routing::MethodRouter::layer`.
    /// Call this after the verb builders (`.get()`/`.post()`/...) it should cover.
    #[must_use]
    pub fn layer<L, NewError>(mut self, layer: L) -> MethodRouter<S, NewError>
    where
        L: tower::Layer<Route<E>> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<Request> + Clone + Send + Sync + 'static,
        <L::Service as tower::Service<Request>>::Response:
            crate::http::response::IntoResponse + 'static,
        <L::Service as tower::Service<Request>>::Error: Into<NewError> + 'static,
        <L::Service as tower::Service<Request>>::Future: Send + 'static,
        E: 'static,
        S: 'static,
        NewError: 'static,
    {
        let mut new_handlers: [Option<BoxedIntoRoute<S, NewError>>; METHOD_COUNT] =
            [const { None }; METHOD_COUNT];
        for (slot, old) in new_handlers.iter_mut().zip(self.handlers.iter_mut()) {
            if let Some(old) = old.take() {
                let layer = layer.clone();
                *slot = Some(Arc::new(move |state: Arc<S>| old(state).layer(&layer)));
            }
        }
        MethodRouter {
            handlers: new_handlers,
            param_names: self.param_names,
            matched_path: self.matched_path,
            nest_prefix: self.nest_prefix,
            _marker: std::marker::PhantomData,
        }
    }

    /// Capture a state and transition this method router to another state type.
    #[must_use]
    pub fn with_state<S2>(self, state: &Arc<S>) -> MethodRouter<S2, E>
    where
        S2: Clone + Send + Sync + 'static,
        S: Clone + Send + Sync + 'static,
        E: 'static,
    {
        let mut new_handlers: [Option<BoxedIntoRoute<S2, E>>; METHOD_COUNT] =
            [const { None }; METHOD_COUNT];
        for (slot, opt_handler) in new_handlers.iter_mut().zip(self.handlers.iter()) {
            if let Some(into_route) = opt_handler {
                let into_route = into_route.clone();
                let state = state.clone();
                *slot = Some(Arc::new(move |_new_state: Arc<S2>| {
                    into_route(state.clone())
                }));
            }
        }
        MethodRouter {
            handlers: new_handlers,
            param_names: self.param_names,
            matched_path: self.matched_path,
            nest_prefix: self.nest_prefix,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S> MethodRouter<S, std::convert::Infallible>
where
    S: Clone,
{
    /// Registers a [`Handler`] at `idx` — always infallible, since `Handler::call` has no
    /// `Error` type to propagate.
    fn set<H, T>(mut self, idx: usize, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
        S: Send + Sync + 'static,
    {
        if let Some(slot) = self.handlers.get_mut(idx) {
            *slot = Some(Arc::new(move |state: Arc<S>| {
                Route::from_handler(handler.clone(), &state)
            }));
        }
        self
    }

    /// Sends a `103 Early Hints` response carrying `links` before this route's handler runs.
    ///
    /// The `Link` header block is rendered once, here, and cloned per request — there is no
    /// per-request formatting, and the hint goes out before any other middleware on this
    /// route has done work. On a transport that cannot carry a 103 this costs one map
    /// lookup and nothing else.
    ///
    /// Use this for hints that don't depend on the request. For hints that do, extract
    /// [`EarlyHints`](crate::http::early_hints::EarlyHints) in the handler instead.
    ///
    /// **Do not attach this to a route that may redirect.** Hints preceding a `3xx` preload
    /// resources for a page that is never rendered — see
    /// [`http::early_hints`](crate::http::early_hints).
    ///
    /// ```rust
    /// use tachyon_web::{Router, get};
    /// use tachyon_web::http::early_hints::Link;
    ///
    /// let app: Router = Router::new().route(
    ///     "/",
    ///     get(|| async { "…" }).early_hints([Link::preload("/app.css").as_style()]),
    /// );
    /// ```
    #[cfg(feature = "early-hints")]
    #[must_use]
    pub fn early_hints(
        self,
        links: impl IntoIterator<Item = crate::http::early_hints::Link>,
    ) -> Self
    where
        S: 'static,
    {
        let headers = crate::http::early_hints::links_to_headers(links);
        if headers.is_empty() {
            return self;
        }
        self.layer(middleware::from_fn(
            move |req: crate::http::Request, next: middleware::Next| {
                let headers = headers.clone();
                async move {
                    fire_early_hints(&req, headers);
                    next.run(req).await
                }
            },
        ))
    }

    /// Materializes every `BoxedIntoRoute<S, Infallible>` slot into a concrete, state-free
    /// [`Route`] by calling it with `state` — the one point any layers
    /// applied so far actually run `tower::Layer::layer()`. Only ever called from
    /// [`crate::routing::Router::compile`], which — matching axum — only ever holds
    /// `MethodRouter<S, Infallible>` entries.
    pub(crate) fn materialize(&self, state: &Arc<S>) -> CompiledMethodRouter {
        let mut handlers: [Option<Route>; METHOD_COUNT] = [const { None }; METHOD_COUNT];
        for (slot, into_route) in handlers.iter_mut().zip(self.handlers.iter()) {
            *slot = into_route.as_ref().map(|f| f(state.clone()));
        }
        CompiledMethodRouter {
            handlers,
            param_names: self.param_names.clone(),
            #[cfg(feature = "matched-path")]
            matched_path: self.matched_path.clone(),
            nest_prefix: self.nest_prefix.clone(),
        }
    }
}

/// The fully state-bound form of [`MethodRouter`], produced by
/// [`MethodRouter::materialize`] at [`Router::compile`] time. Every slot is a
/// ready-to-call [`Route`] — no more state or further layering to apply.
#[derive(Clone)]
pub(crate) struct CompiledMethodRouter {
    pub(crate) handlers: [Option<Route>; METHOD_COUNT],
    pub(crate) param_names: Arc<[Arc<str>]>,
    #[cfg(feature = "matched-path")]
    pub(crate) matched_path: Arc<str>,
    pub(crate) nest_prefix: Option<Arc<str>>,
}

impl CompiledMethodRouter {
    /// The `Allow` header value listing every registered method, in Axum's format
    /// (comma-joined, no spaces). `HEAD` is listed whenever `GET` is, since a `GET` handler
    /// answers `HEAD` when no explicit one is registered.
    pub(crate) fn allow_header(&self) -> String {
        let mut out = String::with_capacity(56);
        let implicit_head = self.handlers[IDX_GET].is_some() && self.handlers[IDX_HEAD].is_none();
        for (i, name) in METHOD_NAMES.iter().enumerate() {
            if self.handlers.get(i).is_some_and(Option::is_some) {
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
}

/// Generates the nine per-verb `MethodRouter` builder methods (`.get()`, `.post()`, …), their
/// raw-`tower::Service` counterparts (`.get_service()`, `.post_service()`, …), and matching
/// free-function shortcuts of both (`get(h)`, `get_service(svc)`, …) — one set per HTTP method,
/// all structurally identical apart from which slot of `handlers` they fill.
macro_rules! method_routes {
    ($( ($name:ident, $svc_name:ident, $idx:ident, $verb:literal) ),+ $(,)?) => {
        // Handler-chaining methods are only available while `E = Infallible` — matching
        // Axum's own restriction (`impl<S> MethodRouter<S, Infallible>`), since a `Handler`
        // never fails, so chaining one onto an already-layered, non-`Infallible` router
        // wouldn't have a sensible `E` to report. Reaching for one of these after `.layer()`
        // is a genuine ordering bug axum also rejects, just via a different mechanism (a
        // missing `on`/`get`/... method rather than a fallback inherent one).
        impl<S> MethodRouter<S, std::convert::Infallible>
        where
            S: Clone,
        {
            $(
                #[doc = concat!("Add a handler for HTTP ", $verb, " requests.")]
                #[must_use]
                pub fn $name<H, T>(self, handler: H) -> Self
                where
                    H: Handler<T, S>,
                    T: 'static,
                    S: Send + Sync + 'static,
                {
                    self.set($idx, handler)
                }
            )+
        }

        impl<S, E> MethodRouter<S, E>
        where
            S: Clone,
        {
            $(
                #[doc = concat!(
                    "Add a raw `tower::Service` handler for HTTP ", $verb,
                    " requests, matching `axum::routing::method_routing::", stringify!($svc_name), "`. ",
                    "`service`'s error becomes this router's `E` — chaining another raw service onto ",
                    "the same `MethodRouter` requires the same error type."
                )]
                #[must_use]
                pub fn $svc_name<Svc>(self, service: Svc) -> Self
                where
                    Svc: tower::Service<Request, Error = E> + Clone + Send + Sync + 'static,
                    Svc::Response: crate::http::response::IntoResponse + 'static,
                    Svc::Future: Send + 'static,
                {
                    self.set_service($idx, service)
                }
            )+
        }

        $(
            #[doc = concat!("Helper to construct a ", $verb, "-only route.")]
            #[doc = ""]
            #[doc = concat!(
                "*Axum compatibility: drop-in replacement for `axum::routing::",
                stringify!($name), "`.*"
            )]
            pub fn $name<H, T, S>(handler: H) -> MethodRouter<S, std::convert::Infallible>
            where
                H: Handler<T, S>,
                T: 'static,
                S: Clone + Send + Sync + 'static,
            {
                MethodRouter::new().$name(handler)
            }

            #[doc = concat!(
                "Helper to construct a ", $verb,
                "-only route from a raw `tower::Service`."
            )]
            #[doc = ""]
            #[doc = concat!(
                "*Axum compatibility: drop-in replacement for `axum::routing::",
                stringify!($svc_name), "`.*"
            )]
            pub fn $svc_name<T, S>(svc: T) -> MethodRouter<S, T::Error>
            where
                T: tower::Service<Request> + Clone + Send + Sync + 'static,
                T::Response: crate::http::response::IntoResponse + 'static,
                T::Future: Send + 'static,
                S: Clone,
            {
                MethodRouter::new().$svc_name(svc)
            }
        )+

        /// A route dispatching every HTTP method to `handler`, matching `axum::routing::any`.
        ///
        /// *Axum compatibility: drop-in replacement for `axum::routing::any`.*
        pub fn any<H, T, S>(handler: H) -> MethodRouter<S, std::convert::Infallible>
        where
            H: Handler<T, S>,
            T: 'static,
            S: Clone + Send + Sync + 'static,
        {
            let router = MethodRouter::new();
            $( let router = router.$name(handler.clone()); )+
            router
        }

        /// A route dispatching every HTTP method to a raw `tower::Service`, matching
        /// `axum::routing::any_service`.
        ///
        /// *Axum compatibility: drop-in replacement for `axum::routing::any_service`.*
        pub fn any_service<T, S>(svc: T) -> MethodRouter<S, T::Error>
        where
            T: tower::Service<Request> + Clone + Send + Sync + 'static,
            T::Response: crate::http::response::IntoResponse + 'static,
            T::Future: Send + 'static,
            S: Clone,
        {
            let router = MethodRouter::new();
            $( let router = router.$svc_name(svc.clone()); )+
            router
        }
    };
}

method_routes! {
    (get, get_service, IDX_GET, "GET"),
    (post, post_service, IDX_POST, "POST"),
    (put, put_service, IDX_PUT, "PUT"),
    (delete, delete_service, IDX_DELETE, "DELETE"),
    (options, options_service, IDX_OPTIONS, "OPTIONS"),
    (head, head_service, IDX_HEAD, "HEAD"),
    (patch, patch_service, IDX_PATCH, "PATCH"),
    (trace, trace_service, IDX_TRACE, "TRACE"),
    (connect, connect_service, IDX_CONNECT, "CONNECT"),
}

/// A bitmask of HTTP methods, matching `axum::routing::MethodFilter`.
///
/// Used by [`on`] and [`on_service`]/`MethodRouter::on`/`MethodRouter::on_service` to register
/// a handler against more than one method at once.
///
/// *Axum compatibility: drop-in replacement for `axum::routing::MethodFilter`.*
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodFilter(u16);

impl MethodFilter {
    /// Matches `CONNECT` requests.
    pub const CONNECT: Self = Self(1u16 << IDX_CONNECT);
    /// Matches `DELETE` requests.
    pub const DELETE: Self = Self(1u16 << IDX_DELETE);
    /// Matches `GET` requests.
    pub const GET: Self = Self(1u16 << IDX_GET);
    /// Matches `HEAD` requests.
    pub const HEAD: Self = Self(1u16 << IDX_HEAD);
    /// Matches `OPTIONS` requests.
    pub const OPTIONS: Self = Self(1u16 << IDX_OPTIONS);
    /// Matches `PATCH` requests.
    pub const PATCH: Self = Self(1u16 << IDX_PATCH);
    /// Matches `POST` requests.
    pub const POST: Self = Self(1u16 << IDX_POST);
    /// Matches `PUT` requests.
    pub const PUT: Self = Self(1u16 << IDX_PUT);
    /// Matches `TRACE` requests.
    pub const TRACE: Self = Self(1u16 << IDX_TRACE);

    #[must_use]
    const fn contains_idx(self, idx: usize) -> bool {
        self.0 & (1u16 << idx) != 0
    }

    /// Combines two filters, matching every method either one matches.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for MethodFilter {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Error returned by `MethodFilter`'s `TryFrom<Method>` impl: `method` isn't one of the nine
/// HTTP methods `MethodFilter` can represent.
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoMatchingMethodFilter {
    method: Method,
}

impl std::fmt::Display for NoMatchingMethodFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no `MethodFilter` matches `{}`", self.method)
    }
}

impl std::error::Error for NoMatchingMethodFilter {}

impl TryFrom<Method> for MethodFilter {
    type Error = NoMatchingMethodFilter;

    fn try_from(method: Method) -> Result<Self, Self::Error> {
        method_index(&method)
            .map(|idx| Self(1u16 << idx))
            .ok_or(NoMatchingMethodFilter { method })
    }
}

impl<S> MethodRouter<S, std::convert::Infallible>
where
    S: Clone,
{
    /// Add a handler for every HTTP method set in `filter`, matching
    /// `axum::routing::MethodRouter::on`.
    #[must_use]
    pub fn on<H, T>(mut self, filter: MethodFilter, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
        S: Send + Sync + 'static,
    {
        let indices: Vec<usize> = (0..METHOD_COUNT)
            .filter(|&idx| filter.contains_idx(idx))
            .collect();
        let Some((&last, init)) = indices.split_last() else {
            return self;
        };
        for &idx in init {
            self = self.set(idx, handler.clone());
        }
        self.set(last, handler)
    }
}

impl<S, E> MethodRouter<S, E>
where
    S: Clone,
{
    /// Add a raw `tower::Service` handler for every HTTP method set in `filter`, matching
    /// `axum::routing::MethodRouter::on_service`. `service`'s error becomes this router's `E`.
    #[must_use]
    pub fn on_service<Svc>(mut self, filter: MethodFilter, service: Svc) -> Self
    where
        Svc: tower::Service<Request, Error = E> + Clone + Send + Sync + 'static,
        Svc::Response: crate::http::response::IntoResponse + 'static,
        Svc::Future: Send + 'static,
    {
        let indices: Vec<usize> = (0..METHOD_COUNT)
            .filter(|&idx| filter.contains_idx(idx))
            .collect();
        let Some((&last, init)) = indices.split_last() else {
            return self;
        };
        for &idx in init {
            self = self.set_service(idx, service.clone());
        }
        self.set_service(last, service)
    }
}

/// Helper to construct a route for every HTTP method set in `filter`, matching
/// `axum::routing::on`.
///
/// *Axum compatibility: drop-in replacement for `axum::routing::on`.*
pub fn on<H, T, S>(filter: MethodFilter, handler: H) -> MethodRouter<S, std::convert::Infallible>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    MethodRouter::new().on(filter, handler)
}

/// Helper to construct a route for every HTTP method set in `filter` from a raw
/// `tower::Service`, matching `axum::routing::on_service`.
///
/// *Axum compatibility: drop-in replacement for `axum::routing::on_service`.*
pub fn on_service<T, S>(filter: MethodFilter, svc: T) -> MethodRouter<S, T::Error>
where
    T: tower::Service<Request> + Clone + Send + Sync + 'static,
    T::Response: crate::http::response::IntoResponse + 'static,
    T::Future: Send + 'static,
    S: Clone,
{
    MethodRouter::new().on_service(filter, svc)
}
