//! The compiled routing engine: [`CompiledRouter`] and its `matchit`-backed
//! request dispatch (the hot path).

use bytes::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;

use crate::http::response::Body;
use crate::routing::extract;
use crate::routing::extract::PathParams;
use crate::routing::method_router::{CompiledMethodRouter, IDX_GET, IDX_HEAD, method_index};
use crate::routing::tower_compat::Route;

/// A compiled routing table ready to serve requests.
///
/// Every route, the fallback, and the method-not-allowed fallback are already
/// fully materialized [`Route`]s at this point — `S` is kept only as a
/// phantom type parameter for API-shape continuity (`CompiledRouter<S>`);
/// dispatch itself needs no further state, since it was bound once, here, at
/// [`crate::routing::router::Router::compile`] time.
///
/// *Tachyon extension: no `axum` equivalent.*
pub struct CompiledRouter<S> {
    pub(crate) matcher: matchit::Router<CompiledMethodRouter>,
    pub(crate) fallback: Option<Route>,
    pub(crate) method_not_allowed_fallback: Option<Route>,
    pub(crate) normalize_trailing_slash: bool,
    pub(crate) _marker: std::marker::PhantomData<fn() -> S>,
}

// Not `#[derive(Clone)]`: that would add a spurious `S: Clone` bound (the
// derive macro doesn't know `S` is only ever used inside a `PhantomData`).
impl<S> Clone for CompiledRouter<S> {
    fn clone(&self) -> Self {
        Self {
            matcher: self.matcher.clone(),
            fallback: self.fallback.clone(),
            method_not_allowed_fallback: self.method_not_allowed_fallback.clone(),
            normalize_trailing_slash: self.normalize_trailing_slash,
            _marker: std::marker::PhantomData,
        }
    }
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
pub(crate) fn extract_param_names(path: &str) -> Arc<[Arc<str>]> {
    let mut names = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        let after_brace = i.saturating_add(1);
        if byte == b'{'
            && let Some(rest) = path.get(after_brace..)
            && let Some(end) = rest.find('}')
            && let Some(inner) = rest.get(..end)
        {
            let name = inner.strip_prefix('*').unwrap_or(inner);
            names.push(Arc::from(name));
            i = after_brace.saturating_add(end).saturating_add(1);
        } else {
            i = i.saturating_add(1);
        }
    }
    Arc::from(names)
}

/// Shared percent-decoding scan, used for both path segments and query/form values.
///
/// `plus_as_space` treats `+` as a literal space, the query-string convention (never applied
/// to path segments). `abort_on_invalid_escape` controls what an unparsable `%XX` does: abort
/// the whole decode (path segments, where the caller falls back to the raw, still-encoded
/// value on `None`) or keep the `%` literally and continue (query/form values, where a
/// dropped `%` mid-value would be a worse failure mode than a partially-decoded string).
fn decode_percent_bytes(
    s: &str,
    plus_as_space: bool,
    abort_on_invalid_escape: bool,
) -> Option<std::borrow::Cow<'_, str>> {
    let bytes = s.as_bytes();
    let needs_decode = bytes.contains(&b'%') || (plus_as_space && bytes.contains(&b'+'));
    if !needs_decode {
        return Some(std::borrow::Cow::Borrowed(s));
    }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'%' => {
                let hex = bytes.get(i.saturating_add(1)..i.saturating_add(3));
                if let Some(hex) = hex
                    && let Ok(hex_str) = std::str::from_utf8(hex)
                    && let Ok(val) = u8::from_str_radix(hex_str, 16)
                {
                    decoded.push(val);
                    i = i.saturating_add(3);
                    continue;
                }
                if abort_on_invalid_escape {
                    return None;
                }
                decoded.push(b'%');
                i = i.saturating_add(1);
            }
            b'+' if plus_as_space => {
                decoded.push(b' ');
                i = i.saturating_add(1);
            }
            other => {
                decoded.push(other);
                i = i.saturating_add(1);
            }
        }
    }
    let s = String::from_utf8(decoded).ok()?;
    Some(std::borrow::Cow::Owned(s))
}

/// Zero-allocation percent-decoding helper for path parameters.
///
/// Returns `None` if the input contains invalid percent encoding.
pub(crate) fn percent_decode(s: &str) -> Option<std::borrow::Cow<'_, str>> {
    decode_percent_bytes(s, false, true)
}

/// Lenient percent/`+`-decoding for query strings and form bodies: an unparsable `%XX`
/// escape is kept as a literal `%` rather than failing the whole value, since real-world
/// query strings and forms sometimes carry a bare `%`.
#[cfg(any(feature = "query", feature = "form"))]
pub(crate) fn decode_query_param(s: &str) -> std::borrow::Cow<'_, str> {
    decode_percent_bytes(s, true, false).unwrap_or(std::borrow::Cow::Borrowed(s))
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
    let new_path = path
        .get(..path.len().saturating_sub(1))
        .unwrap_or(path)
        .to_string();
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

/// Runs `route` (a boxed, infallible `tower::Service`) against `req`, matching
/// the plain `Response<Body>` shape every dispatch call site here wants.
#[inline]
async fn call_route(route: &Route, req: Request<Body>) -> Response<Body> {
    use tower::{Service, ServiceExt};
    let mut route = route.clone();
    match route.ready().await {
        Ok(ready) => match ready.call(req).await {
            Ok(resp) => resp,
            Err(never) => match never {},
        },
        Err(never) => match never {},
    }
}

impl<S> CompiledRouter<S> {
    /// Route an incoming request, returning the resulting HTTP response.
    ///
    /// Routes match **exactly**, as in Axum: `/foo` and `/foo/` are distinct and neither falls
    /// back to the other unless [`crate::routing::router::Router::normalize_trailing_slash`] was set. Paths are
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

        let (method_router, params): RouteResolution<'_> = match self.resolve(path) {
            Some(r) => r,
            None => {
                return if let Some(fb) = &self.fallback {
                    call_route(fb, req).await
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
            let _ = req
                .extensions_mut()
                .insert(crate::routing::extract::NestedPath(Arc::clone(prefix)));
            strip_uri_prefix(&mut req, prefix);
        }

        method_router
            .dispatch(req, self.method_not_allowed_fallback.as_ref())
            .await
    }

    /// Internal: attempt to match `path`, returning `RouteResolution`.
    #[inline]
    fn resolve(&self, path: &str) -> Option<RouteResolution<'_>> {
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
pub(crate) type RouteResolution<'a> = (&'a CompiledMethodRouter, extract::PathParamsVec);

impl CompiledMethodRouter {
    /// Dispatches an already-path-matched request to the handler for its method (falling
    /// back to `GET` for an unregistered `HEAD`), this route's own
    /// [`fallback`](CompiledMethodRouter::fallback) if the method has no handler, then
    /// `router_fallback` (the enclosing `Router`'s `method_not_allowed_fallback`, when
    /// dispatched through one), then a bare `405`.
    pub(crate) async fn dispatch(
        &self,
        req: Request<Body>,
        router_fallback: Option<&Route>,
    ) -> Response<Body> {
        let method = req.method();
        let idx = method_index(method);

        // HEAD uses an explicit HEAD handler when registered; otherwise it
        // falls back to the GET handler, with the body discarded afterwards.
        let is_head = *method == Method::HEAD;
        let falls_back_to_get =
            is_head && self.handlers[IDX_HEAD].is_none() && idx == Some(IDX_HEAD);
        let effective_idx = if falls_back_to_get {
            Some(IDX_GET)
        } else {
            idx
        };

        let route = effective_idx.and_then(|i| self.handlers.get(i).and_then(Option::as_ref));

        if let Some(route) = route {
            let mut resp = call_route(route, req).await;
            // Per HTTP semantics, a HEAD response must never carry a body,
            // regardless of whether it came from an explicit HEAD handler or
            // the implicit GET fallback.
            if is_head {
                discard_body_for_head(&mut resp);
            }
            resp
        } else if let Some(fb) = &self.fallback {
            // Route exists but this method has no handler, and this specific route has
            // its own `MethodRouter::fallback`/`fallback_service` — takes priority over
            // the router-level fallback below.
            call_route(fb, req).await
        } else if let Some(fb) = router_fallback {
            // Route exists but this method has no handler, and a custom fallback
            // was configured for that case via `Router::method_not_allowed_fallback`.
            call_route(fb, req).await
        } else {
            // Route exists but this method has no handler → 405 with Allow header.
            let allow = self.allow_header();
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(hyper::header::ALLOW, &allow)
                .body(Body::full(Bytes::from_static(b"Method Not Allowed")))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
    }
}
