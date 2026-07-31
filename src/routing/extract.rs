//! Type-safe request extractors.

/// WebSocket upgrade extractor and connection types (`WebSocketUpgrade`,
/// `WebSocket`, `Message`, ...) — re-exported here at the same path Axum uses
/// (`axum::extract::ws`), so `use tachyon_web::extract::ws::*;` matches
/// `use axum::extract::ws::*;` verbatim. See [`crate::ws`] for the full docs.
/// Requires the `ws` feature.
#[cfg(feature = "ws")]
pub use crate::ws;
/// Flattened re-export matching `axum::extract::WebSocketUpgrade`.
#[cfg(feature = "ws")]
pub use crate::ws::WebSocketUpgrade;

use crate::http::error::Error;
use crate::http::response::Body;
use bytes::Bytes;

#[cfg(feature = "cookies")]
use cookie::{Cookie, CookieJar};
use hyper::header::HeaderMap;
use hyper::{Method, StatusCode, Uri};
use serde::de::DeserializeOwned;
use std::convert::Infallible;
use std::future::Future;

/// Trait for extracting data from request parts (metadata).
pub trait FromRequestParts<S>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse + Send + 'static;

    /// Extract this type from the request parts and state.
    ///
    /// # Errors
    ///
    /// Returns a rejection if the extraction from the request parts fails.
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection>;
}

/// Trait for extracting data from a request (possibly consuming the body).
///
/// This is `async` so extractors can await the body being streamed in — the
/// request body is not necessarily fully buffered before your handler runs (see
/// [`crate::routing::extract::BodyStream`]). Extractors that only need the parts
/// (headers, method, URI, state) should implement [`FromRequestParts`] instead,
/// which stays synchronous and is cheaper to call.
pub trait FromRequest<S: Sync>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse + Send + 'static;

    /// Extract this type from the request and state.
    ///
    /// # Errors
    ///
    /// Returns a rejection if the extraction from the request body/parts fails.
    fn from_request(
        req: hyper::Request<Body>,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

/// The maximum request-body size assumed by body-buffering extractors
/// (`Bytes`, `String`, `Json`, `Form`) when no [`MaxBodySize`] extension is
/// present on the request — e.g. when calling [`crate::routing::CompiledRouter::handle_request`]
/// directly rather than through [`crate::server::Server`], which always sets it
/// from `Server::max_body_size`.
///
/// 2 MiB, matching Axum's `DefaultBodyLimit` default exactly (Axum: "for
/// security reasons, `Bytes` will, by default, not accept bodies larger than
/// 2MB"). Override per-deployment via [`crate::server::Server::max_body_size`].
pub(crate) const DEFAULT_MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Internal: the configured maximum request-body size, threaded through request
/// extensions (by the connection layer) so body-buffering extractors can enforce
/// it without needing direct access to the `Server` that's handling the request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MaxBodySize(pub usize);

pub(crate) fn max_body_size(extensions: &hyper::http::Extensions) -> usize {
    extensions
        .get::<MaxBodySize>()
        .map_or(DEFAULT_MAX_BODY_SIZE, |m| m.0)
}

/// Overrides the request-body size limit enforced by the `Bytes`/`String`/
/// `Json`/`Form` extractors, for a specific set of routes. Mirrors
/// `axum::extract::DefaultBodyLimit`.
///
/// # Applying it
///
/// Axum applies this as a `tower::Layer`: `.layer(DefaultBodyLimit::max(n))`.
/// Tachyon's body-size check is a plain extension read rather than a
/// byte-buffering Tower layer (buffering happens lazily, only when an
/// extractor that needs the body actually runs) — bridging this through
/// `.layer()` would buffer the body under the *old* limit before the layer
/// ever got a chance to install the new one, silently defeating the override.
/// Apply it the native way instead, via [`DefaultBodyLimit::into_middleware`]
/// and [`crate::routing::Router::hoop`]/[`crate::routing::MethodRouter::hoop`]:
///
/// ```rust,no_run
/// use tachyon_web::extract::DefaultBodyLimit;
/// use tachyon_web::{Router, get};
///
/// async fn upload() -> &'static str { "ok" }
///
/// let _app: Router<()> = Router::new()
///     .route("/upload", get(upload))
///     .hoop(DefaultBodyLimit::max(50 * 1024 * 1024).into_middleware());
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DefaultBodyLimit {
    /// `None` means disabled (`usize::MAX`).
    limit: Option<usize>,
}

impl DefaultBodyLimit {
    /// Sets the maximum accepted request-body size, in bytes, for the routes
    /// this is applied to.
    #[must_use]
    pub const fn max(limit: usize) -> Self {
        Self { limit: Some(limit) }
    }

    /// Disables the body-size limit entirely for the routes this is applied
    /// to. Matches `axum::extract::DefaultBodyLimit::disable`.
    #[must_use]
    pub const fn disable() -> Self {
        Self { limit: None }
    }

    /// Turns this into native middleware, for use with `.hoop()`/`.hoop_at()`.
    pub fn into_middleware<S>(
        self,
    ) -> impl Fn(hyper::Request<Body>, crate::routing::middleware::Next<S>) -> BoxedResponseFuture
    + Clone
    + Send
    + Sync
    + 'static
    where
        S: Send + Sync + 'static,
    {
        let limit = self.limit.unwrap_or(usize::MAX);
        move |mut req: hyper::Request<Body>, next: crate::routing::middleware::Next<S>| {
            let _ = req.extensions_mut().insert(MaxBodySize(limit));
            Box::pin(next.run(req)) as BoxedResponseFuture
        }
    }
}

/// A boxed future resolving to an HTTP response, used by
/// [`DefaultBodyLimit::into_middleware`]'s returned closure.
type BoxedResponseFuture = std::pin::Pin<Box<dyn Future<Output = hyper::Response<Body>> + Send>>;

/// Helper trait to obtain sub-state from app state.
pub trait FromRef<S> {
    /// Extract a reference/clone from the parent state.
    fn from_ref(state: &S) -> Self;
}

impl<T: Clone> FromRef<T> for T {
    fn from_ref(state: &T) -> Self {
        state.clone()
    }
}

/// Extractor for application state.
#[derive(Debug, Clone, Copy)]
pub struct State<T>(pub T);

impl<S, T> FromRequestParts<S> for State<T>
where
    T: FromRef<S> + Send + Sync + 'static,
{
    type Rejection = Infallible;

    fn from_request_parts(
        _parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(T::from_ref(state)))
    }
}

impl<S, T> FromRequest<S> for State<T>
where
    S: Sync,
    T: FromRef<S> + Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, _) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

/// Extractor for path parameters.
#[cfg(any(feature = "query", feature = "form"))]
#[derive(Debug, Clone)]
struct QueryIter<'de> {
    input: &'de str,
}

struct CoercingCowDeserializer<'de> {
    val: std::borrow::Cow<'de, str>,
}

impl<'de> serde::de::Deserializer<'de> for CoercingCowDeserializer<'de> {
    type Error = serde::de::value::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        match self.val {
            std::borrow::Cow::Borrowed(s) => visitor.visit_borrowed_str(s),
            std::borrow::Cow::Owned(s) => visitor.visit_string(s),
        }
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        match self.val {
            std::borrow::Cow::Borrowed(s) => visitor.visit_borrowed_str(s),
            std::borrow::Cow::Owned(s) => visitor.visit_string(s),
        }
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<u8>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_u8(n)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<u16>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_u16(n)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<u32>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_u32(n)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<u64>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_u64(n)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<i8>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_i8(n)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<i16>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_i16(n)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<i32>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_i32(n)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<i64>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_i64(n)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<f32>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_f32(n)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let n = self
            .val
            .parse::<f64>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        visitor.visit_f64(n)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let b = match self.val.as_ref() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => self
                .val
                .parse::<bool>()
                .map_err(|e| serde::de::Error::custom(e.to_string()))?,
        };
        visitor.visit_bool(b)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_some(self)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        use serde::de::IntoDeserializer;
        visitor.visit_enum(self.val.into_deserializer())
    }

    serde::forward_to_deserialize_any! {
        char bytes byte_buf unit unit_struct newtype_struct
        seq tuple tuple_struct map struct identifier ignored_any
    }
}

impl<'de> serde::de::IntoDeserializer<'de, serde::de::value::Error>
    for CoercingCowDeserializer<'de>
{
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

#[cfg(any(feature = "query", feature = "form"))]
impl<'de> Iterator for QueryIter<'de> {
    type Item = (std::borrow::Cow<'de, str>, CoercingCowDeserializer<'de>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            return None;
        }

        let bytes = self.input.as_bytes();
        let len = bytes.len();
        let end = bytes.iter().position(|&b| b == b'&').unwrap_or(len);
        let pair_str = &self.input[..end];

        if end < len {
            self.input = &self.input[end + 1..];
        } else {
            self.input = "";
        }

        if pair_str.is_empty() {
            return self.next();
        }

        let pair_bytes = pair_str.as_bytes();
        let (key_raw, val_raw) = pair_bytes
            .iter()
            .position(|&b| b == b'=')
            .map_or((pair_str, ""), |eq_idx| {
                (&pair_str[..eq_idx], &pair_str[eq_idx + 1..])
            });

        let key = decode_query_param(key_raw);
        let val = decode_query_param(val_raw);
        Some((key, CoercingCowDeserializer { val }))
    }
}

#[cfg(any(feature = "query", feature = "form"))]
fn decode_query_param(s: &str) -> std::borrow::Cow<'_, str> {
    let bytes = s.as_bytes();
    if !bytes.iter().any(|&b| b == b'%' || b == b'+') {
        return std::borrow::Cow::Borrowed(s);
    }

    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    && let Ok(val) = u8::from_str_radix(hex, 16)
                {
                    decoded.push(val);
                    i += 3;
                    continue;
                }
                decoded.push(b'%');
                i += 1;
            }
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            b => {
                decoded.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(decoded)
        .map_or_else(|_| std::borrow::Cow::Borrowed(s), std::borrow::Cow::Owned)
}

/// Extractor for URI path parameters.
///
/// Supports three shapes, matching Axum:
/// - A single scalar: `Path<u32>` on a route with exactly one param.
/// - A tuple: `Path<(String, u32)>`, deserialized positionally in route order.
/// - A struct/map: `Path<MyStruct>`, deserialized by param name (the common case).
///
/// Routes with no path parameters (e.g. `/health`) never populate a params
/// list, so `Path<()>` or any other zero-field extractor deserializes
/// successfully against an empty parameter set on those routes.
#[derive(Debug, Clone)]
pub struct Path<T>(pub T);

/// Internal path parameters container stored in request extensions.
#[derive(Debug, Clone)]
pub struct PathParams(pub Vec<(std::sync::Arc<str>, String)>);

/// A `serde::Deserializer` over route path parameters that supports scalar,
/// tuple, and map/struct deserialization targets, mirroring Axum's `Path`
/// extractor semantics.
struct PathDeserializer<'de> {
    params: &'de [(std::sync::Arc<str>, String)],
}

impl<'de> PathDeserializer<'de> {
    fn single_value(&self) -> Result<&'de str, serde::de::value::Error> {
        match self.params {
            [(_, v)] => Ok(v.as_str()),
            _ => Err(serde::de::Error::custom(format!(
                "wrong number of path parameters: expected 1, got {}",
                self.params.len()
            ))),
        }
    }

    const fn value_deserializer(val: &'de str) -> CoercingCowDeserializer<'de> {
        CoercingCowDeserializer {
            val: std::borrow::Cow::Borrowed(val),
        }
    }

    fn map_deserializer(
        &self,
    ) -> serde::de::value::MapDeserializer<
        'de,
        impl Iterator<Item = (std::borrow::Cow<'de, str>, CoercingCowDeserializer<'de>)>,
        serde::de::value::Error,
    > {
        serde::de::value::MapDeserializer::new(self.params.iter().map(|(k, v)| {
            (
                std::borrow::Cow::Borrowed(k.as_ref()),
                CoercingCowDeserializer {
                    val: std::borrow::Cow::Borrowed(v.as_str()),
                },
            )
        }))
    }
}

struct PathParamsSeqAccess<'de> {
    iter: std::slice::Iter<'de, (std::sync::Arc<str>, String)>,
}

impl<'de> serde::de::SeqAccess<'de> for PathParamsSeqAccess<'de> {
    type Error = serde::de::value::Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        match self.iter.next() {
            Some((_, v)) => seed
                .deserialize(CoercingCowDeserializer {
                    val: std::borrow::Cow::Borrowed(v.as_str()),
                })
                .map(Some),
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

macro_rules! path_deserialize_scalar {
    ($($method:ident),* $(,)?) => {
        $(
            fn $method<V>(self, visitor: V) -> Result<V::Value, Self::Error>
            where
                V: serde::de::Visitor<'de>,
            {
                let val = self.single_value()?;
                PathDeserializer::value_deserializer(val).$method(visitor)
            }
        )*
    };
}

impl<'de> serde::de::Deserializer<'de> for PathDeserializer<'de> {
    type Error = serde::de::value::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        // Single-param routes are ambiguous between "scalar" and "1-field struct" at
        // this point; defer to visit_map, which handles both since serde's derived
        // struct visitors accept single-entry maps and scalar newtypes forward here too.
        visitor.visit_map(self.map_deserializer())
    }

    path_deserialize_scalar!(
        deserialize_bool,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
    );

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_seq(PathParamsSeqAccess {
            iter: self.params.iter(),
        })
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        if self.params.len() != len {
            return Err(serde::de::Error::custom(format!(
                "wrong number of path parameters: expected {len}, got {}",
                self.params.len()
            )));
        }
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_map(self.map_deserializer())
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        use serde::de::IntoDeserializer;
        let val = self.single_value()?;
        visitor.visit_enum(val.into_deserializer())
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

impl<S, T> FromRequestParts<S> for Path<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Routes with no path parameters never insert a `PathParams`
        // extension (see `CompiledRouter::handle_request`'s parameterless
        // fast path), so a missing extension means "zero params" rather than
        // an error — extractors like `Path<()>` must still succeed on those
        // routes instead of getting a spurious 500.
        let params = parts
            .extensions
            .get::<PathParams>()
            .map_or(&[][..], |p| p.0.as_slice());

        T::deserialize(PathDeserializer { params })
            .map(Path)
            .map_err(|e: serde::de::value::Error| Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: format!("Failed to deserialize path parameters: {e}"),
            })
    }
}

impl<S, T> FromRequest<S> for Path<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, _) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

/// Extractor for query parameters. Requires the `query` feature.
#[cfg(feature = "query")]
#[derive(Debug, Clone)]
pub struct Query<T>(pub T);

#[cfg(feature = "query")]
impl<S, T> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let query_str = parts.uri.query().unwrap_or("");
        let iter = QueryIter { input: query_str };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        T::deserialize(map_de)
            .map(Query)
            .map_err(|e: serde::de::value::Error| Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: format!("Failed to deserialize query parameters: {e}"),
            })
    }
}

#[cfg(feature = "query")]
impl<S, T> FromRequest<S> for Query<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, _) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

/// Extracts the raw, un-deserialized query string (`None` if the request has
/// none), matching `axum::extract::RawQuery`. Infallible — unlike [`Query`],
/// this never rejects, since it does no parsing at all.
#[derive(Debug, Clone)]
pub struct RawQuery(pub Option<String>);

impl<S> FromRequestParts<S> for RawQuery {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.uri.query().map(str::to_string)))
    }
}

/// Returns `true` if `content_type` denotes a JSON media type, matching Axum's check:
/// the type must be `application` and the subtype must be `json` or end in `+json`
/// (e.g. `application/json`, `application/json; charset=utf-8`, `application/vnd.api+json`).
#[cfg(feature = "json")]
fn is_json_content_type(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or("").trim();
    let Some((ty, subtype)) = essence.split_once('/') else {
        return false;
    };
    if !ty.eq_ignore_ascii_case("application") {
        return false;
    }
    subtype.eq_ignore_ascii_case("json") || subtype.to_ascii_lowercase().ends_with("+json")
}

/// Extractor for JSON payloads. Requires the `json` feature.
#[cfg(feature = "json")]
#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

#[cfg(feature = "json")]
impl<S, T> FromRequest<S> for Json<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        // Validate Content-Type: must be a JSON media type (`application/json`, optionally
        // with parameters, or any `application/*+json` vendor/suffix type).
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_json_content_type(ct) {
            return Err(Error::Rejection {
                status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
                message: format!("Expected Content-Type: application/json, got: '{ct}'"),
            });
        }
        let limit = max_body_size(req.extensions());
        let body = req.into_body().collect_bytes(limit).await?;
        serde_json::from_slice::<T>(&body).map(Json).map_err(|e| {
            // Matches Axum's `JsonRejection`: malformed JSON (unbalanced braces,
            // trailing commas, invalid escapes, truncated input, ...) is a client
            // syntax error (`400`), while well-formed JSON that doesn't match the
            // target type's shape (wrong field types, missing required fields) is
            // `422` — the payload was understood but semantically rejected.
            let status = match e.classify() {
                serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                    StatusCode::BAD_REQUEST
                }
                serde_json::error::Category::Data | serde_json::error::Category::Io => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
            };
            Error::Rejection {
                status,
                message: format!("Failed to deserialize JSON payload: {e}"),
            }
        })
    }
}

impl<S> FromRequestParts<S> for HeaderMap {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.headers.clone())
    }
}

impl<S> FromRequestParts<S> for Method {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.method.clone())
    }
}

impl<S> FromRequestParts<S> for Uri {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.uri.clone())
    }
}

impl<S: Sync> FromRequest<S> for Bytes {
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        req.into_body().collect_bytes(limit).await
    }
}

impl<S: Sync> FromRequest<S> for String {
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        let body = req.into_body().collect_bytes(limit).await?;
        Self::from_utf8(body.to_vec()).map_err(|e| Error::Rejection {
            status: StatusCode::BAD_REQUEST,
            message: format!("Request body is not valid UTF-8: {e}"),
        })
    }
}

/// Extractor for form-urlencoded payloads. Requires the `form` feature.
#[cfg(feature = "form")]
#[derive(Debug, Clone)]
pub struct Form<T>(pub T);

#[cfg(feature = "form")]
impl<S, T> FromRequestParts<S> for Form<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Error;

    /// Deserializes from the URL query string — matches Axum's `Form` extractor,
    /// which reads `GET`/`HEAD` requests from the query string rather than the
    /// (typically absent) body. See [`FromRequest`] for the `POST`/body path.
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let query_str = parts.uri.query().unwrap_or("");
        let iter = QueryIter { input: query_str };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        T::deserialize(map_de)
            .map(Form)
            .map_err(|e: serde::de::value::Error| Error::Rejection {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: format!("Failed to deserialize form payload: {e}"),
            })
    }
}

#[cfg(feature = "form")]
impl<S, T> FromRequest<S> for Form<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        // Matches Axum: `GET`/`HEAD` requests are read from the query string (no
        // body/Content-Type expected — this is the common "search form" pattern);
        // every other method reads and deserializes the request body.
        if req.method() == hyper::Method::GET || req.method() == hyper::Method::HEAD {
            let (mut parts, _body) = req.into_parts();
            return Self::from_request_parts(&mut parts, state);
        }

        // Validate Content-Type: must be application/x-www-form-urlencoded.
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let essence = ct.split(';').next().unwrap_or("").trim();
        if !essence.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            return Err(Error::Rejection {
                status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
                message: format!(
                    "Expected Content-Type: application/x-www-form-urlencoded, got: '{ct}'"
                ),
            });
        }
        let limit = max_body_size(req.extensions());
        let body = req.into_body().collect_bytes(limit).await?;
        let body_str = std::str::from_utf8(&body).map_err(|_| Error::Rejection {
            status: StatusCode::BAD_REQUEST,
            message: "Form body is not valid UTF-8".to_string(),
        })?;
        let iter = QueryIter { input: body_str };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        T::deserialize(map_de)
            .map(Form)
            .map_err(|e: serde::de::value::Error| Error::Rejection {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: format!("Failed to deserialize form payload: {e}"),
            })
    }
}

/// Extractor for request-local extensions.
#[derive(Debug, Clone, Copy)]
pub struct Extension<T>(pub T);

impl<S, T> FromRequestParts<S> for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<T>()
            .cloned()
            .map(Extension)
            .ok_or_else(|| Error::Rejection {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: format!("Missing extension: {}", std::any::type_name::<T>()),
            })
    }
}

impl<S, T> FromRequest<S> for Extension<T>
where
    S: Sync,
    T: Clone + Send + Sync + 'static,
{
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, _) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

/// Extractor for reading and managing Cookies.
#[cfg(feature = "cookies")]
#[derive(Debug, Clone)]
pub struct Cookies {
    /// The internal cookie jar
    pub jar: CookieJar,
}

#[cfg(feature = "cookies")]
impl Cookies {
    /// Create a new empty Cookies jar.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jar: CookieJar::new(),
        }
    }

    /// Get a cookie by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Cookie<'static>> {
        self.jar.get(name)
    }

    /// Adds `cookie` to the jar, returning `Self` for chaining — the request handler pattern is
    /// `async fn handler(jar: Cookies) -> (Cookies, T) { (jar.add(...), body) }`, matching
    /// `axum-extra`'s `CookieJar`. Returning the jar from a handler (anywhere in an
    /// [`IntoResponseParts`](crate::http::response::IntoResponseParts) tuple) is what actually
    /// applies it — only the cookies that changed (added or removed) are serialized into
    /// `Set-Cookie` headers, via [`cookie::CookieJar::delta`], not the whole jar.
    // Named to match `axum-extra`'s `CookieJar::add` exactly (the point of this method), not
    // `std::ops::Add` — the two aren't actually confusable in practice (different arity/purpose).
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn add(mut self, cookie: Cookie<'static>) -> Self {
        self.jar.add(cookie);
        self
    }

    /// Removes `cookie` from the jar (queuing a `Set-Cookie` that expires it immediately once
    /// this jar is returned from a handler), returning `Self` for chaining — see [`add`](Self::add).
    #[must_use]
    pub fn remove(mut self, cookie: Cookie<'static>) -> Self {
        self.jar.remove(cookie);
        self
    }
}

#[cfg(feature = "cookies")]
impl Default for Cookies {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "cookies")]
impl<S> FromRequestParts<S> for Cookies {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let mut jar = CookieJar::new();
        if let Some(cookie_header) = parts.headers.get(hyper::header::COOKIE)
            && let Ok(cookie_str) = cookie_header.to_str()
        {
            for c in Cookie::split_parse_encoded(cookie_str).flatten() {
                jar.add_original(c.into_owned());
            }
        }
        Ok(Self { jar })
    }
}

impl<S: Sync> FromRequest<S> for hyper::Request<Bytes> {
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        let (parts, body) = req.into_parts();
        let bytes = body.collect_bytes(limit).await?;
        Ok(Self::from_parts(parts, bytes))
    }
}

/// Extractor providing direct, un-buffered access to the request body as a
/// stream — for handlers that want to process large uploads incrementally
/// instead of buffering the whole body into memory first.
///
/// Unlike `Bytes`, `String`, `Json`, and `Form`, this never allocates a single
/// contiguous buffer for the body and is not subject to [`crate::server::Server::max_body_size`]
/// — callers reading from the stream are responsible for enforcing their own limits.
#[derive(Debug)]
pub struct BodyStream(pub Body);

impl<S: Sync> FromRequest<S> for BodyStream {
    type Rejection = Infallible;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(req.into_body()))
    }
}

impl<S: Sync> FromRequest<S> for hyper::Request<Body> {
    type Rejection = Infallible;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(req)
    }
}

/// Extractor for host header or authority.
#[derive(Debug, Clone)]
pub struct Host(pub String);

impl<S> FromRequestParts<S> for Host {
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(host) = parts
            .headers
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
        {
            Ok(Self(host.to_string()))
        } else if let Some(host) = parts.uri.host() {
            Ok(Self(host.to_string()))
        } else {
            Err(Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: "Missing Host header or authority in URI".to_string(),
            })
        }
    }
}

/// Extractor for the original URI. Requires the `original-uri` feature.
#[cfg(feature = "original-uri")]
#[derive(Debug, Clone)]
pub struct OriginalUri(pub Uri);

#[cfg(feature = "original-uri")]
impl<S> FromRequestParts<S> for OriginalUri {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let uri = parts
            .extensions
            .get::<Self>()
            .map_or_else(|| parts.uri.clone(), |ou| ou.0.clone());
        Ok(Self(uri))
    }
}

/// Extractor for the matched route pattern (e.g. `/users/{id}`), as registered
/// via `Router::route`, rather than the literal request path (`/users/1`).
///
/// Matches `axum::extract::MatchedPath` — commonly used to label metrics/traces
/// by route template instead of by concrete path (which would otherwise create
/// one time series per distinct resource ID). Only available for requests that
/// matched a registered route; unmatched requests (404s) have no `MatchedPath`.
/// Requires the `matched-path` feature.
#[cfg(feature = "matched-path")]
#[derive(Debug, Clone)]
pub struct MatchedPath(pub(crate) std::sync::Arc<str>);

#[cfg(feature = "matched-path")]
impl MatchedPath {
    /// The matched route pattern, e.g. `/users/{id}`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "matched-path")]
impl<S> FromRequestParts<S> for MatchedPath {
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| Error::Rejection {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "No matched path found in request extensions".to_string(),
            })
    }
}

/// Extractor for network connection info.
#[derive(Debug, Clone, Copy)]
pub struct ConnectInfo<T>(pub T);

impl<S, T> FromRequestParts<S> for ConnectInfo<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| Error::Rejection {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: format!(
                    "Missing ConnectInfo<{}> extension",
                    std::any::type_name::<T>()
                ),
            })
    }
}

impl<S, T> FromRequest<S> for ConnectInfo<T>
where
    S: Sync,
    T: Clone + Send + Sync + 'static,
{
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, _) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

macro_rules! impl_from_request_via_parts {
    ($ty:ty) => {
        impl<S: Sync> FromRequest<S> for $ty {
            type Rejection = <Self as FromRequestParts<S>>::Rejection;

            async fn from_request(
                req: hyper::Request<Body>,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                let (mut parts, _) = req.into_parts();
                <Self as FromRequestParts<S>>::from_request_parts(&mut parts, state)
            }
        }
    };
}

impl_from_request_via_parts!(RawQuery);
impl_from_request_via_parts!(HeaderMap);
impl_from_request_via_parts!(Method);
impl_from_request_via_parts!(Uri);
#[cfg(feature = "cookies")]
impl_from_request_via_parts!(Cookies);
impl_from_request_via_parts!(Host);
#[cfg(feature = "original-uri")]
impl_from_request_via_parts!(OriginalUri);
#[cfg(feature = "matched-path")]
impl_from_request_via_parts!(MatchedPath);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hyper::http::Request;
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    #[allow(clippy::struct_excessive_bools)]
    struct BigCoerce {
        a: u16,
        b: u64,
        c: i8,
        d: i16,
        e: i32,
        f: i64,
        g: f32,
        h: f64,
        i: bool,
        j: bool,
        k: bool,
        l: bool,
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct BoolTest {
        val: bool,
    }

    #[derive(Deserialize, PartialEq, Debug)]
    enum Color {
        Red,
        Blue,
    }

    #[derive(Deserialize)]
    struct EnumTest {
        val: Color,
    }

    #[cfg(any(feature = "query", feature = "form"))]
    #[test]
    fn test_coercing_cow_deserializer() {
        let query_str = "a=12&b=34&c=5&d=6&e=7&f=8&g=1.2&h=3.4&i=true&j=1&k=false&l=0";
        let iter = QueryIter { input: query_str };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        let data = BigCoerce::deserialize(map_de).unwrap();
        assert_eq!(data.a, 12);
        assert_eq!(data.b, 34);
        assert_eq!(data.c, 5);
        assert_eq!(data.d, 6);
        assert_eq!(data.e, 7);
        assert_eq!(data.f, 8);
        assert!((data.g - 1.2).abs() < 0.001);
        assert!((data.h - 3.4).abs() < 0.001);
        assert!(data.i);
        assert!(data.j);
        assert!(!data.k);
        assert!(!data.l);

        // Test bool parse error
        let iter = QueryIter {
            input: "val=not_bool",
        };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        assert!(BoolTest::deserialize(map_de).is_err());

        // Test enum deserialization
        let iter = QueryIter { input: "val=Red" };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        let et = EnumTest::deserialize(map_de).unwrap();
        assert_eq!(et.val, Color::Red);
    }

    #[cfg(any(feature = "query", feature = "form"))]
    #[test]
    fn test_query_iter_edge_cases() {
        // Empty pair and key without value
        let query_str = "&&foo&&bar=baz";
        let mut iter = QueryIter { input: query_str };
        let first = iter.next().unwrap();
        assert_eq!(first.0, "foo");
        assert_eq!(first.1.val, "");
        let second = iter.next().unwrap();
        assert_eq!(second.0, "bar");
        assert_eq!(second.1.val, "baz");

        // Invalid percent decoding in query param
        let query_str2 = "foo=bar%xy&baz=%";
        let mut iter2 = QueryIter { input: query_str2 };
        let first2 = iter2.next().unwrap();
        assert_eq!(first2.0, "foo");
        assert_eq!(first2.1.val, "bar%xy");
        let second2 = iter2.next().unwrap();
        assert_eq!(second2.0, "baz");
        assert_eq!(second2.1.val, "%");
    }

    #[tokio::test]
    async fn test_extractors_direct() {
        let req = Request::builder()
            .method("POST")
            .uri("/path?q=1")
            .header("x-test", "hello")
            .body(Body::full(Bytes::from("body_bytes")))
            .unwrap();
        let (mut parts, body) = req.into_parts();

        // HeaderMap
        let headers = HeaderMap::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(headers.get("x-test").unwrap(), "hello");

        // Method
        let method = Method::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(method, "POST");

        // Uri
        let uri = Uri::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(uri.path(), "/path");

        // Bytes
        let req_bytes = Request::from_parts(parts.clone(), Body::full(Bytes::from("body_bytes")));
        let bytes = Bytes::from_request(req_bytes, &()).await.unwrap();
        assert_eq!(bytes.as_ref(), b"body_bytes");

        // Request<Bytes>
        let req_full = Request::from_parts(parts, body);
        let extracted_req = <Request<Bytes>>::from_request(req_full, &()).await.unwrap();
        assert_eq!(extracted_req.uri().path(), "/path");
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn test_cookies_remove() {
        use cookie::Cookie;
        let cookies = Cookies::new().add(Cookie::new("foo", "bar"));
        assert_eq!(cookies.get("foo").unwrap().value(), "bar");
        let cookies = cookies.remove(Cookie::new("foo", ""));
        assert!(cookies.get("foo").is_none());
    }

    #[test]
    fn test_host_missing() {
        let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
        let res = Host::from_request_parts(&mut parts, &());
        assert!(res.is_err());
    }

    #[test]
    fn test_connect_info_missing() {
        let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
        let res = ConnectInfo::<std::net::SocketAddr>::from_request_parts(&mut parts, &());
        assert!(res.is_err());
    }

    #[cfg(feature = "form")]
    #[tokio::test]
    async fn test_form_errors() {
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct FormPayload {
            foo: String,
        }

        // Invalid content type. Method must be POST (or any non-GET/HEAD) — otherwise
        // `Form::from_request` silently delegates to the query-string path instead of ever
        // reaching the Content-Type check below, which is exactly the bug this test used to
        // have (all three sub-cases here defaulted to GET and accidentally exercised the
        // wrong branch entirely; the `is_err()` assertions still passed, just for the wrong
        // reason — a missing required field via an empty query string).
        let req = Request::builder()
            .method("POST")
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Body::full(Bytes::from("foo=bar")))
            .unwrap();
        let res = Form::<FormPayload>::from_request(req, &()).await;
        assert!(res.is_err());

        // Invalid UTF-8 body.
        let utf8_req = Request::builder()
            .method("POST")
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::full(Bytes::from(vec![0xff, 0xff])))
            .unwrap();
        let utf8_result = Form::<FormPayload>::from_request(utf8_req, &()).await;
        assert!(utf8_result.is_err());

        // Invalid payload (missing required field).
        let payload_req = Request::builder()
            .method("POST")
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::full(Bytes::from("not_valid")))
            .unwrap();
        let payload_result = Form::<FormPayload>::from_request(payload_req, &()).await;
        assert!(payload_result.is_err());
    }

    #[cfg(feature = "form")]
    #[test]
    fn test_form_from_request_parts_deserialize_error() {
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct FormPayload {
            foo: String,
        }

        // The GET/HEAD "read from the query string" path (`FromRequestParts`), exercised
        // directly rather than via the `FromRequest::from_request` GET delegation, so it's
        // clear which branch is under test.
        let mut parts = Request::builder()
            .uri("/search?bar=baz")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let result = Form::<FormPayload>::from_request_parts(&mut parts, &());
        assert!(result.is_err());
    }

    #[cfg(feature = "form")]
    #[tokio::test]
    async fn test_form_get_request_reads_from_query_string() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct FormPayload {
            foo: String,
        }

        let req = Request::builder()
            .method("GET")
            .uri("/search?foo=bar")
            .body(Body::empty())
            .unwrap();
        let Form(payload) = Form::<FormPayload>::from_request(req, &()).await.unwrap();
        assert_eq!(
            payload,
            FormPayload {
                foo: "bar".to_string(),
            }
        );
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_query_deserialize_error() {
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct QueryPayload {
            foo: u32,
        }

        let mut parts = Request::builder()
            .uri("/?foo=not_a_number")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let result = Query::<QueryPayload>::from_request_parts(&mut parts, &());
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_query_present_and_absent() {
        let mut with_query = Request::builder()
            .uri("/path?a=1&b=2")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let RawQuery(q) = RawQuery::from_request_parts(&mut with_query, &()).unwrap();
        assert_eq!(q.as_deref(), Some("a=1&b=2"));

        let mut without_query = Request::builder()
            .uri("/path")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let RawQuery(q2) = RawQuery::from_request_parts(&mut without_query, &()).unwrap();
        assert!(q2.is_none());
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn test_cookies_default() {
        let cookies = Cookies::default();
        assert!(cookies.get("anything").is_none());
    }

    #[tokio::test]
    async fn test_body_stream_from_request() {
        let req = Request::builder()
            .body(Body::full(Bytes::from("stream me")))
            .unwrap();
        let BodyStream(body) = BodyStream::from_request(req, &()).await.unwrap();
        let collected = body.collect_bytes(1024).await.unwrap();
        assert_eq!(collected.as_ref(), b"stream me");
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_is_json_content_type_without_a_slash_is_rejected() {
        assert!(!is_json_content_type("not-a-media-type"));
    }

    // --- PathDeserializer coverage ---

    fn make_path_parts(params: Vec<(&str, &str)>) -> hyper::http::request::Parts {
        let mut parts = Request::builder().body(()).unwrap().into_parts().0;
        let path_params = PathParams(
            params
                .into_iter()
                .map(|(k, v)| (std::sync::Arc::from(k), v.to_string()))
                .collect(),
        );
        parts.extensions.insert(path_params);
        parts
    }

    #[test]
    fn test_path_tuple_success_and_length_mismatch() {
        let mut ok_parts = make_path_parts(vec![("id", "42"), ("name", "hello")]);
        let Path((id, name)) =
            Path::<(u32, String)>::from_request_parts(&mut ok_parts, &()).unwrap();
        assert_eq!(id, 42);
        assert_eq!(name, "hello");

        // Too many params for a 2-tuple.
        let mut too_many = make_path_parts(vec![("a", "1"), ("b", "2"), ("c", "3")]);
        assert!(Path::<(u32, String)>::from_request_parts(&mut too_many, &()).is_err());

        // Too few params for a 2-tuple.
        let mut too_few = make_path_parts(vec![("a", "1")]);
        assert!(Path::<(u32, String)>::from_request_parts(&mut too_few, &()).is_err());
    }

    #[test]
    fn test_path_vec_seq_target() {
        // `Vec<T>` reaches `deserialize_seq` directly (not via tuple delegation),
        // and its `Deserialize` impl calls `SeqAccess::size_hint` to preallocate.
        let mut parts = make_path_parts(vec![("a", "x"), ("b", "y"), ("c", "z")]);
        let Path(values) = Path::<Vec<String>>::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(
            values,
            vec!["x".to_string(), "y".to_string(), "z".to_string()]
        );
    }

    #[test]
    fn test_path_scalar_wrong_param_count() {
        // Zero params for a bare scalar target.
        let mut zero = make_path_parts(vec![]);
        assert!(Path::<u32>::from_request_parts(&mut zero, &()).is_err());

        // More than one param for a bare scalar target.
        let mut two = make_path_parts(vec![("a", "1"), ("b", "2")]);
        assert!(Path::<u32>::from_request_parts(&mut two, &()).is_err());

        // Exactly one param succeeds.
        let mut one = make_path_parts(vec![("id", "7")]);
        let Path(v) = Path::<u32>::from_request_parts(&mut one, &()).unwrap();
        assert_eq!(v, 7);
    }

    #[test]
    fn test_path_option_top_level_target() {
        // `Path<Option<T>>` makes `Option<T>` the *whole* deserialization target, so
        // `T::deserialize` dispatches straight to `PathDeserializer::deserialize_option`
        // (as opposed to a struct field being `Option<T>`, which is handled entirely by
        // `MapDeserializer`/`CoercingCowDeserializer` without ever calling back into
        // `PathDeserializer::deserialize_option`).
        let mut parts = make_path_parts(vec![("id", "9")]);
        let Path(v) = Path::<Option<u32>>::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(v, Some(9));
    }

    #[test]
    fn test_path_enum_target() {
        let mut parts = make_path_parts(vec![("color", "Red")]);
        let Path(c) = Path::<Color>::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(c, Color::Red);
    }

    #[test]
    fn test_path_unit_and_unit_struct_targets() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct UnitStruct;

        // `()` as the whole target reaches `deserialize_unit` and ignores any params.
        let mut parts = make_path_parts(vec![("a", "1"), ("b", "2")]);
        let Path(unit_val) = Path::<()>::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(unit_val, ());

        // A derived unit struct reaches `deserialize_unit_struct`.
        let mut empty_parts = make_path_parts(vec![]);
        let Path(u) = Path::<UnitStruct>::from_request_parts(&mut empty_parts, &()).unwrap();
        assert_eq!(u, UnitStruct);
    }

    #[test]
    fn test_path_newtype_struct_target() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Wrapper(u32);

        let mut parts = make_path_parts(vec![("id", "77")]);
        let Path(Wrapper(v)) = Path::<Wrapper>::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(v, 77);
    }

    #[test]
    fn test_path_ignored_any_top_level_target() {
        // `serde::de::IgnoredAny` is a real, public serde type whose `Deserialize` impl
        // calls `deserialize_ignored_any` directly on the top-level deserializer, so this
        // exercises `PathDeserializer::deserialize_ignored_any` through the public `Path<T>`
        // API without any artificial scaffolding.
        let mut parts = make_path_parts(vec![("a", "1"), ("b", "2")]);
        let result = Path::<serde::de::IgnoredAny>::from_request_parts(&mut parts, &());
        assert!(result.is_ok());
    }

    struct IdentifierVisitor;

    impl serde::de::Visitor<'_> for IdentifierVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string identifier")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.to_string())
        }
    }

    #[test]
    fn test_path_deserializer_identifier_direct() {
        // No public `Deserialize` target routes into `PathDeserializer::deserialize_identifier`
        // through `Path<T>`: struct/map field names are resolved by the key type inside
        // `MapDeserializer` (a `Cow<str>`/`StrDeserializer`), and enum variant names are
        // resolved via `val.into_deserializer()` in `deserialize_enum` above — neither ever
        // hands control back to `PathDeserializer` itself. So this calls the trait method
        // directly on the (module-private) `PathDeserializer` to exercise its forwarding
        // logic to `deserialize_str`.
        let params: Vec<(std::sync::Arc<str>, String)> =
            vec![(std::sync::Arc::from("k"), "myvalue".to_string())];
        let de = PathDeserializer { params: &params };
        let result =
            serde::de::Deserializer::deserialize_identifier(de, IdentifierVisitor).unwrap();
        assert_eq!(result, "myvalue");
    }
}
