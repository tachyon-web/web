//! Type-safe request extractors.

/// Per-extractor rejection types, matching `axum::extract::rejection`.
pub mod rejection;

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

/// Structured-field typed-header extractor, re-exported at the extractor path.
/// See [`crate::http::sfv`] for the data model and the `sfv_dictionary!` macro.
/// Requires the `sfv` feature.
#[cfg(feature = "sfv")]
pub use crate::http::sfv::StructuredHeader;

/// `multipart/form-data` extractor (`Multipart`, `Field`, `MultipartError`).
///
/// Matches `axum::extract::multipart`. Requires the `multipart` feature.
#[cfg(feature = "multipart")]
pub mod multipart;
/// Flattened re-export matching `axum::extract::Multipart`.
#[cfg(feature = "multipart")]
pub use multipart::Multipart;

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
///
/// `async fn`, matching `axum::extract::FromRequestParts` exactly — most built-in
/// impls here don't need to await anything and resolve immediately, but a user
/// extractor that needs to (e.g. a database round trip keyed off a header) can.
pub trait FromRequestParts<S: Sync>: Sized + Send {
    /// The rejection type returned if extraction fails.
    type Rejection: crate::http::response::IntoResponse;

    /// Extract this type from the request parts and state.
    ///
    /// # Errors
    ///
    /// Returns a rejection if the extraction from the request parts fails.
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
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
    type Rejection: crate::http::response::IntoResponse;

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
/// `Json`/`Form` extractors, for a specific set of routes.
///
/// Mirrors `axum::extract::DefaultBodyLimit`, including how it's applied —
/// as a real `tower::Layer`:
///
/// ```rust,no_run
/// use tachyon_web::extract::DefaultBodyLimit;
/// use tachyon_web::{Router, get};
///
/// async fn upload() -> &'static str { "ok" }
///
/// let _app: Router<()> = Router::new()
///     .route("/upload", get(upload))
///     .layer(DefaultBodyLimit::max(50 * 1024 * 1024));
/// ```
///
/// Unlike a foreign Tower body-limit layer, this never buffers the body
/// itself — it only sets an extension the `Bytes`/`String`/`Json`/`Form`
/// extractors read lazily, when (and if) they actually buffer the body
/// themselves — so layering order relative to *this* layer doesn't matter.
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
}

impl tower::Layer<crate::routing::Route> for DefaultBodyLimit {
    type Service = DefaultBodyLimitService;

    fn layer(&self, inner: crate::routing::Route) -> Self::Service {
        DefaultBodyLimitService {
            limit: self.limit.unwrap_or(usize::MAX),
            inner,
        }
    }
}

/// The `tower::Service` produced by [`DefaultBodyLimit`]'s `tower::Layer` impl.
#[derive(Debug, Clone)]
pub struct DefaultBodyLimitService {
    limit: usize,
    inner: crate::routing::Route,
}

impl tower::Service<hyper::Request<Body>> for DefaultBodyLimitService {
    type Response = hyper::Response<Body>;
    type Error = Infallible;
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<hyper::Response<Body>, Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: hyper::Request<Body>) -> Self::Future {
        let _ = req.extensions_mut().insert(MaxBodySize(self.limit));
        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}

/// Derives sub-state from the app state, matching `axum::extract::FromRef`.
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

impl<S: Sync, T> FromRequestParts<S> for State<T>
where
    T: FromRef<S> + Send + Sync + 'static,
{
    type Rejection = Infallible;

    fn from_request_parts(
        _parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(T::from_ref(state))))
    }
}

/// Extractor for path parameters.
#[cfg(any(feature = "query", feature = "form"))]
#[derive(Debug, Clone)]
struct QueryIter<'de> {
    input: &'de str,
}

#[cfg(any(feature = "query", feature = "form"))]
struct CoercingCowDeserializer<'de> {
    val: std::borrow::Cow<'de, str>,
}

/// Query/form/path values arrive as strings, so every numeric target is deserialized by
/// `FromStr`-parsing the raw value. Generates one `deserialize_*` method per primitive,
/// all identical apart from the type parsed and the visitor method called.
#[cfg(any(feature = "query", feature = "form"))]
macro_rules! coerce_via_from_str {
    ($( $method:ident => $visit:ident : $ty:ty ),* $(,)?) => {
        $(
            fn $method<V>(self, visitor: V) -> Result<V::Value, Self::Error>
            where
                V: serde::de::Visitor<'de>,
            {
                let n = self
                    .val
                    .parse::<$ty>()
                    .map_err(|e| serde::de::Error::custom(e.to_string()))?;
                visitor.$visit(n)
            }
        )*
    };
}

#[cfg(any(feature = "query", feature = "form"))]
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

    coerce_via_from_str! {
        deserialize_u8 => visit_u8: u8,
        deserialize_u16 => visit_u16: u16,
        deserialize_u32 => visit_u32: u32,
        deserialize_u64 => visit_u64: u64,
        deserialize_i8 => visit_i8: i8,
        deserialize_i16 => visit_i16: i16,
        deserialize_i32 => visit_i32: i32,
        deserialize_i64 => visit_i64: i64,
        deserialize_f32 => visit_f32: f32,
        deserialize_f64 => visit_f64: f64,
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

#[cfg(any(feature = "query", feature = "form"))]
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
        let pair_str = self.input.get(..end).unwrap_or(self.input);

        if end < len {
            self.input = self.input.get(end.saturating_add(1)..).unwrap_or_default();
        } else {
            self.input = "";
        }

        if pair_str.is_empty() {
            return self.next();
        }

        let pair_bytes = pair_str.as_bytes();
        let (key_raw, val_raw) =
            pair_bytes
                .iter()
                .position(|&b| b == b'=')
                .map_or((pair_str, ""), |eq_idx| {
                    (
                        pair_str.get(..eq_idx).unwrap_or(pair_str),
                        pair_str.get(eq_idx.saturating_add(1)..).unwrap_or(""),
                    )
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
    while let Some(&b) = bytes.get(i) {
        match b {
            b'%' => {
                let hex_bytes = bytes.get(i.saturating_add(1)..i.saturating_add(3));
                if let Some(hex_bytes) = hex_bytes
                    && let Ok(hex) = std::str::from_utf8(hex_bytes)
                    && let Ok(val) = u8::from_str_radix(hex, 16)
                {
                    decoded.push(val);
                    i = i.saturating_add(3);
                    continue;
                }
                decoded.push(b'%');
                i = i.saturating_add(1);
            }
            b'+' => {
                decoded.push(b' ');
                i = i.saturating_add(1);
            }
            other => {
                decoded.push(other);
                i = i.saturating_add(1);
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

/// The captured path parameters for one request, in route-declaration order.
///
/// Inline up to four, which covers essentially every real route, so a parameterised match
/// costs no separate allocation beyond the extension itself.
pub type PathParamsVec = smallvec::SmallVec<[(std::sync::Arc<str>, String); 4]>;

/// Internal path parameters container stored in request extensions.
#[derive(Debug, Clone)]
pub struct PathParams(pub PathParamsVec);

/// A `serde::Deserializer` over route path parameters that supports scalar,
/// tuple, and map/struct deserialization targets, mirroring Axum's `Path`
/// extractor semantics — including its structured [`rejection::ErrorKind`]
/// (which key/index a parse failure happened at, not just a message string).
struct PathDeserializer<'de> {
    params: &'de [(std::sync::Arc<str>, String)],
}

macro_rules! path_unsupported_type {
    ($trait_fn:ident) => {
        fn $trait_fn<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            Err(rejection::PathDeserializationError::unsupported_type(
                std::any::type_name::<V::Value>(),
            ))
        }
    };
}

macro_rules! path_parse_single_value {
    ($trait_fn:ident, $visit_fn:ident, $ty:literal) => {
        fn $trait_fn<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            let [(_, raw)] = self.params else {
                return Err(
                    rejection::PathDeserializationError::wrong_number_of_parameters(
                        self.params.len(),
                    )
                    .expected(1),
                );
            };
            let value = raw.parse().map_err(|_| {
                rejection::PathDeserializationError::new(rejection::ErrorKind::ParseError {
                    value: raw.clone(),
                    expected_type: $ty,
                })
            })?;
            visitor.$visit_fn(value)
        }
    };
}

impl<'de> serde::de::Deserializer<'de> for PathDeserializer<'de> {
    type Error = rejection::PathDeserializationError;

    // Unlike axum's own top-level deserializer (which rejects these outright),
    // this crate has always supported a bare `Path<Option<T>>`/`Path<IgnoredAny>`
    // target and identifier forwarding — a superset of axum's behavior with no
    // downside, so it's kept rather than narrowed down to match axum's stricter
    // (and, for these four methods, purely more restrictive) real deserializer.
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let [(_, value)] = self.params else {
            return Err(
                rejection::PathDeserializationError::wrong_number_of_parameters(self.params.len())
                    .expected(1),
            );
        };
        visitor.visit_borrowed_bytes(value.as_bytes())
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_some(self)
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

    path_parse_single_value!(deserialize_bool, visit_bool, "bool");
    path_parse_single_value!(deserialize_i8, visit_i8, "i8");
    path_parse_single_value!(deserialize_i16, visit_i16, "i16");
    path_parse_single_value!(deserialize_i32, visit_i32, "i32");
    path_parse_single_value!(deserialize_i64, visit_i64, "i64");
    path_parse_single_value!(deserialize_i128, visit_i128, "i128");
    path_parse_single_value!(deserialize_u8, visit_u8, "u8");
    path_parse_single_value!(deserialize_u16, visit_u16, "u16");
    path_parse_single_value!(deserialize_u32, visit_u32, "u32");
    path_parse_single_value!(deserialize_u64, visit_u64, "u64");
    path_parse_single_value!(deserialize_u128, visit_u128, "u128");
    path_parse_single_value!(deserialize_f32, visit_f32, "f32");
    path_parse_single_value!(deserialize_f64, visit_f64, "f64");
    path_parse_single_value!(deserialize_string, visit_string, "String");
    path_parse_single_value!(deserialize_byte_buf, visit_string, "String");
    path_parse_single_value!(deserialize_char, visit_char, "char");

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let [(key, value)] = self.params else {
            return Err(
                rejection::PathDeserializationError::wrong_number_of_parameters(self.params.len())
                    .expected(1),
            );
        };
        visitor.visit_borrowed_str(value.as_str()).map_err(
            |e: rejection::PathDeserializationError| {
                if let rejection::ErrorKind::Message(message) = &e.kind {
                    rejection::PathDeserializationError::new(
                        rejection::ErrorKind::DeserializeError {
                            key: key.to_string(),
                            value: value.clone(),
                            message: message.clone(),
                        },
                    )
                } else {
                    e
                }
            },
        )
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
        visitor.visit_seq(PathSeqAccess {
            params: self.params,
            idx: 0,
        })
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        if self.params.len() != len {
            return Err(
                rejection::PathDeserializationError::wrong_number_of_parameters(self.params.len())
                    .expected(len),
            );
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
        visitor.visit_map(PathMapAccess {
            params: self.params,
            key: None,
            value: None,
        })
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
        let [(_, value)] = self.params else {
            return Err(
                rejection::PathDeserializationError::wrong_number_of_parameters(self.params.len())
                    .expected(1),
            );
        };
        visitor.visit_enum(PathEnumAccess {
            value: value.as_str(),
        })
    }
}

/// Tracks whether a value came from a named struct field or a positional
/// tuple/sequence slot, so a parse failure can be attributed precisely
/// (`ErrorKind::ParseErrorAtKey` vs `ErrorKind::ParseErrorAtIndex`).
#[derive(Clone, Copy)]
enum PathKeyOrIdx<'de> {
    Key(&'de str),
    Idx(usize),
}

struct PathMapAccess<'de> {
    params: &'de [(std::sync::Arc<str>, String)],
    key: Option<&'de str>,
    value: Option<&'de str>,
}

impl<'de> serde::de::MapAccess<'de> for PathMapAccess<'de> {
    type Error = rejection::PathDeserializationError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        match self.params.split_first() {
            Some(((key, value), tail)) => {
                self.key = Some(key.as_ref());
                self.value = Some(value.as_str());
                self.params = tail;
                seed.deserialize(PathKeyDeserializer { key: key.as_ref() })
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        match self.value.take() {
            Some(value) => seed.deserialize(PathValueDeserializer {
                key_or_idx: self.key.take().map(PathKeyOrIdx::Key),
                value,
            }),
            None => Err(serde::de::Error::custom("value is missing")),
        }
    }
}

struct PathKeyDeserializer<'de> {
    key: &'de str,
}

macro_rules! path_parse_key {
    ($trait_fn:ident) => {
        fn $trait_fn<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_str(self.key)
        }
    };
}

impl<'de> serde::de::Deserializer<'de> for PathKeyDeserializer<'de> {
    type Error = rejection::PathDeserializationError;

    path_parse_key!(deserialize_identifier);
    path_parse_key!(deserialize_str);
    path_parse_key!(deserialize_string);

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::Error::custom("Unexpected key type"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char bytes
        byte_buf option unit unit_struct seq tuple
        tuple_struct map newtype_struct struct enum ignored_any
    }
}

struct PathValueDeserializer<'de> {
    key_or_idx: Option<PathKeyOrIdx<'de>>,
    value: &'de str,
}

macro_rules! path_parse_value {
    ($trait_fn:ident, $visit_fn:ident, $ty:literal) => {
        fn $trait_fn<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            let v = self.value.parse().map_err(|_| match self.key_or_idx {
                Some(PathKeyOrIdx::Key(key)) => rejection::PathDeserializationError::new(
                    rejection::ErrorKind::ParseErrorAtKey {
                        key: key.to_string(),
                        value: self.value.to_string(),
                        expected_type: $ty,
                    },
                ),
                Some(PathKeyOrIdx::Idx(index)) => rejection::PathDeserializationError::new(
                    rejection::ErrorKind::ParseErrorAtIndex {
                        index,
                        value: self.value.to_string(),
                        expected_type: $ty,
                    },
                ),
                None => {
                    rejection::PathDeserializationError::new(rejection::ErrorKind::ParseError {
                        value: self.value.to_string(),
                        expected_type: $ty,
                    })
                }
            })?;
            visitor.$visit_fn(v)
        }
    };
}

impl<'de> serde::de::Deserializer<'de> for PathValueDeserializer<'de> {
    type Error = rejection::PathDeserializationError;

    path_unsupported_type!(deserialize_map);
    path_unsupported_type!(deserialize_identifier);

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_borrowed_bytes(self.value.as_bytes())
    }

    path_parse_value!(deserialize_bool, visit_bool, "bool");
    path_parse_value!(deserialize_i8, visit_i8, "i8");
    path_parse_value!(deserialize_i16, visit_i16, "i16");
    path_parse_value!(deserialize_i32, visit_i32, "i32");
    path_parse_value!(deserialize_i64, visit_i64, "i64");
    path_parse_value!(deserialize_i128, visit_i128, "i128");
    path_parse_value!(deserialize_u8, visit_u8, "u8");
    path_parse_value!(deserialize_u16, visit_u16, "u16");
    path_parse_value!(deserialize_u32, visit_u32, "u32");
    path_parse_value!(deserialize_u64, visit_u64, "u64");
    path_parse_value!(deserialize_u128, visit_u128, "u128");
    path_parse_value!(deserialize_f32, visit_f32, "f32");
    path_parse_value!(deserialize_f64, visit_f64, "f64");
    path_parse_value!(deserialize_string, visit_string, "String");
    path_parse_value!(deserialize_byte_buf, visit_string, "String");
    path_parse_value!(deserialize_char, visit_char, "char");

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        let key_or_idx = self.key_or_idx;
        let value = self.value;
        visitor
            .visit_borrowed_str(value)
            .map_err(
                |e: rejection::PathDeserializationError| match (&e.kind, key_or_idx) {
                    (rejection::ErrorKind::Message(message), Some(PathKeyOrIdx::Key(key))) => {
                        rejection::PathDeserializationError::new(
                            rejection::ErrorKind::DeserializeError {
                                key: key.to_string(),
                                value: value.to_string(),
                                message: message.clone(),
                            },
                        )
                    }
                    _ => e,
                },
            )
    }

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

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        // `Vec<(K, V)>` targets decompose each map entry into a 2-tuple; anything
        // else at this arity has no sensible interpretation for a single value.
        struct PathPairAccess<'de> {
            key_or_idx: Option<PathKeyOrIdx<'de>>,
            value: Option<&'de str>,
        }

        impl<'de> serde::de::SeqAccess<'de> for PathPairAccess<'de> {
            type Error = rejection::PathDeserializationError;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
            where
                T: serde::de::DeserializeSeed<'de>,
            {
                match self.key_or_idx.take() {
                    Some(PathKeyOrIdx::Key(key)) => {
                        return seed.deserialize(PathKeyDeserializer { key }).map(Some);
                    }
                    Some(PathKeyOrIdx::Idx(_)) => {
                        return Err(serde::de::Error::custom("array types are not supported"));
                    }
                    None => {}
                }
                self.value
                    .take()
                    .map(|value| {
                        seed.deserialize(PathValueDeserializer {
                            key_or_idx: None,
                            value,
                        })
                    })
                    .transpose()
            }
        }

        if len == 2 {
            let value = self.value;
            // `key_or_idx` is only `None` when deserializing bare (non-map) values,
            // which never reach `deserialize_tuple` at len == 2.
            self.key_or_idx.map_or_else(
                || {
                    Err(rejection::PathDeserializationError::unsupported_type(
                        std::any::type_name::<V::Value>(),
                    ))
                },
                |key_or_idx| {
                    visitor.visit_seq(PathPairAccess {
                        key_or_idx: Some(key_or_idx),
                        value: Some(value),
                    })
                },
            )
        } else {
            Err(rejection::PathDeserializationError::unsupported_type(
                std::any::type_name::<V::Value>(),
            ))
        }
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(rejection::PathDeserializationError::unsupported_type(
            std::any::type_name::<V::Value>(),
        ))
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(rejection::PathDeserializationError::unsupported_type(
            std::any::type_name::<V::Value>(),
        ))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(rejection::PathDeserializationError::unsupported_type(
            std::any::type_name::<V::Value>(),
        ))
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
        visitor.visit_enum(PathEnumAccess { value: self.value })
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

struct PathEnumAccess<'de> {
    value: &'de str,
}

impl<'de> serde::de::EnumAccess<'de> for PathEnumAccess<'de> {
    type Error = rejection::PathDeserializationError;
    type Variant = PathUnitVariant;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        Ok((
            seed.deserialize(PathKeyDeserializer { key: self.value })?,
            PathUnitVariant,
        ))
    }
}

struct PathUnitVariant;

impl<'de> serde::de::VariantAccess<'de> for PathUnitVariant {
    type Error = rejection::PathDeserializationError;

    fn unit_variant(self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        Err(rejection::PathDeserializationError::unsupported_type(
            "newtype enum variant",
        ))
    }

    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(rejection::PathDeserializationError::unsupported_type(
            "tuple enum variant",
        ))
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(rejection::PathDeserializationError::unsupported_type(
            "struct enum variant",
        ))
    }
}

struct PathSeqAccess<'de> {
    params: &'de [(std::sync::Arc<str>, String)],
    idx: usize,
}

impl<'de> serde::de::SeqAccess<'de> for PathSeqAccess<'de> {
    type Error = rejection::PathDeserializationError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        match self.params.split_first() {
            Some(((_, value), tail)) => {
                self.params = tail;
                let idx = self.idx;
                self.idx = self.idx.wrapping_add(1);
                seed.deserialize(PathValueDeserializer {
                    key_or_idx: Some(PathKeyOrIdx::Idx(idx)),
                    value: value.as_str(),
                })
                .map(Some)
            }
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.params.len())
    }
}

impl<S: Sync, T> FromRequestParts<S> for Path<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::PathRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
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
                .map_err(|e: rejection::PathDeserializationError| {
                    rejection::FailedToDeserializePathParams(e).into()
                })
        })
    }
}

/// Extractor for the raw, un-deserialized path parameters as `(key, value)`
/// string pairs, bypassing [`Path`]'s `serde` deserialization step entirely.
/// Matches `axum::extract::RawPathParams`.
///
/// Prefer [`Path`] where it fits; this exists for the (rarer) case of wanting
/// the params without paying for the deserialize step.
#[derive(Debug, Clone)]
pub struct RawPathParams(PathParamsVec);

impl<S: Sync> FromRequestParts<S> for RawPathParams {
    type Rejection = rejection::RawPathParamsRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        // Mirrors `Path<T>`'s own "no extension = zero params" convention above:
        // this crate never inserts a `PathParams` extension for parameterless
        // routes, so a missing extension isn't `MissingPathParams` here either.
        std::future::ready(Ok(Self(
            parts
                .extensions
                .get::<PathParams>()
                .map_or_else(PathParamsVec::new, |p| p.0.clone()),
        )))
    }
}

impl RawPathParams {
    /// Get an iterator over the path parameters.
    #[must_use]
    pub fn iter(&self) -> RawPathParamsIter<'_> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a RawPathParams {
    type Item = (&'a str, &'a str);
    type IntoIter = RawPathParamsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        RawPathParamsIter(self.0.iter())
    }
}

/// An iterator over raw path parameters. Created with [`RawPathParams::iter`].
#[derive(Debug, Clone)]
pub struct RawPathParamsIter<'a>(std::slice::Iter<'a, (std::sync::Arc<str>, String)>);

impl<'a> Iterator for RawPathParamsIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.0.next()?;
        Some((key.as_ref(), value.as_str()))
    }
}

/// Extractor for query parameters. Requires the `query` feature.
#[cfg(feature = "query")]
#[derive(Debug, Clone)]
pub struct Query<T>(pub T);

#[cfg(feature = "query")]
impl<S: Sync, T> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::QueryRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            let query_str = parts.uri.query().unwrap_or("");
            let iter = QueryIter { input: query_str };
            let map_de = serde::de::value::MapDeserializer::new(iter);
            T::deserialize(map_de)
                .map(Query)
                .map_err(|e: serde::de::value::Error| {
                    rejection::FailedToDeserializeQueryString(format!(
                        "Failed to deserialize query parameters: {e}"
                    ))
                    .into()
                })
        })
    }
}

/// Extracts the raw, un-deserialized query string (`None` if the request has
/// none), matching `axum::extract::RawQuery`. Infallible — unlike [`Query`],
/// this never rejects, since it does no parsing at all.
#[derive(Debug, Clone)]
pub struct RawQuery(pub Option<String>);

impl<S: Sync> FromRequestParts<S> for RawQuery {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(parts.uri.query().map(str::to_string))))
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
    // `get` rather than an index: a split landing mid-codepoint yields `None`, which is the
    // right answer anyway since `+json` is ASCII.
    subtype.eq_ignore_ascii_case("json")
        || subtype
            .len()
            .checked_sub("+json".len())
            .and_then(|split| subtype.get(split..))
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+json"))
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
    type Rejection = rejection::JsonRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        // Validate Content-Type: must be a JSON media type (`application/json`, optionally
        // with parameters, or any `application/*+json` vendor/suffix type).
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_json_content_type(ct) {
            return Err(rejection::MissingJsonContentType(format!(
                "Expected Content-Type: application/json, got: '{ct}'"
            ))
            .into());
        }
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::BytesRejection::from)?;
        serde_json::from_slice::<T>(&body).map(Json).map_err(|e| {
            // Matches Axum's `JsonRejection`: malformed JSON (unbalanced braces,
            // trailing commas, invalid escapes, truncated input, ...) is a client
            // syntax error (`400`), while well-formed JSON that doesn't match the
            // target type's shape (wrong field types, missing required fields) is
            // `422` — the payload was understood but semantically rejected.
            let message = format!("Failed to deserialize JSON payload: {e}");
            match e.classify() {
                serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                    rejection::JsonSyntaxError(message).into()
                }
                serde_json::error::Category::Data | serde_json::error::Category::Io => {
                    rejection::JsonDataError(message).into()
                }
            }
        })
    }
}

impl<S: Sync> FromRequestParts<S> for HeaderMap {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.headers.clone()))
    }
}

impl<S: Sync> FromRequestParts<S> for Method {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.method.clone()))
    }
}

impl<S: Sync> FromRequestParts<S> for Uri {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.uri.clone()))
    }
}

impl<S: Sync> FromRequest<S> for Bytes {
    type Rejection = rejection::BytesRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        req.into_body()
            .collect_bytes(limit)
            .await
            .map_err(Into::into)
    }
}

impl<S: Sync> FromRequest<S> for String {
    type Rejection = rejection::StringRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::BytesRejection::from)?;
        Self::from_utf8(body.to_vec()).map_err(|e| {
            rejection::InvalidUtf8(format!("Request body is not valid UTF-8: {e}")).into()
        })
    }
}

/// Extractor for form-urlencoded payloads. Requires the `form` feature.
#[cfg(feature = "form")]
#[derive(Debug, Clone)]
pub struct Form<T>(pub T);

#[cfg(feature = "form")]
impl<S: Sync, T> FromRequestParts<S> for Form<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::FormRejection;

    /// Deserializes from the URL query string — matches Axum's `Form` extractor,
    /// which reads `GET`/`HEAD` requests from the query string rather than the
    /// (typically absent) body. See [`FromRequest`] for the `POST`/body path.
    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            let query_str = parts.uri.query().unwrap_or("");
            let iter = QueryIter { input: query_str };
            let map_de = serde::de::value::MapDeserializer::new(iter);
            T::deserialize(map_de)
                .map(Form)
                .map_err(|e: serde::de::value::Error| {
                    rejection::FailedToDeserializeForm(format!(
                        "Failed to deserialize form payload: {e}"
                    ))
                    .into()
                })
        })
    }
}

#[cfg(feature = "form")]
impl<S, T> FromRequest<S> for Form<T>
where
    S: Sync,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::FormRejection;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        // Matches Axum: `GET`/`HEAD` requests are read from the query string (no
        // body/Content-Type expected — this is the common "search form" pattern);
        // every other method reads and deserializes the request body.
        if req.method() == hyper::Method::GET || req.method() == hyper::Method::HEAD {
            let (mut parts, _body) = req.into_parts();
            return Self::from_request_parts(&mut parts, state).await;
        }

        // Validate Content-Type: must be application/x-www-form-urlencoded.
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let essence = ct.split(';').next().unwrap_or("").trim();
        if !essence.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            return Err(rejection::InvalidFormContentType(format!(
                "Expected Content-Type: application/x-www-form-urlencoded, got: '{ct}'"
            ))
            .into());
        }
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::BytesRejection::from)?;
        let body_str = std::str::from_utf8(&body).map_err(|_| {
            rejection::FailedToDeserializeFormBody("Form body is not valid UTF-8".to_string())
        })?;
        let iter = QueryIter { input: body_str };
        let map_de = serde::de::value::MapDeserializer::new(iter);
        T::deserialize(map_de)
            .map(Form)
            .map_err(|e: serde::de::value::Error| {
                rejection::FailedToDeserializeFormBody(format!(
                    "Failed to deserialize form payload: {e}"
                ))
                .into()
            })
    }
}

/// Extractor for the raw, un-deserialized form payload, bypassing [`Form`]'s
/// `serde` deserialization step entirely. Matches `axum::extract::RawForm`.
///
/// For `GET`/`HEAD` requests this is the raw query string; for other methods
/// it's the raw `application/x-www-form-urlencoded` request body. Requires
/// the `form` feature.
#[cfg(feature = "form")]
#[derive(Debug, Clone)]
pub struct RawForm(pub Bytes);

#[cfg(feature = "form")]
impl<S> FromRequest<S> for RawForm
where
    S: Sync,
{
    type Rejection = rejection::RawFormRejection;

    async fn from_request(req: hyper::Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        if req.method() == hyper::Method::GET || req.method() == hyper::Method::HEAD {
            return Ok(Self(req.uri().query().map_or_else(Bytes::new, |q| {
                Bytes::copy_from_slice(q.as_bytes())
            })));
        }

        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let essence = ct.split(';').next().unwrap_or("").trim();
        if !essence.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            return Err(rejection::InvalidFormContentType(format!(
                "Expected Content-Type: application/x-www-form-urlencoded, got: '{ct}'"
            ))
            .into());
        }
        let limit = max_body_size(req.extensions());
        let body = req
            .into_body()
            .collect_bytes(limit)
            .await
            .map_err(rejection::BytesRejection::from)?;
        Ok(Self(body))
    }
}

/// Extractor for request-local extensions.
#[derive(Debug, Clone, Copy)]
pub struct Extension<T>(pub T);

impl<S: Sync, T> FromRequestParts<S> for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Rejection = rejection::ExtensionRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            parts
                .extensions
                .get::<T>()
                .cloned()
                .map(Extension)
                .ok_or_else(|| {
                    rejection::MissingExtension(format!(
                        "Missing extension: {}",
                        std::any::type_name::<T>()
                    ))
                    .into()
                })
        })
    }
}

impl<T> crate::http::response::IntoResponse for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn into_response(self) -> crate::http::response::Response {
        let mut res = crate::http::response::IntoResponse::into_response(());
        res.extensions_mut().insert(self.0);
        res
    }
}

/// A `tower::Layer` inserting a fixed, cloneable value into every incoming
/// request's extensions. Matches `Extension<T>`'s `tower::Layer` impl in axum
/// — the layer form of the [`Extension`] extractor above, for a value bound
/// once at `.layer()` time rather than read from somewhere else per request.
impl<S, T> tower::Layer<S> for Extension<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Service = AddExtension<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        AddExtension {
            inner,
            value: self.0.clone(),
        }
    }
}

/// The `tower::Service` produced by [`Extension`]'s `tower::Layer` impl.
/// Matches `axum::extension::AddExtension`.
#[derive(Clone, Copy, Debug)]
pub struct AddExtension<S, T> {
    pub(crate) inner: S,
    pub(crate) value: T,
}

impl<ResBody, S, T> tower::Service<hyper::Request<ResBody>> for AddExtension<S, T>
where
    S: tower::Service<hyper::Request<ResBody>>,
    T: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: hyper::Request<ResBody>) -> Self::Future {
        req.extensions_mut().insert(self.value.clone());
        self.inner.call(req)
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
impl<S: Sync> FromRequestParts<S> for Cookies {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            let mut jar = CookieJar::new();
            if let Some(cookie_header) = parts.headers.get(hyper::header::COOKIE)
                && let Ok(cookie_str) = cookie_header.to_str()
            {
                for c in Cookie::split_parse_encoded(cookie_str).flatten() {
                    jar.add_original(c.into_owned());
                }
            }
            Ok(Self { jar })
        })
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

    fn from_request(
        req: hyper::Request<Body>,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(req.into_body())))
    }
}

impl<S: Sync> FromRequest<S> for hyper::Request<Body> {
    type Rejection = Infallible;

    fn from_request(
        req: hyper::Request<Body>,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(req))
    }
}

/// Extractor for host header or authority.
#[derive(Debug, Clone)]
pub struct Host(pub String);

impl<S: Sync> FromRequestParts<S> for Host {
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            if let Some(host) = parts
                .headers
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
            {
                Ok(Self(host.to_string()))
            } else if let Some(host) = parts.uri.host() {
                Ok(Self(host.to_string()))
            } else {
                Err(Error::status(
                    StatusCode::BAD_REQUEST,
                    "Missing Host header or authority in URI",
                ))
            }
        })
    }
}

/// Extractor for the original URI. Requires the `original-uri` feature.
#[cfg(feature = "original-uri")]
#[derive(Debug, Clone)]
pub struct OriginalUri(pub Uri);

#[cfg(feature = "original-uri")]
impl<S: Sync> FromRequestParts<S> for OriginalUri {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            let uri = parts
                .extensions
                .get::<Self>()
                .map_or_else(|| parts.uri.clone(), |ou| ou.0.clone());
            Ok(Self(uri))
        })
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
impl<S: Sync> FromRequestParts<S> for MatchedPath {
    type Rejection = rejection::MatchedPathRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            parts.extensions.get::<Self>().cloned().ok_or_else(|| {
                rejection::MatchedPathMissing(
                    "No matched path found in request extensions".to_string(),
                )
                .into()
            })
        })
    }
}

/// Extractor for the path prefix a matched route was nested under, e.g. `/api`
/// for a route mounted via `Router::nest("/api", ...)`. Matches
/// `axum::extract::NestedPath`.
///
/// Only available for requests that matched a route reached through at least
/// one level of nesting — a non-nested route has no [`NestedPath`].
#[derive(Debug, Clone)]
pub struct NestedPath(pub(crate) std::sync::Arc<str>);

impl NestedPath {
    /// Returns a `str` representation of the path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S: Sync> FromRequestParts<S> for NestedPath {
    type Rejection = rejection::NestedPathRejection;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Self>()
                .cloned()
                .ok_or(rejection::NestedPathRejection),
        )
    }
}

/// Extractor for network connection info.
#[derive(Debug, Clone, Copy)]
pub struct ConnectInfo<T>(pub T);

impl<S: Sync, T> FromRequestParts<S> for ConnectInfo<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready({
            parts.extensions.get::<Self>().cloned().ok_or_else(|| {
                Error::status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Missing ConnectInfo<{}> extension",
                        std::any::type_name::<T>()
                    ),
                )
            })
        })
    }
}

/// Derives an extractor's [`FromRequest`] impl from its [`FromRequestParts`] one: discard the
/// body, run the parts extractor, forward its rejection type unchanged. Every extractor that
/// only reads request metadata (headers, method, URI, extensions, state) works this way, so
/// each would otherwise repeat the same five-line body verbatim.
///
/// The second form is for generic extractors (`State<T>`, `Path<T>`, …), whose forwarded impl
/// has to restate the same `T` bounds its `FromRequestParts` impl carries.
macro_rules! impl_from_request_via_parts {
    ($ty:ty) => {
        impl_from_request_via_parts!(@imp $ty, [], []);
    };
    ($ty:ty, T: $($bound:tt)+) => {
        impl_from_request_via_parts!(@imp $ty, [T], [T: $($bound)+]);
    };
    (@imp $ty:ty, [$($generic:ident)?], [$($bounds:tt)*]) => {
        impl<S: Sync, $($generic)?> FromRequest<S> for $ty
        where
            $($bounds)*
        {
            type Rejection = <Self as FromRequestParts<S>>::Rejection;

            async fn from_request(
                req: hyper::Request<Body>,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                let (mut parts, _) = req.into_parts();
                <Self as FromRequestParts<S>>::from_request_parts(&mut parts, state).await
            }
        }
    };
}

impl_from_request_via_parts!(RawQuery);
#[cfg(feature = "early-hints")]
impl_from_request_via_parts!(crate::http::early_hints::EarlyHints);
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
impl_from_request_via_parts!(NestedPath);

impl_from_request_via_parts!(State<T>, T: FromRef<S> + Send + Sync + 'static);
impl_from_request_via_parts!(Path<T>, T: DeserializeOwned + Send + Sync + 'static);
impl_from_request_via_parts!(RawPathParams);
#[cfg(feature = "query")]
impl_from_request_via_parts!(Query<T>, T: DeserializeOwned + Send + Sync + 'static);
impl_from_request_via_parts!(Extension<T>, T: Clone + Send + Sync + 'static);
impl_from_request_via_parts!(ConnectInfo<T>, T: Clone + Send + Sync + 'static);

/// `Option<T>` succeeds with `None` wherever `T` would fail, for any
/// extractor. Matches the effect of Axum's `OptionalFromRequestParts`/
/// `OptionalFromRequest` blanket impls, simplified: Axum lets an individual
/// extractor override *which* rejections become `None` versus a real error
/// (e.g. `Query`'s override still hard-errors on malformed query strings,
/// only treating "no query string at all" as `None`). This collapses every
/// rejection to `None` uniformly instead, which is simpler but less precise —
/// most consumers of `Option<Extractor>` just want "was it there or not"
/// and don't rely on the distinction.
impl<S: Sync, T> FromRequestParts<S> for Option<T>
where
    T: FromRequestParts<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(T::from_request_parts(parts, state).await.ok())
    }
}

/// See [`FromRequestParts` for `Option<T>`](#impl-FromRequestParts%3CS%3E-for-Option%3CT%3E)
/// — same simplification relative to Axum's real `OptionalFromRequest`.
impl<S: Sync, T> FromRequest<S> for Option<T>
where
    T: FromRequest<S>,
{
    type Rejection = Infallible;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        Ok(T::from_request(req, state).await.ok())
    }
}

/// Sugar for running an extractor against request *parts* (headers, method,
/// URI, extensions — no body) outside of a handler's argument list. Matches
/// `axum_core::RequestPartsExt`.
pub trait RequestPartsExt {
    /// Runs `T::from_request_parts` against unit state (`S = ()`).
    fn extract<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>;

    /// Runs `T::from_request_parts` against `state`.
    fn extract_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync;
}

impl RequestPartsExt for hyper::http::request::Parts {
    fn extract<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>,
    {
        T::from_request_parts(self, &())
    }

    fn extract_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync,
    {
        T::from_request_parts(self, state)
    }
}

/// Sugar for running an extractor against an owned [`hyper::Request`]
/// outside of a handler's argument list. Matches `axum_core::RequestExt`.
pub trait RequestExt: Sized {
    /// Runs `T::from_request` against unit state (`S = ()`), consuming `self`.
    fn extract<T>(self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<()>;

    /// Runs `T::from_request` against `state`, consuming `self`.
    fn extract_with_state<T, S>(
        self,
        state: &S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<S>,
        S: Sync;

    /// Runs `T::from_request_parts` against unit state, without consuming the body.
    fn extract_parts<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>;

    /// Runs `T::from_request_parts` against `state`, without consuming the body.
    fn extract_parts_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync;
}

impl RequestExt for hyper::Request<Body> {
    fn extract<T>(self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<()>,
    {
        T::from_request(self, &())
    }

    fn extract_with_state<T, S>(
        self,
        state: &S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequest<S>,
        S: Sync,
    {
        T::from_request(self, state)
    }

    fn extract_parts<T>(&mut self) -> impl Future<Output = Result<T, T::Rejection>> + Send
    where
        T: FromRequestParts<()>,
    {
        let (mut parts, body) = std::mem::replace(self, Self::new(Body::empty())).into_parts();
        async move {
            let result = T::from_request_parts(&mut parts, &()).await;
            *self = Self::from_parts(parts, body);
            result
        }
    }

    fn extract_parts_with_state<'a, T, S>(
        &'a mut self,
        state: &'a S,
    ) -> impl Future<Output = Result<T, T::Rejection>> + Send + 'a
    where
        T: FromRequestParts<S> + 'a,
        S: Sync,
    {
        let (mut parts, body) = std::mem::replace(self, Self::new(Body::empty())).into_parts();
        async move {
            let result = T::from_request_parts(&mut parts, state).await;
            *self = Self::from_parts(parts, body);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hyper::http::Request;
    use serde::Deserialize;

    #[tokio::test]
    async fn add_extension_layer_inserts_the_bound_value_into_every_request() {
        #[derive(Clone, PartialEq, Debug)]
        struct Shared(u32);

        struct Echo;
        impl tower::Service<hyper::Request<Body>> for Echo {
            type Response = Option<Shared>;
            type Error = Infallible;
            type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: hyper::Request<Body>) -> Self::Future {
                std::future::ready(Ok(req.extensions().get::<Shared>().cloned()))
            }
        }

        let mut svc = tower::Layer::layer(&Extension(Shared(42)), Echo);
        let req = Request::builder().body(Body::empty()).unwrap();
        let seen = tower::Service::call(&mut svc, req).await.unwrap();
        assert_eq!(seen, Some(Shared(42)));
    }

    #[tokio::test]
    async fn option_extractor_is_some_on_success_and_none_on_rejection() {
        let mut present = Request::builder().body(()).unwrap().into_parts().0;
        present.extensions.insert(7u32);
        let ext_or_none = Option::<Extension<u32>>::from_request_parts(&mut present, &())
            .await
            .unwrap();
        assert_eq!(ext_or_none.map(|Extension(v)| v), Some(7));

        let mut absent = Request::builder().body(()).unwrap().into_parts().0;
        let none = Option::<Extension<u32>>::from_request_parts(&mut absent, &())
            .await
            .unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn request_ext_extract_parts_preserves_the_body() {
        let req = Request::builder()
            .uri("/x?a=1")
            .body(Body::full(Bytes::from("payload")))
            .unwrap();
        let mut req = req;
        let RawQuery(q) = req.extract_parts::<RawQuery>().await.unwrap();
        assert_eq!(q.as_deref(), Some("a=1"));
        // The body must still be there after `extract_parts` returns.
        let bytes = req.into_body().collect_bytes(1024).await.unwrap();
        assert_eq!(bytes.as_ref(), b"payload");
    }

    #[tokio::test]
    async fn request_parts_ext_extract_runs_against_unit_state() {
        let mut parts = Request::builder()
            .uri("/x?a=1")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let RawQuery(q) = parts.extract::<RawQuery>().await.unwrap();
        assert_eq!(q.as_deref(), Some("a=1"));
    }

    #[cfg(any(feature = "query", feature = "form"))]
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

    #[cfg(any(feature = "query", feature = "form"))]
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
        let headers = HeaderMap::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(headers.get("x-test").unwrap(), "hello");

        // Method
        let method = Method::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(method, "POST");

        // Uri
        let uri = Uri::from_request_parts(&mut parts, &()).await.unwrap();
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

    #[tokio::test]
    async fn test_host_missing() {
        let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
        let res = Host::from_request_parts(&mut parts, &()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_connect_info_missing() {
        let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
        let res = ConnectInfo::<std::net::SocketAddr>::from_request_parts(&mut parts, &()).await;
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

        // The method must be POST (or any non-GET/HEAD): `Form::from_request` delegates
        // GET/HEAD to the query-string path without ever reaching the Content-Type check.
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
    #[tokio::test]
    async fn test_form_from_request_parts_deserialize_error() {
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
        let result = Form::<FormPayload>::from_request_parts(&mut parts, &()).await;
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

    #[cfg(feature = "form")]
    #[tokio::test]
    async fn test_raw_form_reads_query_on_get_and_body_on_post() {
        let get_req = Request::builder()
            .method("GET")
            .uri("/search?foo=bar")
            .body(Body::empty())
            .unwrap();
        let RawForm(query) = RawForm::from_request(get_req, &()).await.unwrap();
        assert_eq!(&query[..], b"foo=bar");

        let post_req = Request::builder()
            .method("POST")
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::full(Bytes::from("foo=bar")))
            .unwrap();
        let RawForm(body) = RawForm::from_request(post_req, &()).await.unwrap();
        assert_eq!(&body[..], b"foo=bar");
    }

    #[cfg(feature = "form")]
    #[tokio::test]
    async fn test_raw_form_rejects_wrong_content_type_on_post() {
        let req = Request::builder()
            .method("POST")
            .body(Body::full(Bytes::from("foo=bar")))
            .unwrap();
        let err = RawForm::from_request(req, &()).await.unwrap_err();
        assert!(matches!(
            err,
            rejection::RawFormRejection::InvalidFormContentType(_)
        ));
    }

    #[cfg(feature = "query")]
    #[tokio::test]
    async fn test_query_deserialize_error() {
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
        let result = Query::<QueryPayload>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_raw_query_present_and_absent() {
        let mut with_query = Request::builder()
            .uri("/path?a=1&b=2")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let RawQuery(q) = RawQuery::from_request_parts(&mut with_query, &())
            .await
            .unwrap();
        assert_eq!(q.as_deref(), Some("a=1&b=2"));

        let mut without_query = Request::builder()
            .uri("/path")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let RawQuery(q2) = RawQuery::from_request_parts(&mut without_query, &())
            .await
            .unwrap();
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

    #[tokio::test]
    async fn test_path_tuple_success_and_length_mismatch() {
        let mut ok_parts = make_path_parts(vec![("id", "42"), ("name", "hello")]);
        let Path((id, name)) = Path::<(u32, String)>::from_request_parts(&mut ok_parts, &())
            .await
            .unwrap();
        assert_eq!(id, 42);
        assert_eq!(name, "hello");

        // Too many params for a 2-tuple.
        let mut too_many = make_path_parts(vec![("a", "1"), ("b", "2"), ("c", "3")]);
        assert!(
            Path::<(u32, String)>::from_request_parts(&mut too_many, &())
                .await
                .is_err()
        );

        // Too few params for a 2-tuple.
        let mut too_few = make_path_parts(vec![("a", "1")]);
        assert!(
            Path::<(u32, String)>::from_request_parts(&mut too_few, &())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_path_vec_seq_target() {
        // `Vec<T>` reaches `deserialize_seq` directly (not via tuple delegation),
        // and its `Deserialize` impl calls `SeqAccess::size_hint` to preallocate.
        let mut parts = make_path_parts(vec![("a", "x"), ("b", "y"), ("c", "z")]);
        let Path(values) = Path::<Vec<String>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(
            values,
            vec!["x".to_string(), "y".to_string(), "z".to_string()]
        );
    }

    #[tokio::test]
    async fn test_raw_path_params_iterates_key_value_pairs_in_order() {
        let mut parts = make_path_parts(vec![("user_id", "1"), ("team_id", "2")]);
        let params = RawPathParams::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        let collected: Vec<_> = params.iter().collect();
        assert_eq!(collected, vec![("user_id", "1"), ("team_id", "2")]);
    }

    #[tokio::test]
    async fn test_raw_path_params_succeeds_empty_on_a_parameterless_route() {
        let mut parts = make_path_parts(vec![]);
        let params = RawPathParams::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(params.iter().count(), 0);
    }

    #[tokio::test]
    async fn test_path_scalar_wrong_param_count() {
        // Zero params for a bare scalar target.
        let mut zero = make_path_parts(vec![]);
        assert!(
            Path::<u32>::from_request_parts(&mut zero, &())
                .await
                .is_err()
        );

        // More than one param for a bare scalar target.
        let mut two = make_path_parts(vec![("a", "1"), ("b", "2")]);
        assert!(
            Path::<u32>::from_request_parts(&mut two, &())
                .await
                .is_err()
        );

        // Exactly one param succeeds.
        let mut one = make_path_parts(vec![("id", "7")]);
        let Path(v) = Path::<u32>::from_request_parts(&mut one, &())
            .await
            .unwrap();
        assert_eq!(v, 7);
    }

    #[tokio::test]
    async fn test_path_error_kind_pinpoints_the_failing_field_or_index() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Params {
            a: u32,
            b: u32,
        }

        let mut struct_target = make_path_parts(vec![("a", "1"), ("b", "not-a-number")]);
        let err = Path::<Params>::from_request_parts(&mut struct_target, &())
            .await
            .unwrap_err();
        let rejection::PathRejection::FailedToDeserializePathParams(err) = err else {
            panic!("expected FailedToDeserializePathParams");
        };
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(matches!(
            err.into_kind(),
            rejection::ErrorKind::ParseErrorAtKey { key, expected_type: "u32", .. }
                if key == "b"
        ));

        let mut tuple_target = make_path_parts(vec![("a", "true"), ("b", "nope")]);
        let err = Path::<(bool, u32)>::from_request_parts(&mut tuple_target, &())
            .await
            .unwrap_err();
        let rejection::PathRejection::FailedToDeserializePathParams(err) = err else {
            panic!("expected FailedToDeserializePathParams");
        };
        assert!(matches!(
            err.into_kind(),
            rejection::ErrorKind::ParseErrorAtIndex {
                index: 1,
                expected_type: "u32",
                ..
            }
        ));

        let mut scalar_target = make_path_parts(vec![("id", "nope")]);
        let err = Path::<u32>::from_request_parts(&mut scalar_target, &())
            .await
            .unwrap_err();
        let rejection::PathRejection::FailedToDeserializePathParams(err) = err else {
            panic!("expected FailedToDeserializePathParams");
        };
        assert!(matches!(
            err.into_kind(),
            rejection::ErrorKind::ParseError {
                expected_type: "u32",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_path_option_top_level_target() {
        // `Path<Option<T>>` makes `Option<T>` the *whole* deserialization target, so
        // `T::deserialize` dispatches straight to `PathDeserializer::deserialize_option`
        // (as opposed to a struct field being `Option<T>`, which is handled entirely by
        // `MapDeserializer`/`CoercingCowDeserializer` without ever calling back into
        // `PathDeserializer::deserialize_option`).
        let mut parts = make_path_parts(vec![("id", "9")]);
        let Path(v) = Path::<Option<u32>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(v, Some(9));
    }

    #[tokio::test]
    async fn test_path_enum_target() {
        let mut parts = make_path_parts(vec![("color", "Red")]);
        let Path(c) = Path::<Color>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(c, Color::Red);
    }

    #[tokio::test]
    async fn test_path_unit_and_unit_struct_targets() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct UnitStruct;

        // `()` as the whole target reaches `deserialize_unit` and ignores any params.
        let mut parts = make_path_parts(vec![("a", "1"), ("b", "2")]);
        let Path(unit_val) = Path::<()>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(unit_val, ());

        // A derived unit struct reaches `deserialize_unit_struct`.
        let mut empty_parts = make_path_parts(vec![]);
        let Path(u) = Path::<UnitStruct>::from_request_parts(&mut empty_parts, &())
            .await
            .unwrap();
        assert_eq!(u, UnitStruct);
    }

    #[tokio::test]
    async fn test_path_newtype_struct_target() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Wrapper(u32);

        let mut parts = make_path_parts(vec![("id", "77")]);
        let Path(Wrapper(v)) = Path::<Wrapper>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(v, 77);
    }

    #[tokio::test]
    async fn test_path_ignored_any_top_level_target() {
        // `IgnoredAny`'s `Deserialize` impl calls `deserialize_ignored_any` directly on the
        // top-level deserializer.
        let mut parts = make_path_parts(vec![("a", "1"), ("b", "2")]);
        let result = Path::<serde::de::IgnoredAny>::from_request_parts(&mut parts, &()).await;
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
