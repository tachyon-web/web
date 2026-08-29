//! Query-string extractors: [`Query`], [`RawQuery`], and the shared
//! [`QueryIter`]/`CoercingCowDeserializer` deserializer machinery (also used
//! by [`super::body::Form`]).

#[cfg(feature = "query")]
use serde::de::DeserializeOwned;
use std::future::Future;

#[cfg(any(feature = "query", feature = "form"))]
use crate::routing::compiled::decode_query_param;
use crate::routing::extract::FromRequestParts;
#[cfg(feature = "query")]
use crate::routing::extract::rejection;

/// Extractor for path parameters.
#[cfg(any(feature = "query", feature = "form"))]
#[derive(Debug, Clone)]
pub(crate) struct QueryIter<'de> {
    pub(crate) input: &'de str,
}

#[cfg(any(feature = "query", feature = "form"))]
pub(crate) struct CoercingCowDeserializer<'de> {
    pub(crate) val: std::borrow::Cow<'de, str>,
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
