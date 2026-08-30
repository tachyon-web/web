//! [`Path`]: URI path-parameter extraction, backed by a custom `serde::Deserializer`
//! (`PathDeserializer`) supporting scalar, tuple, and struct/map targets.

use serde::de::DeserializeOwned;
use std::future::Future;

use crate::routing::extract::{FromRequestParts, rejection};

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
pub(crate) struct PathDeserializer<'de> {
    pub(crate) params: &'de [(std::sync::Arc<str>, String)],
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

impl<S: Sync, T> super::OptionalFromRequestParts<S> for Path<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = rejection::PathRejection;

    async fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match <Self as FromRequestParts<S>>::from_request_parts(parts, state).await {
            Ok(path) => Ok(Some(path)),
            Err(rejection::PathRejection::FailedToDeserializePathParams(e))
                if matches!(
                    e.kind(),
                    rejection::ErrorKind::WrongNumberOfParameters { got: 0, .. }
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
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
