//! Per-extractor rejection types, matching `axum::extract::rejection`.
//!
//! Every built-in extractor that can fail returns one of these instead of the
//! generic [`crate::http::error::Error`] — so handler code that matches on
//! *why* extraction failed (`Err(JsonRejection::MissingJsonContentType(_))`)
//! ports from axum unchanged. `http::error::Error` still exists and is still
//! used for genuinely internal/opaque failures; it's just no longer what
//! extractors hand back to callers.
//!
//! Each leaf type carries a human-readable message and implements
//! `Display + std::error::Error + IntoResponse`. Each composite (`FooRejection`)
//! is a plain enum over its leaves with a `From<Leaf>` impl per variant, exactly
//! like axum's `composite_rejection!`-generated types.

use crate::http::error::Error as CoreError;
use crate::http::response::{IntoResponse, Response};
use hyper::StatusCode;

/// Defines a single leaf rejection: a unit-ish struct carrying one message
/// string, with a fixed HTTP status code baked in.
macro_rules! leaf_rejection {
    ($(#[$m:meta])* pub struct $name:ident => $status:ident) => {
        $(#[$m])*
        pub struct $name(pub(crate) String);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::error::Error for $name {}

        impl IntoResponse for $name {
            fn into_response(self) -> Response {
                (StatusCode::$status, self.0).into_response()
            }
        }
    };
}

/// Defines a fixed-message leaf rejection: a true unit struct with a fixed status code and
/// body text baked in, matching axum-core's `define_rejection!` for rejections that carry no
/// per-occurrence detail.
macro_rules! unit_rejection {
    ($(#[$m:meta])* pub struct $name:ident => $status:ident, $body:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($body)
            }
        }

        impl std::error::Error for $name {}

        impl IntoResponse for $name {
            fn into_response(self) -> Response {
                (StatusCode::$status, $body).into_response()
            }
        }
    };
}

/// Defines a composite rejection: an enum over other rejection types, each
/// wrapped in its own variant, with `IntoResponse`/`Display`/`From<Variant>`
/// all derived mechanically from the variant list.
macro_rules! composite_rejection {
    ($(#[$m:meta])* pub enum $name:ident { $($variant:ident($inner:path)),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug)]
        pub enum $name {
            $(
                #[allow(missing_docs)]
                $variant($inner)
            ),+
        }

        impl IntoResponse for $name {
            fn into_response(self) -> Response {
                match self {
                    $(Self::$variant(inner) => inner.into_response()),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$variant(inner) => std::fmt::Display::fmt(inner, f)),+
                }
            }
        }

        impl std::error::Error for $name {}

        $(
            impl From<$inner> for $name {
                fn from(inner: $inner) -> Self {
                    Self::$variant(inner)
                }
            }
        )+
    };
}

// --- body buffering (shared by Bytes, String, Json, Form) ------------------

leaf_rejection! {
    /// The request body was larger than the configured limit. Matches
    /// `axum_core::extract::rejection::LengthLimitError`.
    pub struct LengthLimitError => PAYLOAD_TOO_LARGE
}

leaf_rejection! {
    /// The request body could not be read to completion.
    ///
    /// Covers any reason other than exceeding a length limit (I/O error, malformed
    /// chunked transfer, ...). Matches `axum_core::extract::rejection::UnknownBodyError`.
    pub struct UnknownBodyError => BAD_REQUEST
}

composite_rejection! {
    /// The request body could not be buffered. Matches
    /// `axum_core::extract::rejection::FailedToBufferBody`.
    pub enum FailedToBufferBody {
        LengthLimitError(LengthLimitError),
        UnknownBodyError(UnknownBodyError),
    }
}

impl From<CoreError> for FailedToBufferBody {
    fn from(e: CoreError) -> Self {
        match e.as_status() {
            Some((status, message)) if status == StatusCode::PAYLOAD_TOO_LARGE => {
                Self::LengthLimitError(LengthLimitError(message.to_string()))
            }
            Some((_, message)) => Self::UnknownBodyError(UnknownBodyError(message.to_string())),
            None => Self::UnknownBodyError(UnknownBodyError(e.to_string())),
        }
    }
}

composite_rejection! {
    /// Rejection for the raw [`bytes::Bytes`] extractor. Matches
    /// `axum_core::extract::rejection::BytesRejection`.
    pub enum BytesRejection {
        FailedToBufferBody(FailedToBufferBody),
    }
}

impl From<CoreError> for BytesRejection {
    fn from(e: CoreError) -> Self {
        Self::FailedToBufferBody(FailedToBufferBody::from(e))
    }
}

leaf_rejection! {
    /// The request body was read successfully but wasn't valid UTF-8. Matches
    /// `axum_core::extract::rejection::InvalidUtf8`.
    pub struct InvalidUtf8 => BAD_REQUEST
}

composite_rejection! {
    /// Rejection for the [`String`] extractor. Matches
    /// `axum_core::extract::rejection::StringRejection`.
    pub enum StringRejection {
        FailedToBufferBody(FailedToBufferBody),
        InvalidUtf8(InvalidUtf8),
    }
}

// --- Path --------------------------------------------------------------

/// The kinds of errors that can happen when deserializing into a [`super::Path`].
///
/// Obtained through [`FailedToDeserializePathParams::kind`]/`::into_kind`, useful
/// for building more precise error messages. Matches `axum::extract::path::ErrorKind`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The URI contained the wrong number of parameters.
    WrongNumberOfParameters {
        /// The number of actual parameters in the URI.
        got: usize,
        /// The number of expected parameters.
        expected: usize,
    },
    /// Failed to parse the value at a specific key into the expected type.
    ///
    /// Used when deserializing into types with named fields, such as structs.
    ParseErrorAtKey {
        /// The key at which the value was located.
        key: String,
        /// The value from the URI.
        value: String,
        /// The expected type of the value.
        expected_type: &'static str,
    },
    /// Failed to parse the value at a specific index into the expected type.
    ///
    /// Used when deserializing into sequence types, such as tuples.
    ParseErrorAtIndex {
        /// The index at which the value was located.
        index: usize,
        /// The value from the URI.
        value: String,
        /// The expected type of the value.
        expected_type: &'static str,
    },
    /// Failed to parse a value into the expected type.
    ///
    /// Used when deserializing into a primitive type (such as `String` and `u32`).
    ParseError {
        /// The value from the URI.
        value: String,
        /// The expected type of the value.
        expected_type: &'static str,
    },
    /// A parameter contained text that, once percent-decoded, wasn't valid UTF-8.
    ///
    /// Currently unreachable: this crate's router falls back to the raw,
    /// still-encoded value on a decode failure rather than rejecting the
    /// request (see `crate::routing::percent_decode`'s callers). Kept for
    /// structural parity with axum, in case that fallback policy changes.
    InvalidUtf8InPathParam {
        /// The key at which the invalid value was located.
        key: String,
    },
    /// Tried to deserialize into an unsupported type such as nested maps.
    ///
    /// This error kind is caused by programmer errors and thus gets converted
    /// into a `500 Internal Server Error` response.
    UnsupportedType {
        /// The name of the unsupported type.
        name: &'static str,
    },
    /// Failed to deserialize the value with a custom deserialization error.
    DeserializeError {
        /// The key at which the invalid value was located.
        key: String,
        /// The value that failed to deserialize.
        value: String,
        /// The deserialization failure message.
        message: String,
    },
    /// Catch-all variant for errors that don't fit any other variant.
    Message(String),
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
            Self::InvalidUtf8InPathParam { key } => write!(f, "Invalid UTF-8 in `{key}`"),
            Self::WrongNumberOfParameters { got, expected } => {
                write!(
                    f,
                    "Wrong number of path arguments for `Path`. Expected {expected} but got {got}"
                )?;
                if *expected == 1 {
                    write!(
                        f,
                        ". Note that multiple parameters must be extracted with a tuple \
                         `Path<(_, _)>` or a struct `Path<YourParams>`"
                    )?;
                }
                Ok(())
            }
            Self::UnsupportedType { name } => write!(f, "Unsupported type `{name}`"),
            Self::ParseErrorAtKey {
                key,
                value,
                expected_type,
            } => write!(
                f,
                "Cannot parse `{key}` with value `{value}` to a `{expected_type}`"
            ),
            Self::ParseError {
                value,
                expected_type,
            } => write!(f, "Cannot parse `{value}` to a `{expected_type}`"),
            Self::ParseErrorAtIndex {
                index,
                value,
                expected_type,
            } => write!(
                f,
                "Cannot parse value at index {index} with value `{value}` to a `{expected_type}`"
            ),
            Self::DeserializeError {
                key,
                value,
                message,
            } => write!(f, "Cannot parse `{key}` with value `{value}`: {message}"),
        }
    }
}

/// Wraps [`ErrorKind`] as a `serde::de::Error`, hiding that impl from the
/// public [`FailedToDeserializePathParams`] surface. Matches axum's internal
/// `PathDeserializationError`.
#[derive(Debug)]
pub(crate) struct PathDeserializationError {
    pub(crate) kind: ErrorKind,
}

impl PathDeserializationError {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) const fn wrong_number_of_parameters(got: usize) -> WrongNumberOfParameters {
        WrongNumberOfParameters { got }
    }

    pub(crate) const fn unsupported_type(name: &'static str) -> Self {
        Self::new(ErrorKind::UnsupportedType { name })
    }
}

/// Builder half of [`PathDeserializationError::wrong_number_of_parameters`].
pub(crate) struct WrongNumberOfParameters {
    got: usize,
}

impl WrongNumberOfParameters {
    pub(crate) const fn expected(self, expected: usize) -> PathDeserializationError {
        PathDeserializationError::new(ErrorKind::WrongNumberOfParameters {
            got: self.got,
            expected,
        })
    }
}

impl serde::de::Error for PathDeserializationError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self {
            kind: ErrorKind::Message(msg.to_string()),
        }
    }
}

impl std::fmt::Display for PathDeserializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for PathDeserializationError {}

/// The path parameters didn't deserialize into the extractor's target type.
/// Matches `axum::extract::path::FailedToDeserializePathParams`.
#[derive(Debug)]
pub struct FailedToDeserializePathParams(pub(crate) PathDeserializationError);

impl FailedToDeserializePathParams {
    /// Get a reference to the underlying error kind.
    #[must_use]
    pub const fn kind(&self) -> &ErrorKind {
        &self.0.kind
    }

    /// Convert this error into the underlying error kind.
    #[must_use]
    pub fn into_kind(self) -> ErrorKind {
        self.0.kind
    }

    /// Get the response body text used for this rejection.
    #[must_use]
    pub fn body_text(&self) -> String {
        match &self.0.kind {
            ErrorKind::Message(_)
            | ErrorKind::DeserializeError { .. }
            | ErrorKind::InvalidUtf8InPathParam { .. }
            | ErrorKind::ParseError { .. }
            | ErrorKind::ParseErrorAtIndex { .. }
            | ErrorKind::ParseErrorAtKey { .. } => format!("Invalid URL: {}", self.0.kind),
            ErrorKind::WrongNumberOfParameters { .. } | ErrorKind::UnsupportedType { .. } => {
                self.0.kind.to_string()
            }
        }
    }

    /// Get the status code used for this rejection.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match &self.0.kind {
            ErrorKind::Message(_)
            | ErrorKind::DeserializeError { .. }
            | ErrorKind::InvalidUtf8InPathParam { .. }
            | ErrorKind::ParseError { .. }
            | ErrorKind::ParseErrorAtIndex { .. }
            | ErrorKind::ParseErrorAtKey { .. } => StatusCode::BAD_REQUEST,
            ErrorKind::WrongNumberOfParameters { .. } | ErrorKind::UnsupportedType { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl std::fmt::Display for FailedToDeserializePathParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for FailedToDeserializePathParams {}

impl IntoResponse for FailedToDeserializePathParams {
    fn into_response(self) -> Response {
        let status = self.status();
        (status, self.body_text()).into_response()
    }
}

unit_rejection! {
    /// The route matched but no path-parameter extension was present at all
    /// — an internal routing bug rather than a client error. Matches
    /// `axum::extract::rejection::MissingPathParams`.
    pub struct MissingPathParams => INTERNAL_SERVER_ERROR, "No paths parameters found for matched route"
}

composite_rejection! {
    /// Rejection for the [`super::Path`] extractor. Matches
    /// `axum::extract::rejection::PathRejection`.
    pub enum PathRejection {
        FailedToDeserializePathParams(FailedToDeserializePathParams),
        MissingPathParams(MissingPathParams),
    }
}

/// A path parameter contained text that, once percent-decoded, wasn't valid
/// UTF-8. Matches `axum::extract::path::InvalidUtf8InPathParam`.
///
/// Currently unreachable via [`super::RawPathParams`]: this crate's router
/// falls back to the raw, still-encoded value on a decode failure rather than
/// rejecting the request (see [`ErrorKind::InvalidUtf8InPathParam`]'s docs).
/// Kept for structural parity with axum, in case that fallback policy changes.
#[derive(Debug, Clone)]
pub struct InvalidUtf8InPathParam {
    key: std::sync::Arc<str>,
}

impl InvalidUtf8InPathParam {
    /// Get the response body text used for this rejection.
    #[must_use]
    pub fn body_text(&self) -> String {
        self.to_string()
    }

    /// Get the status code used for this rejection.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl std::fmt::Display for InvalidUtf8InPathParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid UTF-8 in `{}`", self.key)
    }
}

impl std::error::Error for InvalidUtf8InPathParam {}

impl IntoResponse for InvalidUtf8InPathParam {
    fn into_response(self) -> Response {
        let status = self.status();
        (status, self.body_text()).into_response()
    }
}

composite_rejection! {
    /// Rejection for the [`super::RawPathParams`] extractor. Matches
    /// `axum::extract::rejection::RawPathParamsRejection`.
    pub enum RawPathParamsRejection {
        InvalidUtf8InPathParam(InvalidUtf8InPathParam),
        MissingPathParams(MissingPathParams),
    }
}

// --- Query ---------------------------------------------------------------

#[cfg(feature = "query")]
leaf_rejection! {
    /// The query string didn't deserialize into the extractor's target type.
    /// Matches `axum::extract::rejection::FailedToDeserializeQueryString`.
    pub struct FailedToDeserializeQueryString => BAD_REQUEST
}

#[cfg(feature = "query")]
composite_rejection! {
    /// Rejection for the [`super::Query`] extractor. Matches
    /// `axum::extract::rejection::QueryRejection`.
    pub enum QueryRejection {
        FailedToDeserializeQueryString(FailedToDeserializeQueryString),
    }
}

// --- Json ------------------------------------------------------------------

#[cfg(feature = "json")]
unit_rejection! {
    /// The request's `Content-Type` wasn't a JSON media type. Matches
    /// `axum::extract::rejection::MissingJsonContentType`.
    pub struct MissingJsonContentType => UNSUPPORTED_MEDIA_TYPE, "Expected request with `Content-Type: application/json`"
}

#[cfg(feature = "json")]
leaf_rejection! {
    /// The body was syntactically invalid JSON. Matches
    /// `axum::extract::rejection::JsonSyntaxError`.
    pub struct JsonSyntaxError => BAD_REQUEST
}

#[cfg(feature = "json")]
leaf_rejection! {
    /// The body was well-formed JSON but didn't match the target type's
    /// shape. Matches `axum::extract::rejection::JsonDataError`.
    pub struct JsonDataError => UNPROCESSABLE_ENTITY
}

#[cfg(feature = "json")]
composite_rejection! {
    /// Rejection for the [`super::Json`] extractor. Matches
    /// `axum::extract::rejection::JsonRejection`.
    pub enum JsonRejection {
        MissingJsonContentType(MissingJsonContentType),
        JsonSyntaxError(JsonSyntaxError),
        JsonDataError(JsonDataError),
        BytesRejection(BytesRejection),
    }
}

// --- Form ------------------------------------------------------------------

#[cfg(feature = "form")]
unit_rejection! {
    /// The request's `Content-Type` wasn't `application/x-www-form-urlencoded`.
    /// Matches `axum::extract::rejection::InvalidFormContentType`.
    pub struct InvalidFormContentType => UNSUPPORTED_MEDIA_TYPE, "Form requests must have `Content-Type: application/x-www-form-urlencoded`"
}

#[cfg(feature = "form")]
leaf_rejection! {
    /// A `GET`/`HEAD` request's query string didn't deserialize into the
    /// extractor's target type. Matches
    /// `axum::extract::rejection::FailedToDeserializeForm`.
    pub struct FailedToDeserializeForm => UNPROCESSABLE_ENTITY
}

#[cfg(feature = "form")]
leaf_rejection! {
    /// A non-`GET`/`HEAD` request's body didn't deserialize into the
    /// extractor's target type. Matches
    /// `axum::extract::rejection::FailedToDeserializeFormBody`.
    pub struct FailedToDeserializeFormBody => UNPROCESSABLE_ENTITY
}

#[cfg(feature = "form")]
composite_rejection! {
    /// Rejection for the [`super::Form`] extractor. Matches
    /// `axum::extract::rejection::FormRejection`.
    pub enum FormRejection {
        InvalidFormContentType(InvalidFormContentType),
        FailedToDeserializeForm(FailedToDeserializeForm),
        FailedToDeserializeFormBody(FailedToDeserializeFormBody),
        BytesRejection(BytesRejection),
    }
}

#[cfg(feature = "form")]
composite_rejection! {
    /// Rejection for the [`super::RawForm`] extractor. Matches
    /// `axum::extract::rejection::RawFormRejection`.
    pub enum RawFormRejection {
        InvalidFormContentType(InvalidFormContentType),
        BytesRejection(BytesRejection),
    }
}

// --- Extension ---------------------------------------------------------

leaf_rejection! {
    /// The requested extension type wasn't present in the request's
    /// extensions. Matches `axum::extract::rejection::MissingExtension`.
    pub struct MissingExtension => INTERNAL_SERVER_ERROR
}

composite_rejection! {
    /// Rejection for the [`super::Extension`] extractor. Matches
    /// `axum::extract::rejection::ExtensionRejection`.
    pub enum ExtensionRejection {
        MissingExtension(MissingExtension),
    }
}

// --- MatchedPath -------------------------------------------------------

#[cfg(feature = "matched-path")]
unit_rejection! {
    /// No matched route pattern was found in the request's extensions
    /// (the request never matched a route). Matches
    /// `axum::extract::rejection::MatchedPathMissing`.
    pub struct MatchedPathMissing => INTERNAL_SERVER_ERROR, "No matched path found"
}

#[cfg(feature = "matched-path")]
composite_rejection! {
    /// Rejection for the [`super::MatchedPath`] extractor. Matches
    /// `axum::extract::rejection::MatchedPathRejection`.
    pub enum MatchedPathRejection {
        MatchedPathMissing(MatchedPathMissing),
    }
}

// --- NestedPath ----------------------------------------------------------

/// The matched route wasn't nested under a prefix. Matches
/// `axum::extract::rejection::NestedPathRejection`.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct NestedPathRejection;

impl std::fmt::Display for NestedPathRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The matched route is not nested")
    }
}

impl std::error::Error for NestedPathRejection {}

impl IntoResponse for NestedPathRejection {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

// --- Multipart -------------------------------------------------------------

/// The `boundary` in a `multipart/form-data` request was missing or invalid.
///
/// Matches `axum::extract::rejection::InvalidBoundary`.
#[cfg(feature = "multipart")]
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct InvalidBoundary;

#[cfg(feature = "multipart")]
impl std::fmt::Display for InvalidBoundary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid `boundary` for `multipart/form-data` request")
    }
}

#[cfg(feature = "multipart")]
impl std::error::Error for InvalidBoundary {}

#[cfg(feature = "multipart")]
impl IntoResponse for InvalidBoundary {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

#[cfg(feature = "multipart")]
composite_rejection! {
    /// Rejection for the [`super::multipart::Multipart`] extractor.
    ///
    /// Matches `axum::extract::rejection::MultipartRejection`.
    pub enum MultipartRejection {
        InvalidBoundary(InvalidBoundary),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_rejection_from_length_limit_preserves_status() {
        let core = CoreError::status(StatusCode::PAYLOAD_TOO_LARGE, "too big");
        let rej = BytesRejection::from(core);
        assert!(matches!(
            rej,
            BytesRejection::FailedToBufferBody(FailedToBufferBody::LengthLimitError(_))
        ));
        assert_eq!(rej.into_response().status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn bytes_rejection_from_other_error_is_failed_to_buffer() {
        let core = CoreError::new(std::io::Error::other("disk on fire"));
        let rej = BytesRejection::from(core);
        assert!(matches!(rej, BytesRejection::FailedToBufferBody(_)));
        assert_eq!(rej.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_rejection_variants_map_to_expected_status_codes() {
        assert_eq!(
            JsonRejection::from(MissingJsonContentType)
                .into_response()
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            JsonRejection::from(JsonSyntaxError("x".into()))
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            JsonRejection::from(JsonDataError("x".into()))
                .into_response()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn path_rejection_display_forwards_inner_message() {
        let rej = PathRejection::from(FailedToDeserializePathParams(
            PathDeserializationError::new(ErrorKind::Message("bad id".to_string())),
        ));
        assert_eq!(rej.to_string(), "bad id");
    }
}
