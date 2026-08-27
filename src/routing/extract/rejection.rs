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

/// The request body could not be read to completion (I/O error, malformed
/// chunked transfer, a body-read deadline expiring, ...). Matches
/// `axum_core::extract::rejection::FailedToBufferBody`.
///
/// Unlike a `leaf_rejection!`-generated type, this carries its own status
/// code rather than a fixed one: the underlying [`CoreError`] this is built
/// from can legitimately be any status (e.g. a `408 Request Timeout` from a
/// body-read deadline, not just a generic `400`), and collapsing that to a
/// fixed code would silently change the response your client actually sees.
pub struct FailedToBufferBody {
    status: StatusCode,
    message: String,
}

impl std::fmt::Debug for FailedToBufferBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailedToBufferBody")
            .field("status", &self.status)
            .field("message", &self.message)
            .finish()
    }
}

impl std::fmt::Display for FailedToBufferBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FailedToBufferBody {}

impl IntoResponse for FailedToBufferBody {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

composite_rejection! {
    /// Rejection for the raw [`bytes::Bytes`] extractor. Matches
    /// `axum_core::extract::rejection::BytesRejection`.
    pub enum BytesRejection {
        LengthLimitError(LengthLimitError),
        FailedToBufferBody(FailedToBufferBody),
    }
}

impl From<CoreError> for BytesRejection {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Rejection { status, message } if status == StatusCode::PAYLOAD_TOO_LARGE => {
                Self::LengthLimitError(LengthLimitError(message))
            }
            CoreError::Rejection { status, message } => {
                Self::FailedToBufferBody(FailedToBufferBody { status, message })
            }
            other @ CoreError::Internal(_) => Self::FailedToBufferBody(FailedToBufferBody {
                status: StatusCode::BAD_REQUEST,
                message: other.to_string(),
            }),
        }
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
        BytesRejection(BytesRejection),
        InvalidUtf8(InvalidUtf8),
    }
}

// --- Path --------------------------------------------------------------

leaf_rejection! {
    /// The path parameters didn't deserialize into the extractor's target
    /// type. Matches `axum::extract::path::FailedToDeserializePathParams`.
    pub struct FailedToDeserializePathParams => BAD_REQUEST
}

leaf_rejection! {
    /// The route matched but no path-parameter extension was present at all
    /// — an internal routing bug rather than a client error. Matches
    /// `axum::extract::rejection::MissingPathParams`.
    pub struct MissingPathParams => INTERNAL_SERVER_ERROR
}

composite_rejection! {
    /// Rejection for the [`super::Path`] extractor. Matches
    /// `axum::extract::rejection::PathRejection`.
    pub enum PathRejection {
        FailedToDeserializePathParams(FailedToDeserializePathParams),
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
leaf_rejection! {
    /// The request's `Content-Type` wasn't a JSON media type. Matches
    /// `axum::extract::rejection::MissingJsonContentType`.
    pub struct MissingJsonContentType => UNSUPPORTED_MEDIA_TYPE
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
leaf_rejection! {
    /// The request's `Content-Type` wasn't `application/x-www-form-urlencoded`.
    /// Matches `axum::extract::rejection::InvalidFormContentType`.
    pub struct InvalidFormContentType => UNSUPPORTED_MEDIA_TYPE
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
leaf_rejection! {
    /// No matched route pattern was found in the request's extensions
    /// (the request never matched a route). Matches
    /// `axum::extract::rejection::MatchedPathMissing`.
    pub struct MatchedPathMissing => INTERNAL_SERVER_ERROR
}

#[cfg(feature = "matched-path")]
composite_rejection! {
    /// Rejection for the [`super::MatchedPath`] extractor. Matches
    /// `axum::extract::rejection::MatchedPathRejection`.
    pub enum MatchedPathRejection {
        MatchedPathMissing(MatchedPathMissing),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_rejection_from_length_limit_preserves_status() {
        let core = CoreError::Rejection {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: "too big".to_string(),
        };
        let rej = BytesRejection::from(core);
        assert!(matches!(rej, BytesRejection::LengthLimitError(_)));
        assert_eq!(rej.into_response().status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn bytes_rejection_from_other_error_is_failed_to_buffer() {
        let core = CoreError::Internal("disk on fire".to_string());
        let rej = BytesRejection::from(core);
        assert!(matches!(rej, BytesRejection::FailedToBufferBody(_)));
        assert_eq!(rej.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_rejection_variants_map_to_expected_status_codes() {
        assert_eq!(
            JsonRejection::from(MissingJsonContentType("x".into()))
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
        let rej = PathRejection::from(FailedToDeserializePathParams("bad id".into()));
        assert_eq!(rej.to_string(), "bad id");
    }
}
