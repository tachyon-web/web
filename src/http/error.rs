//! Error types for the Tachyon-Web framework.

use bytes::Bytes;
use hyper::{Response, StatusCode};

use crate::http::response::IntoResponse;

/// A specialized Result type for Tachyon-Web operations.
///
/// *Tachyon extension: no `axum` equivalent.*
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A type-erased, boxed `std::error::Error`. Matches `axum_core::BoxError`.
///
/// *Axum compatibility: drop-in replacement for `axum::BoxError`.*
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An opaque, boxed error, matching `axum_core::Error` exactly (a plain struct wrapping
/// [`BoxError`] in a private field).
///
/// A failure from an unpredictable, foreign source (an arbitrary `tower::Service`, a user's
/// body stream) has no HTTP semantics of its own, so converting it to a response is always a
/// generic `500`, same as axum.
///
/// A handful of this crate's *own* internal signals (a body-read timeout, an oversized
/// body) still need a specific status to survive the trip through [`crate::http::response::Body`]'s
/// `Error` associated type (this same type) before reaching [`crate::http::response::Body::collect_bytes`]
/// or an `IntoResponse` call site — tachyon's body layer routes those through here rather
/// than a separate side channel. That's handled by boxing a private `StatusError` and
/// downcasting it back out where needed (see `Error::status`/`Error::as_status`); it's
/// never exposed as a public variant, so from the outside `Error` is exactly as opaque as
/// axum's.
///
/// *Axum compatibility: drop-in replacement for `axum::Error`.*
#[derive(Debug)]
pub struct Error {
    inner: BoxError,
}

impl Error {
    /// Wraps any boxable error as an opaque `Error`. Matches `axum_core::Error::new`.
    pub fn new(error: impl Into<BoxError>) -> Self {
        Self {
            inner: error.into(),
        }
    }

    /// Converts an `Error` back into the underlying boxed trait object. Matches
    /// `axum_core::Error::into_inner`.
    #[must_use]
    pub fn into_inner(self) -> BoxError {
        self.inner
    }

    /// Builds an `Error` that still carries a specific status/message through the opaque
    /// channel, for the internal call sites that need one (a body-read timeout, an
    /// oversized body, ...). Not part of the public API surface — external code that wants
    /// a status-carrying failure should use one of the per-extractor rejection types in
    /// [`crate::routing::extract::rejection`] instead.
    pub(crate) fn status(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            inner: Box::new(StatusError {
                status,
                message: message.into(),
            }),
        }
    }

    /// Builds a genuinely opaque `Error` from a plain message, for the many internal call
    /// sites (WebSocket frame-protocol violations, HTTP/2 stream errors, ...) that previously
    /// built `Error::Internal(msg)` — these have no defined client-facing status, so they
    /// render as a generic `500` via [`IntoResponse for Error`](#impl-IntoResponse-for-Error)
    /// same as any other opaque error.
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            inner: Box::new(Message(message.into())),
        }
    }

    /// Recovers the `(status, message)` this `Error` was built with via [`Error::status`],
    /// if any — `None` for a genuinely opaque error with no defined HTTP semantics.
    pub(crate) fn as_status(&self) -> Option<(StatusCode, &str)> {
        self.inner
            .downcast_ref::<StatusError>()
            .map(|e| (e.status, e.message.as_str()))
    }
}

/// The private payload boxed inside [`Error`] by [`Error::status`]. Deliberately not a
/// public variant — see the type-level docs on [`Error`].
#[derive(Debug)]
struct StatusError {
    status: StatusCode,
    message: String,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.status,
            self.status.as_u16(),
            self.message
        )
    }
}

impl std::error::Error for StatusError {}

/// A plain string wrapped as a [`std::error::Error`], for [`Error::internal`].
#[derive(Debug)]
struct Message(String);

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Message {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(e)
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(e: std::convert::Infallible) -> Self {
        match e {}
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self::new(e)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response<crate::http::response::Body> {
        let (status, body) = if let Some((status, message)) = self.as_status() {
            (status, Bytes::from(message.to_string()))
        } else {
            // The message is deliberately not echoed to the client for a genuinely opaque
            // error — it's logged server-side and replaced with a generic body, since it
            // can carry internals.
            tracing::error!("internal error: {self}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(b"Internal Server Error"),
            )
        };
        let mut resp =
            crate::http::response::with_content_type(body, crate::http::response::TEXT_PLAIN);
        *resp.status_mut() = status;
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err1 = Error::status(StatusCode::BAD_REQUEST, "bad");
        assert_eq!(err1.to_string(), "400 Bad Request (400): bad");

        let err2 = Error::new(std::io::Error::other("oops"));
        assert_eq!(err2.to_string(), "oops");
    }

    #[test]
    fn test_error_into_response() {
        let err1 = Error::status(StatusCode::NOT_FOUND, "not found");
        let resp1 = err1.into_response();
        assert_eq!(resp1.status(), StatusCode::NOT_FOUND);

        let err2 = Error::new(std::io::Error::other("failure"));
        let resp2 = err2.into_response();
        assert_eq!(resp2.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn io_error_converts_to_opaque_error() {
        let io_err = std::io::Error::other("disk on fire");
        let err: Error = io_err.into();
        assert!(err.as_status().is_none());
        assert!(err.to_string().contains("disk on fire"));
    }

    /// `hyper::Error` has no public constructor, so the only way to get a real one is to
    /// actually drive a connection into a parse error — a malformed request line over an
    /// in-memory duplex pipe, no real socket needed.
    #[cfg(feature = "http1")]
    #[tokio::test]
    async fn hyper_error_converts_to_opaque_error() {
        use tokio::io::AsyncWriteExt;

        let (mut client_io, server_io) = tokio::io::duplex(1024);
        let svc = hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
            Ok::<_, std::io::Error>(Response::new(crate::http::response::Body::empty()))
        });
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(server_io), svc)
                .await
        });

        client_io
            .write_all(b"not a valid http request at all\r\n\r\n")
            .await
            .expect("write garbage");
        client_io.shutdown().await.expect("shutdown write half");

        let hyper_err = server
            .await
            .expect("server task join")
            .expect_err("malformed request line must fail to parse");
        let err: Error = hyper_err.into();
        assert!(err.as_status().is_none());
    }

    #[test]
    fn status_error_round_trips_through_as_status() {
        let err = Error::status(StatusCode::IM_A_TEAPOT, "short and stout");
        let (status, message) = err.as_status().expect("built via Error::status");
        assert_eq!(status, StatusCode::IM_A_TEAPOT);
        assert_eq!(message, "short and stout");
    }
}
