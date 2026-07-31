//! Error types for the Tachyon-Web framework.

use bytes::Bytes;
use hyper::{Response, StatusCode};

use crate::http::response::IntoResponse;

/// A specialized Result type for Tachyon-Web operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Represents errors that can occur during request processing, routing, or extraction.
#[derive(Debug, Clone)]
pub enum Error {
    /// A client error resulting in an HTTP status code and a descriptive message.
    Rejection {
        /// The HTTP status code to return.
        status: StatusCode,
        /// The descriptive error message.
        message: String,
    },
    /// An internal server error.
    Internal(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejection { status, message } => write!(f, "Rejection ({status}): {message}"),
            Self::Internal(msg) => write!(f, "Internal Error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(e: std::convert::Infallible) -> Self {
        match e {}
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response<crate::http::response::Body> {
        match self {
            Self::Rejection { status, message } => Response::builder()
                .status(status)
                .header("content-type", "text/plain; charset=utf-8")
                .body(crate::http::response::Body::full(Bytes::from(message)))
                .unwrap_or_else(|_| Response::new(crate::http::response::Body::empty())),
            Self::Internal(msg) => {
                tracing::error!("internal error: {msg}");
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "text/plain; charset=utf-8")
                    .body(crate::http::response::Body::full(Bytes::from_static(
                        b"Internal Server Error",
                    )))
                    .unwrap_or_else(|_| Response::new(crate::http::response::Body::empty()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err1 = Error::Rejection {
            status: StatusCode::BAD_REQUEST,
            message: "bad".to_string(),
        };
        assert_eq!(err1.to_string(), "Rejection (400 Bad Request): bad");

        let err2 = Error::Internal("oops".to_string());
        assert_eq!(err2.to_string(), "Internal Error: oops");
    }

    #[test]
    fn test_error_into_response() {
        let err1 = Error::Rejection {
            status: StatusCode::NOT_FOUND,
            message: "not found".to_string(),
        };
        let resp1 = err1.into_response();
        assert_eq!(resp1.status(), StatusCode::NOT_FOUND);

        let err2 = Error::Internal("failure".to_string());
        let resp2 = err2.into_response();
        assert_eq!(resp2.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn io_error_converts_to_internal() {
        let io_err = std::io::Error::other("disk on fire");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Internal(msg) if msg.contains("disk on fire")));
    }

    /// `hyper::Error` has no public constructor, so the only way to get a real one is to
    /// actually drive a connection into a parse error — a malformed request line over an
    /// in-memory duplex pipe, no real socket needed.
    #[cfg(feature = "http1")]
    #[tokio::test]
    async fn hyper_error_converts_to_internal() {
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
        assert!(matches!(err, Error::Internal(_)));
    }
}
