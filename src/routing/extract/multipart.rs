//! Extractor for `multipart/form-data` requests (file uploads).
//!
//! Matches `axum::extract::Multipart`. Requires the `multipart` feature. Built
//! directly on [`multer`] — the same crate axum itself uses — rather than a
//! bespoke parser, so boundary/header/field parsing behavior matches byte-for-byte.

use crate::http::response::{Body, IntoResponse, Response};
use crate::routing::extract::body::max_body_size;
use crate::routing::extract::{FromRequest, rejection};
use bytes::Bytes;
use futures_core::Stream;
use http_body_util::BodyExt as _;
use hyper::StatusCode;
use hyper::header::{CONTENT_TYPE, HeaderMap};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Re-exported at the path `axum::extract::multipart` uses for them.
pub use rejection::{InvalidBoundary, MultipartRejection};

/// Extractor that parses `multipart/form-data` requests (commonly used for file uploads).
///
/// Matches `axum::extract::Multipart`. Since extracting multipart form data requires consuming the body, this
/// must be the *last* extractor in a handler's argument list.
///
/// # Example
///
/// ```rust,no_run
/// use tachyon_web::extract::Multipart;
/// use tachyon_web::{Router, post};
///
/// async fn upload(mut multipart: Multipart) {
///     while let Some(field) = multipart.next_field().await.unwrap() {
///         let name = field.name().unwrap().to_string();
///         let data = field.bytes().await.unwrap();
///         println!("Length of `{name}` is {} bytes", data.len());
///     }
/// }
///
/// let _app: Router = Router::new().route("/upload", post(upload));
/// ```
///
/// # Large files
///
/// For security reasons, this respects the same body-size limit as
/// [`Bytes`](super::super::extract::DefaultBodyLimit) — 2 MiB by default,
/// configurable via [`DefaultBodyLimit`](super::super::extract::DefaultBodyLimit).
///
/// *Axum compatibility: drop-in replacement for `axum::extract::Multipart`.*
#[derive(Debug)]
pub struct Multipart {
    inner: multer::Multipart<'static>,
}

impl<S> FromRequest<S> for Multipart
where
    S: Sync,
{
    type Rejection = rejection::MultipartRejection;

    fn from_request(
        req: hyper::Request<Body>,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready((|| {
            let boundary = content_type_str(req.headers())
                .and_then(|content_type| multer::parse_boundary(content_type).ok())
                .ok_or(rejection::InvalidBoundary)?;
            let limit = max_body_size(req.extensions());
            let limited = http_body_util::Limited::new(req.into_body(), limit);
            let multipart = multer::Multipart::new(limited.into_data_stream(), boundary);
            Ok(Self { inner: multipart })
        })())
    }
}

impl<S> super::OptionalFromRequest<S> for Multipart
where
    S: Sync,
{
    type Rejection = rejection::MultipartRejection;

    fn from_request(
        req: hyper::Request<Body>,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        std::future::ready((|| {
            let Some(content_type) = content_type_str(req.headers()) else {
                return Ok(None);
            };
            match multer::parse_boundary(content_type) {
                Ok(boundary) => {
                    let limit = max_body_size(req.extensions());
                    let limited = http_body_util::Limited::new(req.into_body(), limit);
                    let multipart = multer::Multipart::new(limited.into_data_stream(), boundary);
                    Ok(Some(Self { inner: multipart }))
                }
                Err(multer::Error::NoMultipart) => Ok(None),
                Err(_) => Err(rejection::InvalidBoundary.into()),
            }
        })())
    }
}

impl Multipart {
    /// Yields the next [`Field`] if available.
    ///
    /// # Errors
    /// Returns [`MultipartError`] if the underlying stream is malformed, the
    /// body-size limit is exceeded, or the connection is interrupted.
    pub async fn next_field(&mut self) -> Result<Option<Field<'_>>, MultipartError> {
        let field = self
            .inner
            .next_field()
            .await
            .map_err(MultipartError::from_multer)?;
        Ok(field.map(|inner| Field {
            inner,
            _multipart: self,
        }))
    }
}

/// A single field in a multipart stream.
///
/// Matches `axum::extract::multipart::Field`.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::multipart::Field`.*
#[derive(Debug)]
pub struct Field<'a> {
    inner: multer::Field<'static>,
    // multer requires there to only be one live `multer::Field` at any point; borrowing
    // `Multipart` here enforces that statically instead of multer's own runtime error.
    _multipart: &'a mut Multipart,
}

impl Stream for Field<'_> {
    type Item = Result<Bytes, MultipartError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner)
            .poll_next(cx)
            .map_err(MultipartError::from_multer)
    }
}

impl Field<'_> {
    /// The field name found in the `Content-Disposition` header.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.inner.name()
    }

    /// The file name found in the `Content-Disposition` header.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.inner.file_name()
    }

    /// The field's `Content-Type`, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.inner.content_type().map(AsRef::as_ref)
    }

    /// The field's headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// Get the full data of the field as [`Bytes`].
    ///
    /// # Errors
    /// Returns [`MultipartError`] if the underlying stream is malformed, the
    /// body-size limit is exceeded, or the connection is interrupted.
    pub async fn bytes(self) -> Result<Bytes, MultipartError> {
        self.inner
            .bytes()
            .await
            .map_err(MultipartError::from_multer)
    }

    /// Get the full field data as text.
    ///
    /// # Errors
    /// Returns [`MultipartError`] if the field isn't valid UTF-8, or for the
    /// same reasons as [`Field::bytes`].
    pub async fn text(self) -> Result<String, MultipartError> {
        self.inner.text().await.map_err(MultipartError::from_multer)
    }

    /// Stream a chunk of the field data. Returns `None` once exhausted.
    ///
    /// Does the same thing as `Field`'s `Stream` implementation.
    ///
    /// # Errors
    /// Returns [`MultipartError`] for the same reasons as [`Field::bytes`].
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, MultipartError> {
        self.inner
            .chunk()
            .await
            .map_err(MultipartError::from_multer)
    }
}

/// Errors associated with parsing `multipart/form-data` requests.
///
/// Matches `axum::extract::multipart::MultipartError`.
///
/// *Axum compatibility: drop-in replacement for `axum::extract::multipart::MultipartError`.*
#[derive(Debug)]
pub struct MultipartError {
    source: multer::Error,
}

impl MultipartError {
    const fn from_multer(source: multer::Error) -> Self {
        Self { source }
    }

    /// Get the response body text used for this rejection.
    #[must_use]
    pub fn body_text(&self) -> String {
        if is_body_limit_error(&self.source) {
            "Request payload is too large".to_string()
        } else {
            self.source.to_string()
        }
    }

    /// Get the status code used for this rejection.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        status_code_from_multer_error(&self.source)
    }
}

fn status_code_from_multer_error(err: &multer::Error) -> StatusCode {
    match err {
        multer::Error::UnknownField { .. }
        | multer::Error::IncompleteFieldData { .. }
        | multer::Error::IncompleteHeaders
        | multer::Error::ReadHeaderFailed(..)
        | multer::Error::DecodeHeaderName { .. }
        | multer::Error::DecodeContentType(..)
        | multer::Error::NoBoundary
        | multer::Error::DecodeHeaderValue { .. }
        | multer::Error::NoMultipart
        | multer::Error::IncompleteStream => StatusCode::BAD_REQUEST,
        multer::Error::FieldSizeExceeded { .. } | multer::Error::StreamSizeExceeded { .. } => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        multer::Error::StreamReadFailed(err) => {
            if let Some(err) = err.downcast_ref::<multer::Error>() {
                return status_code_from_multer_error(err);
            }
            if err
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                return StatusCode::PAYLOAD_TOO_LARGE;
            }
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn is_body_limit_error(err: &multer::Error) -> bool {
    match err {
        multer::Error::FieldSizeExceeded { .. } | multer::Error::StreamSizeExceeded { .. } => true,
        multer::Error::StreamReadFailed(err) => {
            err.downcast_ref::<multer::Error>()
                .is_some_and(is_body_limit_error)
                || err
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
        }
        _ => false,
    }
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Error parsing `multipart/form-data` request")
    }
}

impl std::error::Error for MultipartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl IntoResponse for MultipartError {
    fn into_response(self) -> Response {
        let status = self.status();
        (status, self.body_text()).into_response()
    }
}

fn content_type_str(headers: &HeaderMap) -> Option<&str> {
    headers.get(CONTENT_TYPE)?.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::extract::FromRequest;
    use tokio_stream::StreamExt as _;

    fn multipart_body(boundary: &str, name: &str, filename: &str, content: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        body
    }

    #[tokio::test]
    async fn reads_a_single_field() {
        let boundary = "X-BOUNDARY";
        let body = multipart_body(boundary, "file", "hello.txt", b"hello world");

        let req = hyper::Request::builder()
            .method("POST")
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::full(Bytes::from(body)))
            .unwrap();

        let mut multipart = Multipart::from_request(req, &()).await.unwrap();
        let field = multipart.next_field().await.unwrap().unwrap();
        assert_eq!(field.name(), Some("file"));
        assert_eq!(field.file_name(), Some("hello.txt"));
        assert_eq!(field.bytes().await.unwrap(), &b"hello world"[..]);

        assert!(multipart.next_field().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn field_implements_stream() {
        let boundary = "X-BOUNDARY";
        let body = multipart_body(boundary, "file", "hello.txt", b"streamed");

        let req = hyper::Request::builder()
            .method("POST")
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::full(Bytes::from(body)))
            .unwrap();

        let mut multipart = Multipart::from_request(req, &()).await.unwrap();
        let field = multipart.next_field().await.unwrap().unwrap();
        let chunks: Vec<Bytes> = field.map(Result::unwrap).collect().await;
        let joined: Vec<u8> = chunks.concat();
        assert_eq!(joined, b"streamed");
    }

    #[tokio::test]
    async fn missing_content_type_is_rejected_as_invalid_boundary() {
        let req = hyper::Request::builder()
            .method("POST")
            .body(Body::full(Bytes::from_static(b"irrelevant")))
            .unwrap();

        let err = Multipart::from_request(req, &()).await.unwrap_err();
        assert!(matches!(
            err,
            rejection::MultipartRejection::InvalidBoundary(_)
        ));
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oversized_field_is_rejected_as_413() {
        let boundary = "X-BOUNDARY";
        let body = multipart_body(boundary, "file", "big.bin", &[0u8; 64]);

        let req = hyper::Request::builder()
            .method("POST")
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::full(Bytes::from(body)))
            .unwrap();
        let mut req = req;
        let _ = req
            .extensions_mut()
            .insert(crate::routing::extract::MaxBodySize(16));

        let mut multipart = Multipart::from_request(req, &()).await.unwrap();
        let err = multipart.next_field().await.unwrap_err();
        assert_eq!(err.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.body_text(), "Request payload is too large");
    }

    #[tokio::test]
    async fn option_multipart_is_none_without_a_multipart_content_type() {
        let req = hyper::Request::builder()
            .method("POST")
            .body(Body::empty())
            .unwrap();

        let multipart = Option::<Multipart>::from_request(req, &()).await.unwrap();
        assert!(multipart.is_none());
    }
}
