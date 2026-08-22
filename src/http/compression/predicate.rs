//! Predicates for disabling compression of responses.
//!
//! Mirrors `tower_http::compression::predicate` type-for-type, so predicate code written
//! against `tower-http`/`axum` compiles unchanged against this module. Predicates are
//! applied with [`Compression::compress_when`](super::Compression::compress_when).

use crate::http::response::Body;
use hyper::body::Body as HyperBody;
use hyper::header::CONTENT_LENGTH;
use hyper::http::Extensions;
use hyper::{HeaderMap, Response, StatusCode, Version};
use std::sync::Arc;

/// Predicate used to determine if a response should be compressed or not.
pub trait Predicate: Send + Sync + 'static {
    /// Should this response be compressed?
    fn should_compress(&self, response: &Response<Body>) -> bool;

    /// Combines two predicates into one that compresses only when both do.
    fn and<Other>(self, other: Other) -> And<Self, Other>
    where
        Self: Sized,
        Other: Predicate,
    {
        And {
            lhs: self,
            rhs: other,
        }
    }
}

impl<F> Predicate for F
where
    F: Fn(StatusCode, Version, &HeaderMap, &Extensions) -> bool + Send + Sync + 'static,
{
    fn should_compress(&self, response: &Response<Body>) -> bool {
        self(
            response.status(),
            response.version(),
            response.headers(),
            response.extensions(),
        )
    }
}

/// Two predicates combined into one — compresses only when both would.
///
/// Created with [`Predicate::and`].
#[derive(Debug, Clone, Copy)]
pub struct And<Lhs, Rhs> {
    lhs: Lhs,
    rhs: Rhs,
}

impl<Lhs, Rhs> Predicate for And<Lhs, Rhs>
where
    Lhs: Predicate,
    Rhs: Predicate,
{
    fn should_compress(&self, response: &Response<Body>) -> bool {
        self.lhs.should_compress(response) && self.rhs.should_compress(response)
    }
}

/// [`Predicate`] that only allows compression of responses at or above a certain size.
#[derive(Debug, Clone, Copy)]
pub struct SizeAbove(u16);

impl SizeAbove {
    /// [`Compression::compress_when`](super::Compression::compress_when)'s default: 32 bytes,
    /// matching `tower-http`.
    pub const DEFAULT_MIN_SIZE: u16 = 32;

    /// Creates a `SizeAbove` that only compresses responses larger than `min_size_bytes`.
    ///
    /// A response is compressed if its exact size can't be determined through either
    /// `Content-Length` or `Body::size_hint`.
    #[must_use]
    pub const fn new(min_size_bytes: u16) -> Self {
        Self(min_size_bytes)
    }
}

impl Default for SizeAbove {
    fn default() -> Self {
        Self(Self::DEFAULT_MIN_SIZE)
    }
}

impl Predicate for SizeAbove {
    fn should_compress(&self, response: &Response<Body>) -> bool {
        let content_size = response.body().size_hint().exact().or_else(|| {
            response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
        });
        content_size.is_none_or(|size| size >= u64::from(self.0))
    }
}

/// [`Predicate`] that won't allow responses with a specific `Content-Type` to be compressed.
#[derive(Debug, Clone)]
pub struct NotForContentType {
    content_type: Str,
    exception: Option<Str>,
}

impl NotForContentType {
    /// Won't compress gRPC responses.
    pub const GRPC: Self = Self {
        content_type: Str::Static("application/grpc"),
        exception: Some(Str::Static("application/grpc-web")),
    };

    /// Won't compress images (`image/svg+xml` excepted — it's text).
    pub const IMAGES: Self = Self {
        content_type: Str::Static("image/"),
        exception: Some(Str::Static("image/svg+xml")),
    };

    /// Won't compress Server-Sent Events responses.
    pub const SSE: Self = Self::const_new("text/event-stream");

    /// Creates a new `NotForContentType` from a runtime string.
    #[must_use]
    pub fn new(content_type: &str) -> Self {
        Self {
            content_type: Str::Shared(Arc::from(content_type)),
            exception: None,
        }
    }

    /// Creates a new `NotForContentType` from a static string.
    #[must_use]
    pub const fn const_new(content_type: &'static str) -> Self {
        Self {
            content_type: Str::Static(content_type),
            exception: None,
        }
    }
}

impl Predicate for NotForContentType {
    fn should_compress(&self, response: &Response<Body>) -> bool {
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if let Some(exception) = &self.exception
            && content_type.starts_with(exception.as_str())
        {
            return true;
        }
        !content_type.starts_with(self.content_type.as_str())
    }
}

#[derive(Debug, Clone)]
enum Str {
    Static(&'static str),
    Shared(Arc<str>),
}

impl Str {
    fn as_str(&self) -> &str {
        match self {
            Self::Static(s) => s,
            Self::Shared(s) => s,
        }
    }
}

/// The default predicate: [`Compression::new`](super::Compression::new)'s starting point.
///
/// Compresses everything at least [`SizeAbove::DEFAULT_MIN_SIZE`] bytes, except gRPC, images
/// (`image/svg+xml` excepted), and Server-Sent Events.
#[derive(Debug, Clone)]
pub struct DefaultPredicate(
    And<And<And<SizeAbove, NotForContentType>, NotForContentType>, NotForContentType>,
);

impl DefaultPredicate {
    /// Creates a new `DefaultPredicate`.
    #[must_use]
    pub fn new() -> Self {
        Self(
            SizeAbove::default()
                .and(NotForContentType::GRPC)
                .and(NotForContentType::IMAGES)
                .and(NotForContentType::SSE),
        )
    }
}

impl Default for DefaultPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl Predicate for DefaultPredicate {
    fn should_compress(&self, response: &Response<Body>) -> bool {
        self.0.should_compress(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn response_with(content_type: &str, len: usize) -> Response<Body> {
        Response::builder()
            .header(hyper::header::CONTENT_TYPE, content_type)
            .body(Body::full(Bytes::from(vec![b'x'; len])))
            .unwrap()
    }

    #[test]
    fn size_above_gates_on_exact_size() {
        let predicate = SizeAbove::new(100);
        assert!(!predicate.should_compress(&response_with("text/plain", 10)));
        assert!(predicate.should_compress(&response_with("text/plain", 200)));
    }

    #[test]
    fn not_for_content_type_excepts_the_declared_prefix() {
        assert!(!NotForContentType::IMAGES.should_compress(&response_with("image/png", 1000)));
        assert!(NotForContentType::IMAGES.should_compress(&response_with("image/svg+xml", 1000)));
        assert!(!NotForContentType::GRPC.should_compress(&response_with("application/grpc", 1000)));
        assert!(
            NotForContentType::GRPC.should_compress(&response_with("application/grpc-web", 1000))
        );
    }

    #[test]
    fn and_requires_both_sides() {
        let predicate = SizeAbove::new(100).and(NotForContentType::SSE);
        assert!(!predicate.should_compress(&response_with("text/event-stream", 1000)));
        assert!(!predicate.should_compress(&response_with("text/plain", 10)));
        assert!(predicate.should_compress(&response_with("text/plain", 1000)));
    }

    #[test]
    fn default_predicate_matches_documented_behaviour() {
        let predicate = DefaultPredicate::new();
        assert!(predicate.should_compress(&response_with("text/plain", 1000)));
        assert!(!predicate.should_compress(&response_with("text/plain", 10)));
        assert!(!predicate.should_compress(&response_with("image/png", 1000)));
        assert!(!predicate.should_compress(&response_with("application/grpc", 1000)));
        assert!(!predicate.should_compress(&response_with("text/event-stream", 1000)));
    }
}
