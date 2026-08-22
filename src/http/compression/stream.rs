//! The streaming half of response compression.
//!
//! A body of unknown length can't be compressed in one shot (see `codec.rs` for that path),
//! so it goes through `async-compression`'s `tokio::bufread` encoders instead: the frame
//! source becomes an `AsyncRead` via `tokio_util::io::StreamReader`, the encoder wraps that,
//! and `tokio_util::io::ReaderStream` turns the compressed output back into frames. This
//! delegates all flush/frame-boundary handling — previously a hand-rolled state machine — to
//! a widely used crate, at the cost of the async plumbing below to carry trailers across it
//! (a body's trailers, if any, arrive only after the last data frame).
//!
//! Level and window parameters are computed the same way as the one-shot path in `codec.rs`,
//! so the two compress identically — `async-compression`'s own per-codec defaults are not
//! used, for the same reasons documented on [`super::CompressionLevel`].

use super::{CompressionLevel, Encoding};
use crate::http::response::Body;
use bytes::Bytes;
use hyper::HeaderMap;
use hyper::body::{Body as HyperBody, Frame};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, BufReader};
use tokio_util::io::{ReaderStream, StreamReader};

pin_project_lite::pin_project! {
    /// Adapts a [`Body`]'s data frames into the `io::Result<Bytes>` items
    /// [`StreamReader`] wants, stashing any trailers for [`WithTrailers`] to re-emit once
    /// the compressed stream ends.
    struct DataFrames {
        #[pin]
        inner: Body,
        trailers: Arc<Mutex<Option<HeaderMap>>>,
    }
}

impl futures_core::Stream for DataFrames {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            return match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) if data.is_empty() => continue,
                    Ok(data) => Poll::Ready(Some(Ok(data))),
                    Err(non_data) => {
                        if let Ok(trailers) = non_data.into_trailers() {
                            *this.trailers.lock().unwrap_or_else(PoisonError::into_inner) =
                                Some(trailers);
                        }
                        continue;
                    }
                },
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(io::Error::other(e)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

pin_project_lite::pin_project! {
    /// Turns a compressed-byte stream into `Frame`s, appending one trailers frame — if the
    /// source body had any — once the stream ends.
    struct WithTrailers<S> {
        #[pin]
        inner: S,
        trailers: Arc<Mutex<Option<HeaderMap>>>,
        done: bool,
    }
}

impl<S: futures_core::Stream<Item = io::Result<Bytes>>> futures_core::Stream for WithTrailers<S> {
    type Item = Result<Frame<Bytes>, crate::http::error::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(
                this.trailers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                    .map(Frame::trailers)
                    .map(Ok),
            );
        }
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => {
                *this.done = true;
                Poll::Ready(
                    this.trailers
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take()
                        .map(Frame::trailers)
                        .map(Ok),
                )
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Wraps `inner` in a streaming compressor for `encoding`, or hands it back unchanged
/// (`Err`) if this build has no codec for it. The returned body's length is unknowable up
/// front.
pub(super) fn compressed_body(
    inner: Body,
    encoding: Encoding,
    level: CompressionLevel,
) -> Result<Body, Body> {
    if !encoding.encoder_available() || encoding == Encoding::Identity {
        return Err(inner);
    }

    let trailers = Arc::new(Mutex::new(None));
    let reader = BufReader::new(StreamReader::new(DataFrames {
        inner,
        trailers: Arc::clone(&trailers),
    }));

    let read: Pin<Box<dyn AsyncRead + Send>> = match encoding {
        #[cfg(feature = "compression-gzip")]
        Encoding::Gzip => Box::pin(
            async_compression::tokio::bufread::GzipEncoder::with_quality(
                reader,
                flate_level(level),
            ),
        ),
        #[cfg(feature = "compression-deflate")]
        Encoding::Deflate => Box::pin(
            async_compression::tokio::bufread::ZlibEncoder::with_quality(
                reader,
                flate_level(level),
            ),
        ),
        #[cfg(feature = "compression-br")]
        Encoding::Brotli => {
            let params = async_compression::brotli::EncoderParams::default()
                .quality(async_compression::Level::Precise(
                    i32::try_from(level.brotli()).unwrap_or(4),
                ))
                .window_size(i32::try_from(super::codec::BROTLI_WINDOW_LOG).unwrap_or(22));
            Box::pin(async_compression::tokio::bufread::BrotliEncoder::with_params(reader, params))
        }
        #[cfg(feature = "compression-zstd")]
        Encoding::Zstd => {
            let zstd_level = level.zstd();
            let params: &[_] = if zstd_level >= super::codec::ZSTD_WINDOW_CLAMP_FROM {
                &[async_compression::zstd::CParameter::window_log(
                    super::codec::ZSTD_MAX_WINDOW_LOG,
                )]
            } else {
                &[]
            };
            Box::pin(
                async_compression::tokio::bufread::ZstdEncoder::with_quality_and_params(
                    reader,
                    async_compression::Level::Precise(zstd_level),
                    params,
                ),
            )
        }
        // Reached only if `encoder_available` disagreed with which codecs are actually
        // compiled in above — every reachable arm is feature-gated to match it exactly.
        #[allow(unreachable_patterns)]
        _ => unreachable!("{encoding} has no encoder compiled in"),
    };

    let frames = WithTrailers {
        inner: ReaderStream::new(read),
        trailers,
        done: false,
    };
    Ok(Body::stream(http_body_util::StreamBody::new(frames)))
}

/// [`CompressionLevel::flate`] wrapped as an `async-compression` level, for gzip/zlib.
#[cfg(any(feature = "compression-gzip", feature = "compression-deflate"))]
fn flate_level(level: CompressionLevel) -> async_compression::Level {
    async_compression::Level::Precise(i32::try_from(level.flate()).unwrap_or(6))
}
