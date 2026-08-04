//! The codec layer behind [`Compression`](super::Compression).
//!
//! One `Write`-shaped adapter per content coding, all writing into a `Vec<u8>` the caller
//! drains between frames. Deliberately synchronous: an async-compression wrapper would add
//! an `AsyncRead`/`Stream` conversion on both sides of a codec that is pure CPU work, and
//! [`super::Compression`] already decides — via `blocking_threshold` — where that work runs.

use super::Encoding;
#[cfg(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
))]
use std::io::Write;

/// The compression quality/speed tradeoff, mapped onto each codec's own scale.
///
/// Named to match `tower-http`'s type of the same name so an `axum` migration keeps
/// working; the numeric mappings differ where `tower-http`'s defaults are a poor fit for
/// per-request compression, and each variant documents what it actually resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionLevel {
    /// The cheapest setting each codec offers: gzip/deflate 1, Brotli 1, zstd 1.
    ///
    /// The right choice for large dynamic responses on a busy server, where the bytes
    /// saved past this point cost more CPU than they save transmission time.
    Fastest,
    /// The best ratio worth using on a server: gzip/deflate 9, Brotli 11, zstd 19.
    ///
    /// zstd stops at 19 rather than its true maximum of 22 — levels 20-22 need hundreds of
    /// megabytes of encoder state per stream, which is a denial-of-service vector when one
    /// exists per in-flight response. Pass [`CompressionLevel::Precise`] to override.
    Best,
    /// A middle setting tuned per codec: gzip/deflate 6, Brotli 4, zstd 3.
    ///
    /// Brotli sits at 4 rather than its nominal default of 11: quality 11 is an order of
    /// magnitude slower and is meant for assets compressed once ahead of time, not for a
    /// body built per request.
    Default,
    /// An exact level, clamped to the codec's valid range — 0-9 for gzip and deflate,
    /// 0-11 for Brotli, 1-22 for zstd.
    Precise(i32),
}

impl CompressionLevel {
    /// Level for gzip and deflate, in flate2's 0-9 range.
    #[cfg(any(feature = "compression-gzip", feature = "compression-deflate"))]
    fn flate(self) -> u32 {
        match self {
            Self::Fastest => 1,
            Self::Best => 9,
            Self::Default => 6,
            Self::Precise(level) => level.clamp(0, 9).unsigned_abs(),
        }
    }

    /// Quality for Brotli, in its 0-11 range.
    #[cfg(feature = "compression-br")]
    fn brotli(self) -> u32 {
        match self {
            Self::Fastest => 1,
            Self::Best => 11,
            Self::Default => 4,
            Self::Precise(level) => level.clamp(0, 11).unsigned_abs(),
        }
    }

    /// Level for zstd, in its 1-22 range.
    #[cfg(feature = "compression-zstd")]
    fn zstd(self) -> i32 {
        match self {
            Self::Fastest => 1,
            Self::Best => 19,
            Self::Default => 3,
            Self::Precise(level) => level.clamp(1, 22),
        }
    }
}

/// Brotli's sliding-window size, as a power of two: 4 MiB.
///
/// [RFC 7932 §9.1] permits up to `lgwin` 24, but a decoder only has to support the window
/// the encoder actually declares, and 22 is what every browser and CDN encodes at. Raising
/// it costs encoder memory per in-flight response for a fraction of a percent of ratio.
///
/// [RFC 7932 §9.1]: https://www.rfc-editor.org/rfc/rfc7932#section-9.1
#[cfg(feature = "compression-br")]
const BROTLI_WINDOW_LOG: u32 = 22;

/// Size of Brotli's internal output staging buffer.
#[cfg(feature = "compression-br")]
const BROTLI_BUFFER_SIZE: usize = 8 * 1024;

/// The largest zstd window a browser will decode, as a power of two: 8 MiB.
///
/// Chrome rejects a frame whose header declares a larger window, and so — with varying
/// limits — do other decoders. zstd picks the window from the compression level, and
/// levels above 19 exceed this, producing a stream that decodes perfectly in `curl` and
/// fails in the browser. This is the single most common way to ship a broken
/// `Content-Encoding: zstd`, so the window is clamped rather than left to the level.
#[cfg(feature = "compression-zstd")]
const ZSTD_MAX_WINDOW_LOG: u32 = 23;

/// The lowest zstd level whose default window exceeds [`ZSTD_MAX_WINDOW_LOG`].
#[cfg(feature = "compression-zstd")]
const ZSTD_WINDOW_CLAMP_FROM: i32 = 19;

/// A configured encoder writing into an owned output buffer.
#[cfg(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
))]
pub(super) enum Encoder {
    #[cfg(feature = "compression-gzip")]
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    #[cfg(feature = "compression-deflate")]
    Deflate(flate2::write::ZlibEncoder<Vec<u8>>),
    #[cfg(feature = "compression-br")]
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    #[cfg(feature = "compression-zstd")]
    Zstd(Box<zstd::stream::write::Encoder<'static, Vec<u8>>>),
}

#[cfg(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
))]
impl Encoder {
    /// Builds an encoder for `encoding`, or `None` if this build has no codec for it.
    ///
    /// `pledged_size` is the exact number of bytes that will be written, when known. Only
    /// zstd uses it, to size its window to the input instead of to the level — which both
    /// saves memory and keeps small responses well inside the browser window limit.
    pub(super) fn new(
        encoding: Encoding,
        level: super::CompressionLevel,
        #[cfg_attr(not(feature = "compression-zstd"), allow(unused_variables))]
        pledged_size: Option<usize>,
    ) -> Option<Self> {
        match encoding {
            Encoding::Identity => None,
            #[cfg(feature = "compression-gzip")]
            Encoding::Gzip => Some(Self::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(level.flate()),
            ))),
            #[cfg(feature = "compression-deflate")]
            Encoding::Deflate => Some(Self::Deflate(flate2::write::ZlibEncoder::new(
                Vec::new(),
                flate2::Compression::new(level.flate()),
            ))),
            #[cfg(feature = "compression-br")]
            Encoding::Brotli => Some(Self::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                BROTLI_BUFFER_SIZE,
                level.brotli(),
                BROTLI_WINDOW_LOG,
            )))),
            #[cfg(feature = "compression-zstd")]
            Encoding::Zstd => {
                let zstd_level = level.zstd();
                let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), zstd_level).ok()?;
                if zstd_level >= ZSTD_WINDOW_CLAMP_FROM {
                    encoder
                        .set_parameter(zstd::zstd_safe::CParameter::WindowLog(ZSTD_MAX_WINDOW_LOG))
                        .ok()?;
                }
                if let Some(size) = pledged_size {
                    // Advisory only; a failure here costs ratio, not correctness.
                    let _ = encoder.set_pledged_src_size(Some(size as u64));
                }
                Some(Self::Zstd(Box::new(encoder)))
            }
            #[cfg(not(feature = "compression-gzip"))]
            Encoding::Gzip => None,
            #[cfg(not(feature = "compression-deflate"))]
            Encoding::Deflate => None,
            #[cfg(not(feature = "compression-br"))]
            Encoding::Brotli => None,
            #[cfg(not(feature = "compression-zstd"))]
            Encoding::Zstd => None,
        }
    }

    /// Feeds `data` to the codec. Output accumulates in the internal buffer, which
    /// [`Self::take_output`] drains.
    pub(super) fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            #[cfg(feature = "compression-gzip")]
            Self::Gzip(encoder) => encoder.write_all(data),
            #[cfg(feature = "compression-deflate")]
            Self::Deflate(encoder) => encoder.write_all(data),
            #[cfg(feature = "compression-br")]
            Self::Brotli(encoder) => encoder.write_all(data),
            #[cfg(feature = "compression-zstd")]
            Self::Zstd(encoder) => encoder.write_all(data),
        }
    }

    /// Ends the current compressor block so everything written so far is decodable by
    /// the client, without ending the stream. Costs ratio, so the streaming body only does
    /// it when the source has nothing more to give right now.
    pub(super) fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(feature = "compression-gzip")]
            Self::Gzip(encoder) => encoder.flush(),
            #[cfg(feature = "compression-deflate")]
            Self::Deflate(encoder) => encoder.flush(),
            #[cfg(feature = "compression-br")]
            Self::Brotli(encoder) => encoder.flush(),
            #[cfg(feature = "compression-zstd")]
            Self::Zstd(encoder) => encoder.flush(),
        }
    }

    /// Takes everything the codec has emitted so far, leaving an empty buffer behind.
    pub(super) fn take_output(&mut self) -> Vec<u8> {
        match self {
            #[cfg(feature = "compression-gzip")]
            Self::Gzip(encoder) => std::mem::take(encoder.get_mut()),
            #[cfg(feature = "compression-deflate")]
            Self::Deflate(encoder) => std::mem::take(encoder.get_mut()),
            #[cfg(feature = "compression-br")]
            Self::Brotli(encoder) => std::mem::take(encoder.get_mut()),
            #[cfg(feature = "compression-zstd")]
            Self::Zstd(encoder) => std::mem::take(encoder.get_mut()),
        }
    }

    /// Ends the stream and returns the remaining output — the codec's trailer plus
    /// anything still buffered.
    pub(super) fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            #[cfg(feature = "compression-gzip")]
            Self::Gzip(encoder) => encoder.finish(),
            #[cfg(feature = "compression-deflate")]
            Self::Deflate(encoder) => encoder.finish(),
            // `into_inner` runs the FINISH operation and discards any error from it. The
            // only sink here is a `Vec<u8>`, whose writes are infallible, so the sole way
            // that could fail is an internal codec fault — in which case the truncated
            // stream is detected by the client's decoder either way.
            #[cfg(feature = "compression-br")]
            Self::Brotli(encoder) => Ok(encoder.into_inner()),
            #[cfg(feature = "compression-zstd")]
            Self::Zstd(encoder) => encoder.finish(),
        }
    }
}

#[cfg(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
))]
impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            #[cfg(feature = "compression-gzip")]
            Self::Gzip(_) => "Encoder::Gzip",
            #[cfg(feature = "compression-deflate")]
            Self::Deflate(_) => "Encoder::Deflate",
            #[cfg(feature = "compression-br")]
            Self::Brotli(_) => "Encoder::Brotli",
            #[cfg(feature = "compression-zstd")]
            Self::Zstd(_) => "Encoder::Zstd",
        })
    }
}

/// With no `compression-*` feature enabled there is no codec to hold, but the call sites in
/// the parent module still have to type-check. `Compression::new` yields an empty encoding
/// list in that build, so `new` returning `None` is the only path ever taken and the
/// remaining methods are unreachable rather than merely unused.
#[cfg(not(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
)))]
pub(super) struct Encoder(());

#[cfg(not(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
)))]
#[allow(
    clippy::unused_self,
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_ref_mut
)]
impl Encoder {
    pub(super) const fn new(
        _encoding: Encoding,
        _level: super::CompressionLevel,
        _pledged_size: Option<usize>,
    ) -> Option<Self> {
        None
    }

    pub(super) fn write(&mut self, _data: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    pub(super) fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    pub(super) fn take_output(&mut self) -> Vec<u8> {
        Vec::new()
    }

    pub(super) fn finish(self) -> std::io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[cfg(not(any(
    feature = "compression-gzip",
    feature = "compression-deflate",
    feature = "compression-br",
    feature = "compression-zstd",
)))]
impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Encoder::Unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::{CompressionLevel, Encoder};
    use crate::http::compression::Encoding;

    /// Round-trips through every codec this build has, proving the framing the browser
    /// will see is the one the matching decoder expects — one-shot and streamed.
    #[test]
    fn every_available_codec_round_trips() {
        let input = "the quick brown fox jumps over the lazy dog. ".repeat(200);

        for encoding in [
            Encoding::Gzip,
            Encoding::Deflate,
            Encoding::Brotli,
            Encoding::Zstd,
        ] {
            if !encoding.encoder_available() {
                continue;
            }

            let mut encoder =
                Encoder::new(encoding, CompressionLevel::Default, Some(input.len())).unwrap();
            encoder.write(input.as_bytes()).unwrap();
            let compressed = encoder.finish().unwrap();
            assert!(
                compressed.len() < input.len(),
                "{encoding} did not shrink highly redundant input"
            );
            assert_eq!(decompress(encoding, &compressed), input.as_bytes());

            // Streamed in pieces, with a mid-stream flush, must decode identically.
            let mut encoder = Encoder::new(encoding, CompressionLevel::Fastest, None).unwrap();
            let mut streamed = Vec::new();
            for chunk in input.as_bytes().chunks(97) {
                encoder.write(chunk).unwrap();
                encoder.flush().unwrap();
                streamed.extend_from_slice(&encoder.take_output());
            }
            streamed.extend_from_slice(&encoder.finish().unwrap());
            assert_eq!(decompress(encoding, &streamed), input.as_bytes());
        }
    }

    #[test]
    fn precise_levels_are_clamped_into_range() {
        for encoding in [
            Encoding::Gzip,
            Encoding::Deflate,
            Encoding::Brotli,
            Encoding::Zstd,
        ] {
            if !encoding.encoder_available() {
                continue;
            }
            for level in [-5, 0, 99] {
                assert!(
                    Encoder::new(encoding, CompressionLevel::Precise(level), None).is_some(),
                    "{encoding} rejected out-of-range level {level} instead of clamping"
                );
            }
        }
    }

    /// zstd above level 19 defaults to a window larger than the 8 MiB every browser caps
    /// at; the encoder must clamp it back down. Read the window bits out of the frame
    /// header rather than trusting the setter.
    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_window_stays_inside_the_browser_limit() {
        let input = vec![7u8; 64 * 1024];
        for level in [1, 3, 19, 22] {
            let mut encoder =
                Encoder::new(Encoding::Zstd, CompressionLevel::Precise(level), None).unwrap();
            encoder.write(&input).unwrap();
            let frame = encoder.finish().unwrap();
            let window = zstd_frame_window_log(&frame);
            assert!(
                window <= super::ZSTD_MAX_WINDOW_LOG,
                "level {level} declared windowLog {window}, over the browser limit",
            );
        }
    }

    /// Decodes the `Window_Descriptor` of a zstd frame header (RFC 8878 §3.1.1.1.2) into
    /// the base-2 log of the window size.
    #[cfg(feature = "compression-zstd")]
    fn zstd_frame_window_log(frame: &[u8]) -> u32 {
        let descriptor = frame[4];
        let single_segment = (descriptor >> 5) & 1 == 1;
        assert!(
            !single_segment,
            "expected a windowed frame, got Single_Segment_Flag"
        );
        let window_descriptor = frame[5];
        let exponent = u32::from(window_descriptor >> 3);
        let mantissa = u32::from(window_descriptor & 0b111);
        let base = 10 + exponent;
        // window = base + base/8 * mantissa; round up to the next power of two.
        let size = (1u64 << base) + ((1u64 << base) / 8) * u64::from(mantissa);
        size.next_power_of_two().trailing_zeros()
    }

    #[allow(unused_imports, unused_mut, unused_variables, unreachable_code)]
    fn decompress(encoding: Encoding, bytes: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut out = Vec::new();
        match encoding {
            #[cfg(feature = "compression-gzip")]
            Encoding::Gzip => {
                flate2::read::GzDecoder::new(bytes)
                    .read_to_end(&mut out)
                    .unwrap();
            }
            #[cfg(feature = "compression-deflate")]
            Encoding::Deflate => {
                flate2::read::ZlibDecoder::new(bytes)
                    .read_to_end(&mut out)
                    .unwrap();
            }
            #[cfg(feature = "compression-br")]
            Encoding::Brotli => {
                brotli::Decompressor::new(bytes, 8192)
                    .read_to_end(&mut out)
                    .unwrap();
            }
            #[cfg(feature = "compression-zstd")]
            Encoding::Zstd => {
                zstd::stream::read::Decoder::new(bytes)
                    .unwrap()
                    .read_to_end(&mut out)
                    .unwrap();
            }
            // Unreachable: the caller skips codings without a compiled-in encoder, and
            // every encoder feature also brings in its decoder.
            other => unreachable!("no decoder compiled in for {other}"),
        }
        out
    }
}
