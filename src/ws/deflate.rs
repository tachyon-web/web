//! `permessage-deflate` (RFC 7692): negotiation of the `Sec-WebSocket-Extensions` offer/response,
//! and the actual per-message DEFLATE compressor/decompressor built on raw (headerless) deflate
//! streams via `flate2`.
//!
//! Compression is negotiated per RFC 7692 §7 and applied to the *payload of a full message* (all
//! fragments concatenated) rather than per-frame: RSV1 is only ever set on the first frame of a
//! message, and continuation frames carry no RSV1 of their own. The wire format for a compressed
//! message is produced with `Z_SYNC_FLUSH` and then has its trailing 4-byte empty-block marker
//! (`00 00 ff ff`) stripped per §7.2.1; the decompressor puts that marker back before inflating.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use hyper::header::{HeaderMap, HeaderValue, SEC_WEBSOCKET_EXTENSIONS};

/// The 4 bytes a `Z_SYNC_FLUSH` block ends with, which RFC 7692 requires senders to strip and
/// receivers to restore before inflating.
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Server-side tuning for the `permessage-deflate` extension.
///
/// Constructed via [`Default`] and passed to
/// [`WebSocketUpgrade::deflate_config`](super::WebSocketUpgrade::deflate_config).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DeflateConfig {
    /// Reset our own compression context after every message instead of reusing the sliding
    /// window across messages. Lowers compression ratio, lowers memory use. Default: `false`.
    pub server_no_context_takeover: bool,
    /// Require the client to reset its compression context after every message. This is only a
    /// request; correctness on our end does not depend on the client honoring it. Default: `false`.
    pub client_no_context_takeover: bool,
    /// The base-2 logarithm of the LZ77 window we use to compress outgoing messages, `9..=15`.
    /// Values are clamped into that range. Default: `15` (32 KiB window, maximum compression).
    pub server_max_window_bits: u8,
}

impl Default for DeflateConfig {
    fn default() -> Self {
        Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
        }
    }
}

/// One `permessage-deflate` offer parsed out of a `Sec-WebSocket-Extensions` request header.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Offer {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    /// The `server_max_window_bits` cap the client's offer named, if it named the parameter at
    /// all — `None` distinguishes "absent" (we may use any window) from "present", in which case
    /// RFC 7692 §7.1.2.1 makes the value a hard upper bound on the window our *compressor* may
    /// use: the client sizes its decompressor to exactly what it asked for, so exceeding it
    /// produces output the client cannot inflate. A bare `server_max_window_bits` with no value
    /// isn't legal in a client offer, so it's treated leniently as the no-op cap of 15.
    ///
    /// We don't honor `client_max_window_bits` (our decompressor always uses the maximum window,
    /// which is always compatible with whatever smaller window the client's compressor might
    /// use), so there's nothing to record for it beyond validating it during parsing.
    server_max_window_bits: Option<u8>,
}

/// The agreed-upon parameters after negotiating an [`Offer`] against a [`DeflateConfig`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Agreement {
    pub(super) server_no_context_takeover: bool,
    pub(super) client_no_context_takeover: bool,
    pub(super) server_max_window_bits: u8,
    /// Whether `server_max_window_bits` should be echoed in the response — only valid if the
    /// client's offer itself named the parameter.
    echo_server_max_window_bits: bool,
}

/// Extracts every `permessage-deflate` offer from the request's `Sec-WebSocket-Extensions`
/// header(s), in the order they appeared. Unrecognized extensions and unrecognized/malformed
/// parameters on an otherwise-recognized offer are skipped per-offer (per RFC 7692 §7, a server
/// declines an individual malformed offer rather than failing the whole negotiation).
pub(super) fn parse_offers(headers: &HeaderMap) -> Vec<Offer> {
    let mut offers = Vec::new();
    for header in headers.get_all(SEC_WEBSOCKET_EXTENSIONS) {
        let Ok(text) = header.to_str() else { continue };
        for extension in text.split(',') {
            let mut parts = extension.split(';').map(str::trim);
            let Some(name) = parts.next() else { continue };
            if !name.eq_ignore_ascii_case("permessage-deflate") {
                continue;
            }
            if let Some(offer) = parse_params(parts) {
                offers.push(offer);
            }
        }
    }
    offers
}

/// Parses one `window_bits` parameter's optional value, validating it against RFC 7692's
/// `9..=15` range when present. Returns the requested cap (or `15`, the no-op cap, when the
/// parameter carried no value), or `Err` if the offer should be declined outright.
fn parse_window_bits(value: Option<&str>) -> Result<u8, ()> {
    match value.map(str::parse::<u8>) {
        None => Ok(15),
        Some(Ok(bits @ 9..=15)) => Ok(bits),
        Some(_) => Err(()),
    }
}

fn parse_params<'a>(params: impl Iterator<Item = &'a str>) -> Option<Offer> {
    let mut offer = Offer::default();
    for param in params {
        if param.is_empty() {
            continue;
        }
        let (key, value) = match param.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim().trim_matches('"'))),
            None => (param, None),
        };
        match key {
            "server_no_context_takeover" if value.is_none() => {
                offer.server_no_context_takeover = true;
            }
            "client_no_context_takeover" if value.is_none() => {
                offer.client_no_context_takeover = true;
            }
            "server_max_window_bits" => {
                offer.server_max_window_bits = Some(parse_window_bits(value).ok()?);
            }
            "client_max_window_bits" => {
                parse_window_bits(value).ok()?;
            }
            // Unrecognized parameter, or a value on a no-value-only flag: decline this offer.
            _ => return None,
        }
    }
    Some(offer)
}

/// Picks the first offer we can accept and applies `config`'s server-side preferences to it.
/// Returns `None` if there is nothing to negotiate (no offers at all).
pub(super) fn negotiate(offers: &[Offer], config: DeflateConfig) -> Option<Agreement> {
    let offer = offers.first()?;
    // A `server_max_window_bits` the client named is a hard cap, not a hint (RFC 7692 §7.1.2.1):
    // the client sizes its decompressor to exactly the value it offered, so using a *larger*
    // window than it asked for yields output it can't inflate. Take the smaller of the two.
    let server_max_window_bits = config
        .server_max_window_bits
        .clamp(9, 15)
        .min(offer.server_max_window_bits.unwrap_or(15));
    Some(Agreement {
        server_no_context_takeover: config.server_no_context_takeover
            || offer.server_no_context_takeover,
        client_no_context_takeover: config.client_no_context_takeover
            || offer.client_no_context_takeover,
        server_max_window_bits,
        // Echoed whenever the client asked about the parameter, so it learns the window we
        // actually settled on rather than assuming its own offered value was taken verbatim.
        echo_server_max_window_bits: offer.server_max_window_bits.is_some()
            && server_max_window_bits < 15,
    })
}

/// Builds the `Sec-WebSocket-Extensions` response header value for an accepted [`Agreement`].
pub(super) fn agreement_header_value(agreement: Agreement) -> HeaderValue {
    let mut value = String::from("permessage-deflate");
    if agreement.server_no_context_takeover {
        value.push_str("; server_no_context_takeover");
    }
    if agreement.client_no_context_takeover {
        value.push_str("; client_no_context_takeover");
    }
    if agreement.echo_server_max_window_bits {
        value.push_str("; server_max_window_bits=");
        value.push_str(&agreement.server_max_window_bits.to_string());
    }
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("permessage-deflate"))
}

/// Per-connection compressor/decompressor for an agreed `permessage-deflate` extension.
pub(super) struct PerMessageDeflate {
    compress: Compress,
    decompress: Decompress,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
}

impl PerMessageDeflate {
    pub(super) fn new(agreement: Agreement) -> Self {
        Self {
            compress: Compress::new_with_window_bits(
                Compression::default(),
                false,
                agreement.server_max_window_bits,
            ),
            decompress: Decompress::new_with_window_bits(false, 15),
            server_no_context_takeover: agreement.server_no_context_takeover,
            client_no_context_takeover: agreement.client_no_context_takeover,
        }
    }

    /// Compresses `data`, but only when the result actually comes out smaller — RFC 7692 leaves
    /// per-message compression up to the sender (RSV1 is just left unset for the ones we skip),
    /// and deflate's per-block overhead means a small or already-dense payload can come out
    /// *larger* compressed. Returns `None` when the caller should send `data` verbatim instead.
    ///
    /// When we skip, the compressor's context is reset regardless of `server_no_context_takeover`:
    /// RFC 7692 requires an unsent-compressed message not to affect the compression context, but
    /// `flate2` gives no way to "undo" the trial `compress_vec` call already made while sizing up
    /// the candidate. Resetting is the only way back to a self-consistent state — deflate back-
    /// references are entirely encoder-side, so a reset simply means future messages don't
    /// reference data the client's decompressor never saw; the client's own (untouched, larger)
    /// window carrying unused extra history is harmless.
    pub(super) fn compress_if_smaller(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, crate::http::error::Error> {
        let compressed = self.compress_raw(data)?;
        if compressed.len() < data.len() {
            if self.server_no_context_takeover {
                self.compress.reset();
            }
            Ok(Some(compressed))
        } else {
            self.compress.reset();
            Ok(None)
        }
    }

    /// Compresses one full message payload, stripping the trailing sync-flush marker per §7.2.1.
    fn compress_raw(&mut self, data: &[u8]) -> Result<Vec<u8>, crate::http::error::Error> {
        let total_in_before = self.compress.total_in();
        let mut out = Vec::with_capacity(data.len() + 32);
        loop {
            grow(&mut out, 1024.max(data.len()), usize::MAX);
            let status = self
                .compress
                .compress_vec(data, &mut out, FlushCompress::Sync)
                .map_err(|e| crate::http::error::Error::Internal(e.to_string()))?;
            let consumed =
                usize::try_from(self.compress.total_in() - total_in_before).unwrap_or(usize::MAX);
            if consumed >= data.len() {
                break;
            }
            // `BufError`/`StreamEnd` here mean the compressor made no progress and never will —
            // looping on it would grow `out`'s capacity geometrically without ever consuming
            // more input, so bail rather than spin.
            if status != Status::Ok {
                return Err(crate::http::error::Error::Internal(
                    "permessage-deflate compressor stalled before consuming the message"
                        .to_string(),
                ));
            }
        }
        out.truncate(out.len().saturating_sub(DEFLATE_TAIL.len()));
        Ok(out)
    }

    /// Decompresses one full message payload, restoring the trailing sync-flush marker first.
    pub(super) fn decompress(
        &mut self,
        data: &[u8],
        max_size: Option<usize>,
    ) -> Result<Vec<u8>, crate::http::error::Error> {
        let max_size = max_size.unwrap_or(usize::MAX);
        let mut input = Vec::with_capacity(data.len() + DEFLATE_TAIL.len());
        input.extend_from_slice(data);
        input.extend_from_slice(&DEFLATE_TAIL);

        // One byte past `max_size`, so a message that overruns the limit still has somewhere to
        // land and be *detected* by the `out.len() > max_size` check below, rather than the
        // buffer wedging exactly at the limit with no room left to make progress.
        let capacity_limit = max_size.saturating_add(1);
        let total_in_before = self.decompress.total_in();
        let mut out = Vec::with_capacity(
            data.len()
                .saturating_mul(3)
                .saturating_add(32)
                .min(capacity_limit),
        );
        loop {
            grow(&mut out, 1024, capacity_limit);
            let consumed_before =
                usize::try_from(self.decompress.total_in() - total_in_before).unwrap_or(usize::MAX);
            let status = self
                .decompress
                .decompress_vec(&input[consumed_before..], &mut out, FlushDecompress::Sync)
                .map_err(|e| crate::http::error::Error::Internal(e.to_string()))?;
            if out.len() > max_size {
                return Err(crate::http::error::Error::Internal(
                    "decompressed message exceeds the configured maximum size".to_string(),
                ));
            }
            let consumed =
                usize::try_from(self.decompress.total_in() - total_in_before).unwrap_or(usize::MAX);
            if consumed >= input.len() {
                break;
            }
            // A peer can end its deflate stream (`BFINAL`) mid-payload, or send a block the
            // inflater can make no further progress on. Either way `decompress_vec` stops
            // consuming input while reporting success, and the old unconditional `continue`
            // spun forever — doubling `out`'s capacity on every pass (`out.len()`, which the
            // `max_size` check guards, stays put) until the process ran out of memory. Any
            // non-`Ok` status means no more progress is coming, so stop.
            if status != Status::Ok {
                return Err(crate::http::error::Error::Internal(
                    "permessage-deflate stream ended before the full message was decompressed"
                        .to_string(),
                ));
            }
        }
        if self.client_no_context_takeover {
            self.decompress.reset(false);
        }
        Ok(out)
    }
}

/// Reserves more spare capacity in `out`, doubling what's already there (or `min_initial` on the
/// first call) but never past `max_capacity` — geometric growth means a large payload needing
/// several `compress_vec`/`decompress_vec` rounds costs O(log n) reallocations instead of O(n),
/// while the ceiling keeps decompression from allocating ~2× the configured message limit in
/// slack capacity (the doubling overshoots, and the limit is only checked against `out.len()`
/// *after* a round) before that limit is enforced.
fn grow(out: &mut Vec<u8>, min_initial: usize, max_capacity: usize) {
    let current = out.capacity();
    let target = current
        .saturating_add(current.max(min_initial))
        .min(max_capacity);
    if target > current {
        out.reserve(target - current);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::{Agreement, DeflateConfig, PerMessageDeflate, negotiate, parse_offers};
    use hyper::header::{HeaderMap, HeaderValue, SEC_WEBSOCKET_EXTENSIONS};

    fn offers_from(value: &'static str) -> Vec<super::Offer> {
        let mut headers = HeaderMap::new();
        let _ = headers.insert(SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_static(value));
        parse_offers(&headers)
    }

    /// A `server_max_window_bits` the client names is a cap on *our* compressor's window, not a
    /// hint: the client sizes its inflater to exactly that, so exceeding it produces output it
    /// cannot read. It must also be echoed so the client isn't left guessing.
    #[test]
    fn client_offered_server_max_window_bits_caps_our_window() {
        let offers = offers_from("permessage-deflate; server_max_window_bits=10");
        let agreement = negotiate(&offers, DeflateConfig::default()).unwrap();
        assert_eq!(agreement.server_max_window_bits, 10);
        let header = super::agreement_header_value(agreement);
        assert!(
            header
                .to_str()
                .unwrap()
                .contains("server_max_window_bits=10"),
            "header: {header:?}"
        );
    }

    /// The server's own configured window still applies when it's the smaller of the two.
    #[test]
    fn server_config_wins_when_it_is_more_restrictive() {
        let offers = offers_from("permessage-deflate; server_max_window_bits=15");
        let config = DeflateConfig {
            server_max_window_bits: 9,
            ..DeflateConfig::default()
        };
        assert_eq!(
            negotiate(&offers, config).unwrap().server_max_window_bits,
            9
        );
    }

    #[test]
    fn absent_server_max_window_bits_leaves_the_window_unconstrained() {
        let offers = offers_from("permessage-deflate");
        let agreement = negotiate(&offers, DeflateConfig::default()).unwrap();
        assert_eq!(agreement.server_max_window_bits, 15);
        assert!(!agreement.echo_server_max_window_bits);
    }

    fn deflate() -> PerMessageDeflate {
        PerMessageDeflate::new(Agreement {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
            echo_server_max_window_bits: false,
        })
    }

    #[test]
    fn round_trips_a_compressible_message() {
        let payload = b"the quick brown fox ".repeat(64);
        let mut d = deflate();
        let compressed = d.compress_if_smaller(&payload).unwrap().unwrap();
        assert!(compressed.len() < payload.len());
        assert_eq!(d.decompress(&compressed, None).unwrap(), payload);
    }

    /// Garbage that inflates to nothing (and so never consumes its input) used to spin
    /// `decompress` forever, doubling the output buffer's *capacity* on every pass — `out.len()`
    /// stays at 0, so the `max_size` check never fired. It must terminate with an error.
    #[test]
    fn decompress_terminates_on_input_it_cannot_consume() {
        let mut d = deflate();
        // A final (`BFINAL`) empty stored block: valid deflate that ends the stream immediately,
        // leaving the rest of the payload unconsumable.
        let mut data = vec![0x01, 0x00, 0x00, 0xff, 0xff];
        data.extend_from_slice(&[0xaa; 64]);
        assert!(d.decompress(&data, Some(1024)).is_err());
    }

    #[test]
    fn decompress_rejects_a_message_over_the_size_limit() {
        let payload = vec![b'x'; 128 * 1024];
        let mut d = deflate();
        let compressed = d.compress_if_smaller(&payload).unwrap().unwrap();
        let mut d = deflate();
        assert!(d.decompress(&compressed, Some(1024)).is_err());
    }
}
