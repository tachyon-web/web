//! Response compression: `Accept-Encoding` negotiation and content coding.
//!
//! Covers the four codings browsers actually negotiate — `zstd` ([RFC 8878]), `br`
//! ([RFC 7932]), `gzip` ([RFC 1952]) and `deflate` ([RFC 1950]) — behind one
//! [`Compression`] config, applied either to a whole server or to one router.
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//! use tachyon_web::http::compression::Compression;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let app: Router = Router::new().route("/", get(|| async { "hello" }));
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//!
//! Server::new(app)
//!     .compression(Compression::new())   // zstd → br → gzip → deflate
//!     .serve_http(listener)
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! Every codec is behind its own feature flag, named to match `tower-http` so an
//! `axum` migration is a search-and-replace: `compression-gzip`, `compression-deflate`,
//! `compression-br`, `compression-zstd`, and `compression-full` for all four.
//! [`Compression::new`] enables exactly the codecs that were compiled in, so adding a
//! feature flag is the only step needed to start serving a new coding.
//!
//! # What is *not* compressed
//!
//! Compression is skipped — and the response passes through byte-identical — when any of
//! the following holds. These are correctness rules, not tuning knobs, and none of them
//! are configurable:
//!
//! - the client's `Accept-Encoding` offers nothing this server supports (or is absent);
//! - the response already carries a `Content-Encoding` other than `identity`;
//! - the response carries `Cache-Control: no-transform` ([RFC 9111 §5.2.2.6]);
//! - the status is `1xx`, `204 No Content`, `304 Not Modified`, or `206 Partial Content`
//!   (a range is expressed against the representation the client already holds);
//! - the body is empty, or its known length is below [`Compression::min_size`];
//! - the `Content-Type` is one [`Compression::predicate`] rejects — by default anything
//!   already compressed (JPEG, WOFF2, MP4, …) and `text/event-stream`, whose whole point
//!   is per-event delivery.
//!
//! # BREACH
//!
//! Compressing a response that contains both a secret and attacker-influenced text leaks the
//! secret. The attacker varies the text they control, watches the coded length, and keeps
//! whatever guess compressed best — a CSRF token falls in a few thousand requests. TLS does
//! not help; the length is visible regardless.
//!
//! Compression is off by default, and turning it on is the point at which to check:
//!
//! - Does any compressed response embed a CSRF token, session identifier, or API key
//!   *alongside* text derived from the request (a search term, a `?q=`, a reflected name)?
//!   Exclude those responses with [`Compression::predicate`], or move the secret to a header
//!   or a `Set-Cookie`, neither of which is part of the body.
//! - Over Tor or I2P, coded length is also a fingerprint: it varies with content in a way a
//!   padded, uniform response does not, which is worth weighing against the bandwidth saved
//!   on a link that is already slow.
//!
//! [`ServeDir`](crate::ServeDir) assets are static and request-independent, so they are not
//! exposed to this.
//!
//! # Interaction with `ETag`
//!
//! A content coding produces a different representation, so it must not keep a *strong*
//! entity tag ([RFC 9110 §8.8.3]). Compressing a response whose `ETag` is strong rewrites
//! it to the weak form (`"abc"` → `W/"abc"`) rather than leaving a strong tag that two
//! different byte streams now share. Weak tags, and the `If-None-Match` comparisons
//! [`ServeDir`](crate::ServeDir) performs, are unaffected.
//!
//! [RFC 8878]: https://www.rfc-editor.org/rfc/rfc8878
//! [RFC 7932]: https://www.rfc-editor.org/rfc/rfc7932
//! [RFC 1952]: https://www.rfc-editor.org/rfc/rfc1952
//! [RFC 1950]: https://www.rfc-editor.org/rfc/rfc1950
//! [RFC 9111 §5.2.2.6]: https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.6
//! [RFC 9110 §8.8.3]: https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3

use crate::http::response::Body;
use bytes::Bytes;
use hyper::body::{Body as HyperBody, Frame, SizeHint};
use hyper::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
    HeaderMap, HeaderValue, VARY,
};
use hyper::{Response, StatusCode};
use smallvec::SmallVec;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

mod codec;

pub use codec::CompressionLevel;

/// A content coding, as registered in the IANA HTTP Content Coding Registry.
///
/// Every variant exists regardless of which `compression-*` features are enabled, because
/// negotiation and pre-compressed static assets are useful without the matching encoder
/// linked in — [`ServeDir`](crate::ServeDir) serves a `.zst` sidecar from disk whether or
/// not this crate can produce one. [`Encoding::encoder_available`] reports whether the
/// running binary can actually *perform* the coding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// No transformation. Always acceptable unless explicitly refused with `identity;q=0`.
    Identity,
    /// `deflate` — zlib-wrapped DEFLATE, [RFC 1950]. Listed last by default: it buys
    /// nothing over `gzip` and a handful of ancient servers emitted it raw, so some
    /// clients distrust it.
    ///
    /// [RFC 1950]: https://www.rfc-editor.org/rfc/rfc1950
    Deflate,
    /// `gzip` — [RFC 1952]. The universal fallback; assume every client supports it.
    ///
    /// [RFC 1952]: https://www.rfc-editor.org/rfc/rfc1952
    Gzip,
    /// `br` — Brotli, [RFC 7932]. Best ratio on text, and the right choice for assets
    /// compressed ahead of time where encode cost is paid once.
    ///
    /// [RFC 7932]: https://www.rfc-editor.org/rfc/rfc7932
    Brotli,
    /// `zstd` — Zstandard, [RFC 8878]. Compresses far faster than Brotli at a comparable
    /// ratio, which is the tradeoff that matters for a response generated per request.
    ///
    /// [RFC 8878]: https://www.rfc-editor.org/rfc/rfc8878
    Zstd,
}

impl Encoding {
    /// The `Content-Encoding` / `Accept-Encoding` token for this coding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Deflate => "deflate",
            Self::Gzip => "gzip",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }

    /// The conventional filename suffix for a pre-compressed sidecar of this coding —
    /// `app.js.zst`, `app.js.br`, `app.js.gz`.
    #[must_use]
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::Identity => "",
            Self::Deflate => "zz",
            Self::Gzip => "gz",
            Self::Brotli => "br",
            Self::Zstd => "zst",
        }
    }

    /// Parses a coding token, case-insensitively per [RFC 9110 §8.4.1].
    ///
    /// Returns `None` for unregistered tokens and for the deprecated `x-gzip`/`x-compress`
    /// aliases — a client sending only `x-gzip` gets `identity`, which is correct if
    /// unhelpful, and no modern client does.
    ///
    /// [RFC 9110 §8.4.1]: https://www.rfc-editor.org/rfc/rfc9110#section-8.4.1
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim();
        [
            Self::Identity,
            Self::Deflate,
            Self::Gzip,
            Self::Brotli,
            Self::Zstd,
        ]
        .into_iter()
        .find(|candidate| token.eq_ignore_ascii_case(candidate.as_str()))
    }

    /// Whether this build can actually perform the coding, i.e. whether the matching
    /// `compression-*` feature is enabled. [`Encoding::Identity`] is always available.
    #[must_use]
    pub const fn encoder_available(self) -> bool {
        match self {
            Self::Identity => true,
            Self::Gzip => cfg!(feature = "compression-gzip"),
            Self::Deflate => cfg!(feature = "compression-deflate"),
            Self::Brotli => cfg!(feature = "compression-br"),
            Self::Zstd => cfg!(feature = "compression-zstd"),
        }
    }

    /// The pre-validated `Content-Encoding` header value for this coding.
    ///
    /// A `const` construction from a static string, so it costs nothing to call per
    /// response — unlike `HeaderValue::from_str`, which re-validates the bytes.
    #[must_use]
    pub const fn header_value(self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Self::Identity => "identity",
            Self::Deflate => "deflate",
            Self::Gzip => "gzip",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        })
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The order codings are preferred in when the client expresses no preference of its own.
///
/// `zstd` first: for a body compressed once per request, its throughput advantage over
/// Brotli dominates Brotli's slightly better ratio. Pre-compressed static assets invert
/// that tradeoff, which is why [`ServeDir`](crate::ServeDir) prefers `br` instead.
pub const DEFAULT_PREFERENCE: [Encoding; 4] = [
    Encoding::Zstd,
    Encoding::Brotli,
    Encoding::Gzip,
    Encoding::Deflate,
];

/// Quality value scaled to thousandths, so comparisons stay in integer arithmetic.
///
/// `Accept-Encoding` q-values carry at most three decimal places ([RFC 9110 §12.4.2]), so
/// this is exact rather than an approximation of the float form.
///
/// [RFC 9110 §12.4.2]: https://www.rfc-editor.org/rfc/rfc9110#section-12.4.2
type Quality = u16;

const Q_MAX: Quality = 1000;

/// Parses a `q=` parameter value into thousandths, saturating at `1.000`.
fn parse_quality(raw: &str) -> Option<Quality> {
    let raw = raw.trim();
    let (int_part, frac_part) = raw.split_once('.').unwrap_or((raw, ""));
    // `1.` and `.5` are both tolerated by real clients even though the grammar wants a
    // digit on each side of the point.
    let int: Quality = if int_part.is_empty() {
        0
    } else {
        int_part.parse().ok()?
    };
    if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut frac: Quality = 0;
    for i in 0..3 {
        frac = frac * 10 + Quality::from(frac_part.as_bytes().get(i).map_or(0, |b| b - b'0'));
    }
    Some((int.saturating_mul(1000).saturating_add(frac)).min(Q_MAX))
}

/// Every q-value a client expressed, indexed by [`Encoding`], plus the `*` wildcard.
///
/// Parsing `Accept-Encoding` once into this and answering from it beats re-scanning the
/// header per candidate coding: the header is attacker-controlled and can run to the
/// connection's whole header allowance, so a pass per codec turns one large header into
/// four large scans.
#[derive(Default)]
struct AcceptedEncodings {
    /// Indexed by [`Encoding::index`]; `None` where the coding went unmentioned.
    exact: [Option<Quality>; 5],
    wildcard: Option<Quality>,
}

impl Encoding {
    /// Dense index into [`AcceptedEncodings::exact`].
    const fn index(self) -> usize {
        match self {
            Self::Identity => 0,
            Self::Deflate => 1,
            Self::Gzip => 2,
            Self::Brotli => 3,
            Self::Zstd => 4,
        }
    }
}

impl AcceptedEncodings {
    /// Parses an `Accept-Encoding` field value in a single pass.
    fn parse(accept_encoding: &str) -> Self {
        let mut parsed = Self::default();
        for element in accept_encoding.split(',') {
            let mut parts = element.split(';').map(str::trim);
            let Some(token) = parts.next().filter(|t| !t.is_empty()) else {
                continue;
            };
            let quality = parts
                .find_map(|param| {
                    param
                        .split_once('=')
                        .filter(|(key, _)| key.trim().eq_ignore_ascii_case("q"))
                        .map(|(_, value)| parse_quality(value).unwrap_or(0))
                })
                .unwrap_or(Q_MAX);

            if token == "*" {
                // A repeated wildcard is malformed; the last one wins, as with any duplicate.
                parsed.wildcard = Some(quality);
            } else if let Some(encoding) = Encoding::from_token(token) {
                parsed.exact[encoding.index()] = Some(quality);
            }
        }
        parsed
    }

    /// The q-value the client assigned to `encoding`, resolving the `*` wildcard.
    ///
    /// Returns `None` when the coding is not acceptable at all — either listed with `q=0`,
    /// or unlisted with a `*;q=0` in effect. Per [RFC 9110 §12.5.3], an unlisted `identity`
    /// is acceptable unless a wildcard refuses it, while any other unlisted coding is not.
    ///
    /// [RFC 9110 §12.5.3]: https://www.rfc-editor.org/rfc/rfc9110#section-12.5.3
    fn quality_of(&self, encoding: Encoding) -> Option<Quality> {
        let effective = match (self.exact[encoding.index()], self.wildcard) {
            // An explicit entry always beats the wildcard, even a lower one.
            (Some(q), _) | (None, Some(q)) => q,
            (None, None) => {
                if encoding == Encoding::Identity {
                    Q_MAX
                } else {
                    return None;
                }
            }
        };
        (effective > 0).then_some(effective)
    }
}

/// Picks the best coding for a request, given the codings this server is willing to use.
///
/// `supported` is consulted in order, so it doubles as the server's own preference for
/// breaking q-value ties — the client's ranking wins, and `supported` decides only among
/// equals. `Encoding::Identity` need not appear in `supported`; it is the result whenever
/// nothing else is both offered and acceptable.
///
/// Returns `Encoding::Identity` when the request carries no `Accept-Encoding` at all. An
/// absent header technically means "anything is acceptable", but a client that omits it is
/// overwhelmingly a client that will mishandle a coded response, so it gets bytes as-is.
///
/// ```rust
/// use tachyon_web::http::compression::{negotiate, Encoding, DEFAULT_PREFERENCE};
///
/// // The client's explicit ranking wins over the server's.
/// assert_eq!(
///     negotiate("gzip;q=1.0, zstd;q=0.5", &DEFAULT_PREFERENCE),
///     Encoding::Gzip,
/// );
/// // Ties fall back to server preference — zstd leads DEFAULT_PREFERENCE.
/// assert_eq!(
///     negotiate("gzip, br, zstd", &DEFAULT_PREFERENCE),
///     Encoding::Zstd,
/// );
/// // `q=0` is a refusal, not a low ranking.
/// assert_eq!(
///     negotiate("zstd;q=0, gzip", &DEFAULT_PREFERENCE),
///     Encoding::Gzip,
/// );
/// ```
#[must_use]
pub fn negotiate(accept_encoding: &str, supported: &[Encoding]) -> Encoding {
    if supported.is_empty() {
        return Encoding::Identity;
    }
    let accepted = AcceptedEncodings::parse(accept_encoding);
    let mut best: Option<(Quality, Encoding)> = None;
    for &candidate in supported {
        if candidate == Encoding::Identity {
            continue;
        }
        let Some(quality) = accepted.quality_of(candidate) else {
            continue;
        };
        // Strictly greater, so the first entry in `supported` wins a tie.
        if best.is_none_or(|(best_q, _)| quality > best_q) {
            best = Some((quality, candidate));
        }
    }
    best.map_or(Encoding::Identity, |(_, encoding)| encoding)
}

/// `application/*` subtypes that are text or otherwise uncompressed, and so are worth
/// coding despite `application` being the catch-all for opaque binary payloads.
const COMPRESSIBLE_APPLICATION_SUBTYPES: &[&str] = &[
    "json",
    "xml",
    "javascript",
    "x-javascript",
    "ecmascript",
    "x-ecmascript",
    "xhtml+xml",
    "wasm",
    "sql",
    "graphql",
    "x-ndjson",
    "ld+json",
    "x-www-form-urlencoded",
    "toml",
    "yaml",
    "x-yaml",
    "vnd.api+json",
    "vnd.ms-fontobject",
    "rtf",
    "postscript",
    "x-tar",
];

/// Whether a `Content-Type` names a representation worth compressing.
///
/// The default for [`Compression::predicate`]. Roughly: text-shaped things yes, things
/// that are already a compressed container no. Returns `true` for a response with no
/// `Content-Type` at all, since an unlabelled body is usually text.
#[must_use]
pub fn is_compressible(content_type: &str) -> bool {
    // Strip parameters: `text/html; charset=utf-8` → `text/html`.
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    let (kind, subtype) = essence.split_once('/').unwrap_or((essence, ""));

    // Server-Sent Events are a stream of individually-meaningful events; buffering them
    // into compressor blocks defeats the transport even though the bytes compress well.
    if essence.eq_ignore_ascii_case("text/event-stream") {
        return false;
    }
    // Structured suffixes cover a long tail — `image/svg+xml`, `application/manifest+json`,
    // `application/atom+xml` — without enumerating it.
    if let Some((_, suffix)) = subtype.rsplit_once('+')
        && ["xml", "json", "text", "yaml"]
            .iter()
            .any(|known| suffix.eq_ignore_ascii_case(known))
    {
        return true;
    }
    if kind.eq_ignore_ascii_case("text") {
        return true;
    }
    if kind.eq_ignore_ascii_case("font") {
        // WOFF/WOFF2 wrap already-compressed tables; raw TTF/OTF do not.
        return !subtype.eq_ignore_ascii_case("woff") && !subtype.eq_ignore_ascii_case("woff2");
    }
    if kind.eq_ignore_ascii_case("image") {
        // Everything else in `image/*` is an already-compressed raster format.
        return subtype.eq_ignore_ascii_case("bmp")
            || subtype.eq_ignore_ascii_case("x-icon")
            || subtype.eq_ignore_ascii_case("vnd.microsoft.icon");
    }
    if kind.eq_ignore_ascii_case("audio") || kind.eq_ignore_ascii_case("video") {
        return false;
    }
    if essence.is_empty() {
        return true;
    }

    kind.eq_ignore_ascii_case("application")
        && COMPRESSIBLE_APPLICATION_SUBTYPES
            .iter()
            .any(|known| subtype.eq_ignore_ascii_case(known))
}

/// Decides, per response, whether compression should be attempted.
///
/// See [`Compression::predicate`].
pub type Predicate = Arc<dyn Fn(&Response<Body>) -> bool + Send + Sync>;

/// Response-compression configuration.
///
/// Cheap to clone (one `SmallVec` and one `Arc`), so a single value is built at startup and
/// shared by every connection.
///
/// # Example
///
/// ```rust
/// use tachyon_web::http::compression::{Compression, CompressionLevel, Encoding};
///
/// let compression = Compression::new()
///     // Speed over ratio for responses built per request.
///     .level(CompressionLevel::Fastest)
///     // Don't bother below 1 KiB.
///     .min_size(1024)
///     // Never compress this app's pre-signed URLs, whatever their content type.
///     .predicate(|response| !response.headers().contains_key("x-signed-payload"));
///
/// assert!(compression.supports(Encoding::Identity));
/// ```
#[derive(Clone)]
pub struct Compression {
    /// Enabled codings in server-preference order.
    enabled: SmallVec<[Encoding; 4]>,
    level: CompressionLevel,
    min_size: u64,
    blocking_threshold: usize,
    predicate: Option<Predicate>,
}

/// Bodies at or above this many bytes are compressed on the blocking pool rather than
/// inline — see [`Compression::blocking_threshold`].
const DEFAULT_BLOCKING_THRESHOLD: usize = 32 * 1024;

/// Default for [`Compression::min_size`].
///
/// Higher than `tower-http`'s 32, which is below the ~20-byte framing overhead of gzip
/// plus the cost of a `Vary`-keyed cache entry. At 128 bytes a text body reliably shrinks.
const DEFAULT_MIN_SIZE: u64 = 128;

impl Default for Compression {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compression")
            .field("enabled", &self.enabled)
            .field("level", &self.level)
            .field("min_size", &self.min_size)
            .field("blocking_threshold", &self.blocking_threshold)
            .field("predicate", &self.predicate.as_ref().map(|_| "<custom>"))
            .finish()
    }
}

impl Compression {
    /// Enables every coding this build was compiled with, in [`DEFAULT_PREFERENCE`] order.
    ///
    /// With no `compression-*` feature enabled this produces a configuration that never
    /// compresses anything — a valid, if pointless, state that keeps code depending on
    /// this type compiling regardless of feature selection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: DEFAULT_PREFERENCE
                .into_iter()
                .filter(|e| e.encoder_available())
                .collect(),
            level: CompressionLevel::Default,
            min_size: DEFAULT_MIN_SIZE,
            blocking_threshold: DEFAULT_BLOCKING_THRESHOLD,
            predicate: None,
        }
    }

    /// Starts from no codings at all, for building an explicit list with [`Self::enable`].
    #[must_use]
    pub fn empty() -> Self {
        Self {
            enabled: SmallVec::new(),
            ..Self::new()
        }
    }

    /// Appends `encoding` to the preference list, if this build can perform it.
    ///
    /// Requesting a coding whose feature is disabled is a no-op rather than an error, so a
    /// configuration written once compiles and runs under any feature selection. Check
    /// [`Encoding::encoder_available`] up front if a missing codec should be fatal.
    #[must_use]
    pub fn enable(mut self, encoding: Encoding) -> Self {
        if encoding.encoder_available()
            && encoding != Encoding::Identity
            && !self.enabled.contains(&encoding)
        {
            self.enabled.push(encoding);
        }
        self
    }

    /// Removes `encoding` from the preference list.
    #[must_use]
    pub fn disable(mut self, encoding: Encoding) -> Self {
        self.enabled.retain(|&mut e| e != encoding);
        self
    }

    /// Replaces the preference list wholesale. Order is the server's tie-break ranking;
    /// codings this build cannot perform are dropped.
    #[must_use]
    pub fn preference(mut self, order: impl IntoIterator<Item = Encoding>) -> Self {
        self.enabled = order
            .into_iter()
            .filter(|e| e.encoder_available() && *e != Encoding::Identity)
            .collect();
        self
    }

    /// Whether `encoding` would be used for a client that accepts it.
    ///
    /// [`Encoding::Identity`] is always supported.
    #[must_use]
    pub fn supports(&self, encoding: Encoding) -> bool {
        encoding == Encoding::Identity || self.enabled.contains(&encoding)
    }

    /// The enabled codings, in server-preference order.
    #[must_use]
    pub fn encodings(&self) -> &[Encoding] {
        &self.enabled
    }

    /// Sets the quality/speed tradeoff, applied to every codec — each maps the level onto
    /// its own scale. See [`CompressionLevel`].
    #[must_use]
    pub const fn level(mut self, level: CompressionLevel) -> Self {
        self.level = level;
        self
    }

    /// Bodies below this many bytes are sent uncompressed (default: 128).
    ///
    /// Only applies when the length is known up front. A streaming body of unknown length
    /// is always compressed, since the alternative is buffering it to find out.
    #[must_use]
    pub const fn min_size(mut self, bytes: u64) -> Self {
        self.min_size = bytes;
        self
    }

    /// In-memory bodies at or above this size are compressed on Tokio's blocking pool
    /// instead of inline (default: 32 KiB).
    ///
    /// Compression is CPU-bound and synchronous. Doing a megabyte of Brotli on a runtime
    /// worker stalls every other connection that worker is driving; handing it to the
    /// blocking pool costs a task spawn and a channel round-trip, which is the wrong
    /// tradeoff for the small responses that make up most traffic. Hence a threshold
    /// rather than a global choice.
    ///
    /// Streaming bodies are always compressed inline — they arrive in frames small enough
    /// that per-frame encoding is not a meaningful stall.
    #[must_use]
    pub const fn blocking_threshold(mut self, bytes: usize) -> Self {
        self.blocking_threshold = bytes;
        self
    }

    /// Replaces the content-type test with a custom one.
    ///
    /// The predicate sees the full response, so it can key off any header, not just
    /// `Content-Type`. It runs *after* the unconditional correctness rules in the module
    /// docs, so it can only ever suppress compression, never force it onto a `304` or a
    /// response that is already coded.
    ///
    /// To keep the default type check and add to it, call [`is_compressible`] from inside
    /// the predicate:
    ///
    /// ```rust
    /// use tachyon_web::http::compression::{Compression, is_compressible};
    /// use tachyon_web::http::header::CONTENT_TYPE;
    ///
    /// let compression = Compression::new().predicate(|response| {
    ///     if response.headers().contains_key("x-no-compress") {
    ///         return false;
    ///     }
    ///     response
    ///         .headers()
    ///         .get(CONTENT_TYPE)
    ///         .and_then(|value| value.to_str().ok())
    ///         .is_none_or(is_compressible)
    /// });
    /// # let _ = compression;
    /// ```
    #[must_use]
    pub fn predicate<F>(mut self, predicate: F) -> Self
    where
        F: Fn(&Response<Body>) -> bool + Send + Sync + 'static,
    {
        self.predicate = Some(Arc::new(predicate));
        self
    }

    /// Compresses `response` if the request's `Accept-Encoding` and this configuration
    /// both allow it, returning the response either way.
    ///
    /// This is what [`Server::compression`](crate::Server::compression) and
    /// [`Router::compression`](crate::Router::compression) call; reach for it directly
    /// only when compressing a response outside the normal pipeline.
    pub async fn apply(
        &self,
        request_headers: &HeaderMap,
        response: Response<Body>,
    ) -> Response<Body> {
        let Some(accept_encoding) = request_headers
            .get(ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
        else {
            return response;
        };
        self.apply_to(accept_encoding, response).await
    }

    /// [`Self::apply`] against an already-extracted `Accept-Encoding` value.
    ///
    /// Split out for transports that hold the header as a `&str` rather than a
    /// [`HeaderMap`], and for tests.
    pub async fn apply_to(
        &self,
        accept_encoding: &str,
        mut response: Response<Body>,
    ) -> Response<Body> {
        if self.enabled.is_empty() || !is_eligible(&response) {
            return response;
        }
        // `Vary` goes on before the negotiation result is known: a cache must key on
        // `Accept-Encoding` even for the identity response it is about to store, or the
        // next client — one that *does* accept a coding — gets served this entry forever.
        add_vary_accept_encoding(response.headers_mut());

        let allowed = self.predicate.as_ref().map_or_else(
            || passes_default_predicate(&response),
            |predicate| predicate(&response),
        );
        if !allowed {
            return response;
        }

        let encoding = negotiate(accept_encoding, &self.enabled);
        if encoding == Encoding::Identity {
            return response;
        }

        // A body whose length is known and tiny is not worth a codec's framing overhead.
        // `upper == lower` is the only case where the length is actually known.
        let size = response.body().size_hint();
        if size.exact().is_some_and(|len| len < self.min_size) {
            return response;
        }

        let (mut parts, body) = response.into_parts();
        let new_body = match body {
            Body::Empty => return Response::from_parts(parts, Body::Empty),
            Body::Full(_) | Body::Stream(_) if size.exact() == Some(0) => {
                return Response::from_parts(parts, body);
            }
            // A `Full` body is already entirely in memory, so it can be compressed in one
            // shot — which both compresses better than framed streaming and lets the
            // exact `Content-Length` be restored below.
            Body::Full(_) => {
                let Ok(bytes) = collect_full(body).await else {
                    return Response::from_parts(parts, Body::Empty);
                };
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) < self.min_size {
                    return Response::from_parts(parts, Body::full(bytes));
                }
                match self.compress_in_memory(encoding, bytes).await {
                    Ok(compressed) => {
                        set_content_length(&mut parts.headers, compressed.len());
                        Body::full(compressed)
                    }
                    Err(Some(original)) => {
                        return Response::from_parts(parts, Body::full(original));
                    }
                    // The body is gone; a `500` is the only response left that doesn't lie
                    // about what the client is holding.
                    Err(None) => {
                        use crate::http::response::IntoResponse;
                        return crate::http::error::Error::Internal(
                            "response compression failed".to_string(),
                        )
                        .into_response();
                    }
                }
            }
            Body::Stream(_) => {
                let Some(encoder) = codec::Encoder::new(encoding, self.level, None) else {
                    return Response::from_parts(parts, body);
                };
                // The coded length is unknowable until the last frame, so the response
                // becomes chunked (HTTP/1.1) or simply length-less (HTTP/2, HTTP/3).
                let _ = parts.headers.remove(CONTENT_LENGTH);
                Body::stream(CompressedBody {
                    inner: body,
                    encoder: Some(encoder),
                    pending_trailers: None,
                    flushed_while_pending: false,
                    finished: false,
                })
            }
        };

        let _ = parts
            .headers
            .insert(CONTENT_ENCODING, encoding.header_value());
        weaken_etag(&mut parts.headers);
        Response::from_parts(parts, new_body)
    }

    /// One-shot compression of a fully-buffered body, on the blocking pool when the input
    /// is large enough to be worth the handoff.
    ///
    /// Returns `Err(Some(original))` when the codec is unavailable, fails, or made the body
    /// bigger, so the caller can send the identity representation instead. `Err(None)` means
    /// the input itself was lost and neither representation can still be produced.
    async fn compress_in_memory(
        &self,
        encoding: Encoding,
        bytes: Bytes,
    ) -> Result<Bytes, Option<Bytes>> {
        let level = self.level;
        let run = move |bytes: Bytes| -> Result<Bytes, Bytes> {
            // `set_pledged_src_size` lets zstd shrink its window to fit the input, which
            // both saves memory and keeps the frame header inside the 8 MiB window every
            // browser decoder caps at.
            let Some(mut encoder) = codec::Encoder::new(encoding, level, Some(bytes.len())) else {
                return Err(bytes);
            };
            match encoder.write(&bytes).and_then(|()| encoder.finish()) {
                // Compression is not guaranteed to shrink anything — incompressible bytes
                // that slipped past the content-type check come back larger. Sending the
                // original is both smaller and cheaper for the client to read.
                Ok(compressed) if compressed.len() < bytes.len() => Ok(Bytes::from(compressed)),
                Ok(_) => Err(bytes),
                Err(e) => {
                    tracing::warn!("{encoding} compression failed, sending identity: {e}");
                    Err(bytes)
                }
            }
        };

        if bytes.len() < self.blocking_threshold {
            return run(bytes).map_err(Some);
        }
        match tokio::task::spawn_blocking(move || run(bytes)).await {
            Ok(result) => result.map_err(Some),
            Err(e) => {
                tracing::error!("compression task failed: {e}");
                Err(None)
            }
        }
    }
}

/// The unconditional correctness rules from the module docs — everything that must hold
/// before a response may be coded at all, independent of configuration.
fn is_eligible(response: &Response<Body>) -> bool {
    let status = response.status();
    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        // A `206` body is a range of the representation the client is already reassembling.
        || status == StatusCode::PARTIAL_CONTENT
    {
        return false;
    }
    let headers = response.headers();
    // Re-coding an already-coded body is legal but pointless, and gets the ordering of the
    // `Content-Encoding` list wrong more often than not.
    if headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity"))
    {
        return false;
    }
    // RFC 9111 §5.2.2.6: `no-transform` forbids intermediaries *and* the origin from
    // changing the representation.
    if headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
        })
    {
        return false;
    }
    !headers.contains_key(hyper::header::CONTENT_RANGE)
}

/// [`is_compressible`] against a response's `Content-Type`.
fn passes_default_predicate(response: &Response<Body>) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(is_compressible)
}

/// Appends `Accept-Encoding` to `Vary` without disturbing entries already there, and
/// without duplicating it if a handler set it already.
fn add_vary_accept_encoding(headers: &mut HeaderMap) {
    let already_present = headers.get_all(VARY).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|field| field.trim().eq_ignore_ascii_case("accept-encoding"))
                // `Vary: *` already forbids any shared cache from reusing this response.
                || value.trim() == "*"
        })
    });
    if !already_present {
        headers.append(VARY, HeaderValue::from_static("accept-encoding"));
    }
}

/// Rewrites a strong `ETag` to its weak form — see the module docs on `ETag` interaction.
fn weaken_etag(headers: &mut HeaderMap) {
    let Some(etag) = headers.get(ETAG) else {
        return;
    };
    let etag = etag.as_bytes();
    if etag.starts_with(b"W/") {
        return;
    }
    // Entity tags are short, so the `W/` prefix goes on in a stack buffer; only a tag past
    // 62 bytes spills to the heap.
    let mut weakened: SmallVec<[u8; 64]> = SmallVec::with_capacity(etag.len() + 2);
    weakened.extend_from_slice(b"W/");
    weakened.extend_from_slice(etag);
    if let Ok(value) = HeaderValue::from_bytes(&weakened) {
        let _ = headers.insert(ETAG, value);
    }
}

/// Rewrites `Content-Length` to the coded length.
fn set_content_length(headers: &mut HeaderMap, len: usize) {
    let mut buffer = LengthBuffer::new();
    if let Ok(value) = HeaderValue::from_str(buffer.format(len)) {
        let _ = headers.insert(CONTENT_LENGTH, value);
    }
}

/// A stack buffer for rendering a `Content-Length` without allocating a `String` on every
/// compressed response. 20 digits holds `u64::MAX`, so it can never overflow.
struct LengthBuffer([u8; 20]);

impl LengthBuffer {
    const fn new() -> Self {
        Self([0; 20])
    }

    fn format(&mut self, mut value: usize) -> &str {
        if value == 0 {
            self.0[0] = b'0';
            return std::str::from_utf8(&self.0[..1]).unwrap_or("0");
        }
        let mut index = self.0.len();
        while value > 0 && index > 0 {
            index -= 1;
            self.0[index] = b'0' + u8::try_from(value % 10).unwrap_or(0);
            value /= 10;
        }
        std::str::from_utf8(&self.0[index..]).unwrap_or("0")
    }
}

/// Drains a [`Body`] to its bytes.
///
/// The call sites that matter hold a `Full`/`Empty` body, which cannot yield or fail, so
/// this completes on the first poll; the `Result` is only there because `BodyExt::collect`
/// is fallible for bodies in general.
async fn collect_full(body: Body) -> Result<Bytes, crate::http::error::Error> {
    use http_body_util::BodyExt;
    body.collect()
        .await
        .map(http_body_util::Collected::to_bytes)
}

pin_project_lite::pin_project! {
    /// A streaming body that codes each frame as it passes through.
    ///
    /// Frames are written into the encoder as they arrive and whatever the encoder has
    /// emitted so far is forwarded. When the inner body goes `Pending` — no more data is
    /// available *right now* — the encoder is flushed once, so a slow producer's bytes
    /// reach the client instead of sitting in a half-full compressor block until the next
    /// frame arrives. That flush costs a little ratio and is skipped entirely for a body
    /// that never blocks, which is the common case for a file or a buffered render.
    struct CompressedBody {
        #[pin]
        inner: Body,
        // `None` once `finish()` has consumed it.
        encoder: Option<codec::Encoder>,
        // Trailers seen before the encoder was flushed; re-emitted after the final block.
        pending_trailers: Option<HeaderMap>,
        flushed_while_pending: bool,
        finished: bool,
    }
}

impl HyperBody for CompressedBody {
    type Data = Bytes;
    type Error = crate::http::error::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();

        loop {
            if *this.finished {
                return Poll::Ready(this.pending_trailers.take().map(Frame::trailers).map(Ok));
            }

            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let frame = match frame.into_data() {
                        Ok(data) => {
                            if data.is_empty() {
                                continue;
                            }
                            let Some(encoder) = this.encoder.as_mut() else {
                                continue;
                            };
                            if let Err(e) = encoder.write(&data) {
                                return Poll::Ready(Some(Err(e.into())));
                            }
                            *this.flushed_while_pending = false;
                            let output = encoder.take_output();
                            if output.is_empty() {
                                // Still inside a compressor block. Ask for more input
                                // rather than emitting a zero-length frame.
                                continue;
                            }
                            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(output)))));
                        }
                        // Trailers arrive after the last data frame, so this is the end of
                        // the stream: finish the encoder, emit the tail, then the trailers.
                        Err(non_data) => non_data,
                    };
                    *this.pending_trailers = frame.into_trailers().ok();
                    match finish(this.encoder, this.finished) {
                        Ok(Some(tail)) => return Poll::Ready(Some(Ok(Frame::data(tail)))),
                        // Nothing left to emit; the next turn of the loop sees `finished`
                        // and hands back the stashed trailers.
                        Ok(None) => {}
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => match finish(this.encoder, this.finished) {
                    Ok(Some(tail)) => return Poll::Ready(Some(Ok(Frame::data(tail)))),
                    Ok(None) => {}
                    Err(e) => return Poll::Ready(Some(Err(e))),
                },
                Poll::Pending => {
                    if *this.flushed_while_pending {
                        return Poll::Pending;
                    }
                    *this.flushed_while_pending = true;
                    let Some(encoder) = this.encoder.as_mut() else {
                        return Poll::Pending;
                    };
                    if let Err(e) = encoder.flush() {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    let output = encoder.take_output();
                    if output.is_empty() {
                        return Poll::Pending;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(output)))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished && self.pending_trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        // The coded length is not known until the stream ends, and claiming the identity
        // length here would produce a `Content-Length` that lies.
        SizeHint::default()
    }
}

/// Consumes the encoder and returns its final block, or `None` if it produced no bytes.
///
/// Sets `finished` either way, so a caller looping on `Ok(None)` terminates.
fn finish(
    encoder: &mut Option<codec::Encoder>,
    finished: &mut bool,
) -> Result<Option<Bytes>, crate::http::error::Error> {
    *finished = true;
    let Some(encoder) = encoder.take() else {
        return Ok(None);
    };
    let tail = encoder.finish()?;
    Ok((!tail.is_empty()).then(|| Bytes::from(tail)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The q-value a header assigns to one coding, parsing it fresh each time.
    fn quality_of(accept_encoding: &str, encoding: Encoding) -> Option<Quality> {
        AcceptedEncodings::parse(accept_encoding).quality_of(encoding)
    }

    fn response_with(content_type: &str, body: &'static str) -> Response<Body> {
        Response::builder()
            .header(CONTENT_TYPE, content_type)
            .body(Body::full(Bytes::from_static(body.as_bytes())))
            .unwrap()
    }

    #[test]
    fn quality_parses_to_thousandths() {
        assert_eq!(parse_quality("1"), Some(1000));
        assert_eq!(parse_quality("1.0"), Some(1000));
        assert_eq!(parse_quality("0.5"), Some(500));
        assert_eq!(parse_quality("0.001"), Some(1));
        assert_eq!(parse_quality("0"), Some(0));
        // Over 1.0 is out of grammar; clamping beats rejecting the whole header.
        assert_eq!(parse_quality("2.0"), Some(1000));
        assert_eq!(parse_quality("abc"), None);
    }

    #[test]
    fn explicit_entry_beats_wildcard_even_when_lower() {
        assert_eq!(quality_of("*;q=1.0, gzip;q=0.1", Encoding::Gzip), Some(100));
        assert_eq!(
            quality_of("*;q=0.1, gzip;q=1.0", Encoding::Gzip),
            Some(1000)
        );
    }

    #[test]
    fn wildcard_covers_unlisted_codings() {
        assert_eq!(quality_of("*", Encoding::Zstd), Some(1000));
        assert_eq!(quality_of("gzip", Encoding::Zstd), None);
        assert_eq!(quality_of("*;q=0", Encoding::Zstd), None);
    }

    /// RFC 9110 §12.5.3: identity is acceptable unless explicitly, or wildcard-, refused.
    #[test]
    fn identity_is_acceptable_unless_refused() {
        assert_eq!(quality_of("gzip", Encoding::Identity), Some(1000));
        assert_eq!(quality_of("gzip, identity;q=0", Encoding::Identity), None);
        assert_eq!(quality_of("gzip, *;q=0", Encoding::Identity), None);
    }

    #[test]
    fn negotiation_respects_client_ranking_then_server_order() {
        let all = DEFAULT_PREFERENCE;
        assert_eq!(negotiate("gzip, br, zstd", &all), Encoding::Zstd);
        assert_eq!(negotiate("gzip;q=1, zstd;q=0.5", &all), Encoding::Gzip);
        assert_eq!(negotiate("zstd;q=0, br;q=0, gzip", &all), Encoding::Gzip);
        assert_eq!(negotiate("", &all), Encoding::Identity);
        assert_eq!(negotiate("identity", &all), Encoding::Identity);
        // Server preference is consulted only among codings the server enabled.
        assert_eq!(
            negotiate("gzip, br, zstd", &[Encoding::Gzip, Encoding::Brotli]),
            Encoding::Gzip,
        );
    }

    #[test]
    fn compressible_types_cover_structured_suffixes_and_exclude_packed_formats() {
        assert!(is_compressible("text/html; charset=utf-8"));
        assert!(is_compressible("application/json"));
        assert!(is_compressible("image/svg+xml"));
        assert!(is_compressible("application/manifest+json"));
        assert!(is_compressible("application/wasm"));
        assert!(is_compressible("font/ttf"));
        assert!(is_compressible(""));

        assert!(!is_compressible("text/event-stream"));
        assert!(!is_compressible("image/png"));
        assert!(!is_compressible("video/mp4"));
        assert!(!is_compressible("font/woff2"));
        assert!(!is_compressible("application/octet-stream"));
    }

    #[test]
    fn content_length_formats_without_allocating() {
        for value in [0, 1, 9, 10, 1_234_567, usize::MAX] {
            let mut buffer = LengthBuffer::new();
            assert_eq!(buffer.format(value), value.to_string());
        }
    }

    #[test]
    fn vary_is_appended_not_replaced() {
        let mut headers = HeaderMap::new();
        headers.insert(VARY, HeaderValue::from_static("accept-language"));
        add_vary_accept_encoding(&mut headers);
        let values: Vec<_> = headers
            .get_all(VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["accept-language", "accept-encoding"]);

        // Idempotent, and case-insensitive about what's already there.
        add_vary_accept_encoding(&mut headers);
        assert_eq!(headers.get_all(VARY).iter().count(), 2);

        let mut headers = HeaderMap::new();
        headers.insert(VARY, HeaderValue::from_static("Accept-Encoding, Origin"));
        add_vary_accept_encoding(&mut headers);
        assert_eq!(headers.get_all(VARY).iter().count(), 1);
    }

    #[test]
    fn strong_etags_are_weakened_and_weak_ones_left_alone() {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("\"abc\""));
        weaken_etag(&mut headers);
        assert_eq!(headers.get(ETAG).unwrap(), "W/\"abc\"");

        weaken_etag(&mut headers);
        assert_eq!(headers.get(ETAG).unwrap(), "W/\"abc\"");
    }

    #[test]
    fn ineligible_responses_are_recognised() {
        assert!(is_eligible(&response_with("text/plain", "body")));

        let mut already_coded = response_with("text/plain", "body");
        already_coded
            .headers_mut()
            .insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!is_eligible(&already_coded));

        let mut no_transform = response_with("text/plain", "body");
        no_transform.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, no-transform"),
        );
        assert!(!is_eligible(&no_transform));

        let mut not_modified = response_with("text/plain", "body");
        *not_modified.status_mut() = StatusCode::NOT_MODIFIED;
        assert!(!is_eligible(&not_modified));

        let mut partial = response_with("text/plain", "body");
        *partial.status_mut() = StatusCode::PARTIAL_CONTENT;
        assert!(!is_eligible(&partial));
    }

    /// A cache must key on `Accept-Encoding` even for the identity response, or the entry it
    /// stores for this client is later served to one that would have accepted a coding.
    ///
    /// Only meaningful in a build with a codec: with none enabled the server can never
    /// compress, and adding `Vary` would fragment caches for nothing.
    #[cfg(any(
        feature = "compression-gzip",
        feature = "compression-deflate",
        feature = "compression-br",
        feature = "compression-zstd",
    ))]
    #[tokio::test]
    async fn vary_is_set_even_when_the_client_accepts_nothing() {
        let response = Compression::new()
            .apply_to("identity", response_with("text/html", "hello world"))
            .await;
        assert!(response.headers().get(VARY).is_some());
        assert!(response.headers().get(CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn tiny_bodies_are_left_alone() {
        let response = Compression::new()
            .min_size(1024)
            .apply_to("gzip, br, zstd", response_with("text/html", "hi"))
            .await;
        assert!(response.headers().get(CONTENT_ENCODING).is_none());
    }

    /// A `Content-Encoding` this build cannot produce must never be advertised, so the
    /// enabled list only ever holds codings with a compiled-in encoder.
    #[test]
    fn only_available_codecs_are_enabled() {
        for &encoding in Compression::new().encodings() {
            assert!(encoding.encoder_available(), "{encoding} has no encoder");
        }
        // `identity` is the absence of a coding, not something to enable.
        let explicit = Compression::empty().enable(Encoding::Identity);
        assert!(explicit.encodings().is_empty());
        assert!(explicit.supports(Encoding::Identity));
    }

    #[test]
    fn preference_order_is_the_configured_one() {
        let compression = Compression::empty()
            .enable(Encoding::Gzip)
            .enable(Encoding::Brotli)
            .enable(Encoding::Gzip);
        let expected: Vec<_> = [Encoding::Gzip, Encoding::Brotli]
            .into_iter()
            .filter(|encoding| Encoding::encoder_available(*encoding))
            .collect();
        assert_eq!(
            compression.encodings(),
            expected,
            "duplicates must not stack"
        );
    }

    /// A coding is only useful if the response also says the cache must key on it, and the
    /// entity tag stops claiming to be the identity bytes.
    #[cfg(feature = "compression-gzip")]
    #[tokio::test]
    async fn compressed_response_carries_vary_encoding_and_a_weak_etag() {
        let mut original = response_with("text/plain", "hello world, hello world, hello world!");
        original
            .headers_mut()
            .insert(ETAG, HeaderValue::from_static("\"v1\""));

        let response = Compression::empty()
            .enable(Encoding::Gzip)
            .min_size(1)
            .apply_to("gzip", original)
            .await;

        assert_eq!(response.headers().get(CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(response.headers().get(ETAG).unwrap(), "W/\"v1\"");
        assert!(
            response
                .headers()
                .get_all(VARY)
                .iter()
                .any(|v| v.to_str().unwrap().eq_ignore_ascii_case("accept-encoding"))
        );

        // `Content-Length` must describe the coded bytes, not the original.
        let declared: usize = response
            .headers()
            .get(CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let body = collect_full(response.into_body()).await.unwrap();
        assert_eq!(declared, body.len());
    }

    /// Incompressible bytes come out of a codec larger than they went in; sending the
    /// original is both smaller and cheaper for the client.
    #[cfg(feature = "compression-gzip")]
    #[tokio::test]
    async fn incompressible_bodies_fall_back_to_identity() {
        // xorshift64* output, labelled as text so the content-type check lets it past. Has
        // to be genuinely high-entropy: anything a DEFLATE window can find structure in
        // would compress, and the test would prove nothing.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                u8::try_from(state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56).unwrap_or(0)
            })
            .collect();
        let original = Response::builder()
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::full(Bytes::from(noise.clone())))
            .unwrap();

        let response = Compression::empty()
            .enable(Encoding::Gzip)
            .apply_to("gzip", original)
            .await;

        assert!(response.headers().get(CONTENT_ENCODING).is_none());
        assert_eq!(collect_full(response.into_body()).await.unwrap(), noise);
    }

    #[cfg(feature = "compression-gzip")]
    #[tokio::test]
    async fn streaming_bodies_are_coded_frame_by_frame() {
        use futures::stream;
        use std::io::Read;

        let chunks: Vec<Result<Frame<Bytes>, crate::http::error::Error>> = (0..16)
            .map(|i| {
                Ok(Frame::data(Bytes::from(format!(
                    "chunk {i} of streamed text\n"
                ))))
            })
            .collect();
        let expected: Vec<u8> = (0..16)
            .flat_map(|i| format!("chunk {i} of streamed text\n").into_bytes())
            .collect();

        let original = Response::builder()
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::stream(http_body_util::StreamBody::new(stream::iter(
                chunks,
            ))))
            .unwrap();

        let response = Compression::empty()
            .enable(Encoding::Gzip)
            .apply_to("gzip", original)
            .await;

        assert_eq!(response.headers().get(CONTENT_ENCODING).unwrap(), "gzip");
        // A streamed length is unknowable up front, so no `Content-Length` may be claimed.
        assert!(response.headers().get(CONTENT_LENGTH).is_none());

        let coded = collect_full(response.into_body()).await.unwrap();
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&coded[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, expected);
    }
}
