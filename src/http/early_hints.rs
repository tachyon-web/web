//! `103 Early Hints` ([RFC 8297]) — telling the browser what to fetch while your handler is
//! still waiting on the database.
//!
//! An informational response is sent *during* server think-time, before the final status
//! line, carrying [RFC 8288] `Link` headers:
//!
//! ```text
//! HTTP/2 103 Early Hints
//! link: </static/app.css>; rel=preload; as=style
//! link: <https://cdn.example.com>; rel=preconnect
//!
//! HTTP/2 200 OK
//! content-type: text/html
//! ```
//!
//! The browser starts those fetches immediately instead of waiting for the HTML to arrive
//! and be parsed. On a handler with real latency this removes a full round trip from the
//! critical path; on a handler that responds in two milliseconds it does nothing at all,
//! which is worth knowing before enabling it everywhere.
//!
//! # Why this needs framework support
//!
//! An informational response is a *second* response on the same request. The
//! `Service<Request> → Response` signature every Rust HTTP framework is built on returns
//! one, so this cannot be a middleware — it needs a hole through the handler API and 1xx
//! support in the HTTP stack underneath. `hyper` has neither: `proto/h1/role.rs` refuses a
//! 1xx status outright, and its HTTP/2 path never calls `h2`'s `send_informational`. So
//! Tachyon drives [`h2`](https://docs.rs/h2) directly for HTTP/2 connections when early
//! hints are enabled, and emits the hint frame itself over HTTP/3.
//!
//! # Transport support
//!
//! | Transport | Emitted? | Why |
//! |---|---|---|
//! | HTTP/2 over TLS ([`serve_https`]) | **Yes** | native `h2` driver, see below |
//! | HTTP/3 ([`serve_h3`]) | **Yes** | Tachyon owns the HTTP/3 dispatch loop |
//! | HTTP/1.1 | No | intermediaries mis-parse an unexpected 1xx; no browser acts on it |
//! | h2c ([`serve_http`]) | No | no browser speaks cleartext HTTP/2 |
//! | Tor, I2P | No | HTTP/1.1 transports |
//!
//! [`EarlyHints::is_supported`] reports which case a given request is in, so a handler can
//! skip building hints it cannot send. [`EarlyHints::send`] on an unsupported transport is
//! a no-op that returns `false` — never an error, and never a wasted allocation past the
//! `Link`s the caller already built.
//!
//! ## Enabling the native HTTP/2 driver
//!
//! [`Server::early_hints`](crate::Server::early_hints) switches HTTPS connections that
//! negotiate `h2` from `hyper`'s HTTP/2 server onto Tachyon's own. Connections that do not
//! negotiate `h2` are untouched. The one behavioural difference is **RFC 8441 `WebSocket`s
//! over HTTP/2**: those rely on `hyper`'s upgrade machinery, so under the native driver an
//! extended `CONNECT` is answered with `501 Not Implemented`. No browser uses RFC 8441 —
//! they all open `WebSocket`s over HTTP/1.1 — but a non-browser client that does will notice.
//!
//! # Two ways to send
//!
//! **Declarative**, for hints that don't depend on the request. The header block is built
//! once at startup and the hint goes out *before* the handler is even called, so there is
//! no per-request formatting and no way to forget:
//!
//! ```rust
//! use tachyon_web::{Router, get};
//! use tachyon_web::http::early_hints::Link;
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "…" }))
//!     .early_hints([
//!         Link::preload("/static/app.css").as_style(),
//!         Link::preconnect("https://cdn.example.com"),
//!     ]);
//! ```
//!
//! **Imperative**, when the hints depend on the request — extract [`EarlyHints`] and fire
//! it before the work you're trying to overlap:
//!
//! ```rust
//! use tachyon_web::http::early_hints::{EarlyHints, Link};
//! use tachyon_web::{Html, Path};
//!
//! async fn product_page(hints: EarlyHints, Path(id): Path<String>) -> Html<String> {
//!     hints.send([
//!         Link::preload("/static/product.css").as_style(),
//!         Link::preload(&format!("/api/products/{id}/image")).as_image(),
//!     ]); // returns immediately — nothing to await
//!
//!     // The think-time this feature exists to overlap.
//!     let product = load_product(&id).await;
//!     Html(render(&product))
//! }
//! # async fn load_product(_: &str) -> String { String::new() }
//! # fn render(_: &str) -> String { String::new() }
//! ```
//!
//! # Traps
//!
//! - **Hints are gated on `Sec-Fetch-Mode: navigate` by default.** Old clients, bots and
//!   some proxies mishandle an informational response they did not expect, and a browser
//!   only acts on 103 for a navigation anyway. See
//!   [`EarlyHintsConfig::require_navigation`] to change this — and read why first.
//! - **Never hint before a redirect.** Hints preceding a `3xx` preload resources for a page
//!   that is never rendered. If a handler might redirect, hint after that decision, not
//!   before. The declarative form cannot know, so don't attach it to routes that redirect.
//! - **A 103 is not cacheable.** A cache hit on the final `200` serves it without the
//!   hints, so full-page caching and early hints do not compose.
//! - **CDNs may buffer or strip them.** Verify end-to-end through whatever sits in front of
//!   the origin, not just against the origin.
//!
//! [RFC 8297]: https://www.rfc-editor.org/rfc/rfc8297
//! [RFC 8288]: https://www.rfc-editor.org/rfc/rfc8288
//! [`serve_https`]: crate::Server::serve_https
//! [`serve_h3`]: crate::Server::serve_h3
//! [`serve_http`]: crate::Server::serve_http

use hyper::header::{HeaderMap, HeaderValue, LINK};
use std::sync::Arc;

/// How many informational responses one request may send, in total.
///
/// [RFC 8297 §2] permits any number, but browsers act on the first and each one costs a
/// header block on the wire. A small cap keeps a buggy handler from turning a hot path into
/// a frame storm while leaving room for the legitimate "hint what I know now, hint the rest
/// once the session is resolved" pattern.
///
/// This is a lifetime budget for the request, not a queue depth: the transport drains hints
/// as fast as the handler queues them, so a bound on the channel alone would let a handler
/// looping on [`EarlyHints::send`] emit frames without limit — and, because the transport
/// drains before it polls the handler, starve its own response in the process.
///
/// [RFC 8297 §2]: https://www.rfc-editor.org/rfc/rfc8297#section-2
pub const MAX_HINTS_PER_REQUEST: usize = 4;

/// How many `Link` values one hint may carry.
///
/// A header block big enough to exceed the peer's `SETTINGS_MAX_HEADER_LIST_SIZE` is
/// refused wholesale, taking the hint's useful links down with the surplus, so the block is
/// truncated here instead.
pub const MAX_LINKS_PER_HINT: usize = 32;

/// A fetch destination, the `as=` parameter of a `rel=preload` link.
///
/// Required on every `preload`: without it the browser cannot apply the right `Accept`
/// header, request priority, or CSP directive, and Chrome logs a console warning and
/// fetches the resource a *second* time when the real request turns out to differ. Values
/// come from the [HTML fetch destination] list.
///
/// [HTML fetch destination]: https://fetch.spec.whatwg.org/#concept-request-destination
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum As {
    /// A stylesheet — `<link rel=stylesheet>`.
    Style,
    /// A classic script — `<script src>`.
    Script,
    /// A font. Always needs [`Link::crossorigin`]; fonts are fetched in CORS mode even
    /// same-origin, and a preload without it is fetched twice.
    Font,
    /// An image — `<img>`, `<picture>`, CSS `url()`.
    Image,
    /// A `fetch()` or `XMLHttpRequest` request.
    Fetch,
    /// A nested document — `<iframe>`.
    Document,
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// A `<track>` text track.
    Track,
    /// A web worker.
    Worker,
    /// An embed or object.
    Embed,
    /// A `<link rel=manifest>` web app manifest.
    Manifest,
}

impl As {
    /// The token as it appears in the `as=` parameter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Style => "style",
            Self::Script => "script",
            Self::Font => "font",
            Self::Image => "image",
            Self::Fetch => "fetch",
            Self::Document => "document",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Track => "track",
            Self::Worker => "worker",
            Self::Embed => "embed",
            Self::Manifest => "manifest",
        }
    }
}

impl std::fmt::Display for As {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The CORS mode a preload is fetched in — the `crossorigin=` parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossOrigin {
    /// CORS request without credentials. What fonts and most cross-origin assets need.
    Anonymous,
    /// CORS request with cookies and HTTP auth attached.
    UseCredentials,
}

impl CrossOrigin {
    /// The token as it appears in the `crossorigin=` parameter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::UseCredentials => "use-credentials",
        }
    }
}

/// The `fetchpriority=` hint, relative to other resources of the same destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchPriority {
    /// Raise this above the browser's default for its destination.
    High,
    /// Lower it.
    Low,
    /// Leave it to the browser. Emitting this is the same as omitting the parameter, and
    /// it is skipped on the wire.
    Auto,
}

impl FetchPriority {
    /// The token as it appears in the `fetchpriority=` parameter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Low => "low",
            Self::Auto => "auto",
        }
    }
}

/// The relation type — the `rel=` parameter, and the thing that decides what the browser
/// actually does with the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rel {
    /// Fetch and cache the resource now, at high priority, for use by this navigation.
    Preload,
    /// Fetch a JavaScript module and its dependency graph.
    Modulepreload,
    /// Open the connection — DNS, TCP and TLS — without fetching anything. The one hint
    /// Safari acts on.
    Preconnect,
    /// Resolve the hostname only. Cheaper and weaker than `preconnect`.
    DnsPrefetch,
    /// Fetch at low priority for a *future* navigation, not this one.
    Prefetch,
}

impl Rel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preload => "preload",
            Self::Modulepreload => "modulepreload",
            Self::Preconnect => "preconnect",
            Self::DnsPrefetch => "dns-prefetch",
            Self::Prefetch => "prefetch",
        }
    }
}

/// One [RFC 8288] `Link` header field value.
///
/// Built with a constructor per relation type, then narrowed with the parameter methods:
///
/// ```rust
/// use tachyon_web::http::early_hints::{CrossOrigin, FetchPriority, Link};
///
/// // </static/app.css>; rel=preload; as=style
/// let css = Link::preload("/static/app.css").as_style();
///
/// // </static/inter.woff2>; rel=preload; as=font; type="font/woff2"; crossorigin=anonymous
/// let font = Link::preload("/static/inter.woff2")
///     .as_font()
///     .mime_type("font/woff2")
///     .crossorigin(CrossOrigin::Anonymous);
///
/// // <https://cdn.example.com>; rel=preconnect
/// let cdn = Link::preconnect("https://cdn.example.com");
///
/// assert_eq!(css.to_header_value().unwrap(), "</static/app.css>; rel=preload; as=style");
/// # let _ = (font, cdn, FetchPriority::High);
/// ```
///
/// [RFC 8288]: https://www.rfc-editor.org/rfc/rfc8288
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    target: String,
    rel: Rel,
    destination: Option<As>,
    mime_type: Option<String>,
    media: Option<String>,
    crossorigin: Option<CrossOrigin>,
    fetch_priority: Option<FetchPriority>,
    imagesrcset: Option<String>,
    imagesizes: Option<String>,
    integrity: Option<String>,
    nonce: Option<String>,
}

impl Link {
    fn new(rel: Rel, target: &str) -> Self {
        Self {
            target: target.to_owned(),
            rel,
            destination: None,
            mime_type: None,
            media: None,
            crossorigin: None,
            fetch_priority: None,
            imagesrcset: None,
            imagesizes: None,
            integrity: None,
            nonce: None,
        }
    }

    /// `rel=preload` — fetch `target` now, for this navigation.
    ///
    /// Pair it with a destination ([`as_style`](Self::as_style) and friends); a preload
    /// without one is fetched twice by Chrome.
    #[must_use]
    pub fn preload(target: &str) -> Self {
        Self::new(Rel::Preload, target)
    }

    /// `rel=modulepreload` — fetch a JavaScript module and its dependency graph.
    #[must_use]
    pub fn modulepreload(target: &str) -> Self {
        Self::new(Rel::Modulepreload, target)
    }

    /// `rel=preconnect` — open the DNS/TCP/TLS connection to an origin without fetching
    /// anything. The only relation Safari acts on in a 103.
    #[must_use]
    pub fn preconnect(target: &str) -> Self {
        Self::new(Rel::Preconnect, target)
    }

    /// `rel=dns-prefetch` — resolve a hostname only. Cheaper and weaker than
    /// [`preconnect`](Self::preconnect).
    #[must_use]
    pub fn dns_prefetch(target: &str) -> Self {
        Self::new(Rel::DnsPrefetch, target)
    }

    /// `rel=prefetch` — fetch at low priority for a *later* navigation.
    ///
    /// Rarely what you want in a 103, which exists to accelerate the navigation already in
    /// flight; [`preload`](Self::preload) is almost always the right choice there.
    #[must_use]
    pub fn prefetch(target: &str) -> Self {
        Self::new(Rel::Prefetch, target)
    }

    /// Sets the `as=` fetch destination.
    #[must_use]
    pub const fn destination(mut self, destination: As) -> Self {
        self.destination = Some(destination);
        self
    }

    /// `as=style`.
    #[must_use]
    pub const fn as_style(self) -> Self {
        self.destination(As::Style)
    }

    /// `as=script`.
    #[must_use]
    pub const fn as_script(self) -> Self {
        self.destination(As::Script)
    }

    /// `as=font`. Remember [`crossorigin`](Self::crossorigin) — fonts are fetched in CORS
    /// mode even same-origin, and a preload without it is fetched twice.
    #[must_use]
    pub const fn as_font(self) -> Self {
        self.destination(As::Font)
    }

    /// `as=image`.
    #[must_use]
    pub const fn as_image(self) -> Self {
        self.destination(As::Image)
    }

    /// `as=fetch`.
    #[must_use]
    pub const fn as_fetch(self) -> Self {
        self.destination(As::Fetch)
    }

    /// Sets `type=`, the resource's expected media type. Lets the browser skip the fetch
    /// entirely if it cannot handle the type.
    #[must_use]
    pub fn mime_type(mut self, mime_type: &str) -> Self {
        self.mime_type = Some(mime_type.to_owned());
        self
    }

    /// Sets `media=`, a media query gating the fetch — `(max-width: 600px)`.
    #[must_use]
    pub fn media(mut self, media: &str) -> Self {
        self.media = Some(media.to_owned());
        self
    }

    /// Sets `crossorigin=`.
    #[must_use]
    pub const fn crossorigin(mut self, mode: CrossOrigin) -> Self {
        self.crossorigin = Some(mode);
        self
    }

    /// Sets `fetchpriority=`. [`FetchPriority::Auto`] is the default and is not emitted.
    #[must_use]
    pub const fn fetch_priority(mut self, priority: FetchPriority) -> Self {
        self.fetch_priority = Some(priority);
        self
    }

    /// Sets `imagesrcset=`, mirroring `<img srcset>` so a responsive image preloads the
    /// same candidate the markup will pick.
    #[must_use]
    pub fn imagesrcset(mut self, srcset: &str) -> Self {
        self.imagesrcset = Some(srcset.to_owned());
        self
    }

    /// Sets `imagesizes=`, mirroring `<img sizes>`.
    #[must_use]
    pub fn imagesizes(mut self, sizes: &str) -> Self {
        self.imagesizes = Some(sizes.to_owned());
        self
    }

    /// Sets `integrity=`, a Subresource Integrity digest.
    #[must_use]
    pub fn integrity(mut self, integrity: &str) -> Self {
        self.integrity = Some(integrity.to_owned());
        self
    }

    /// Sets `nonce=`, to satisfy a nonce-based Content Security Policy.
    #[must_use]
    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_owned());
        self
    }

    /// Renders this link as a `Link` header value.
    ///
    /// Returns `None` if the target or any parameter contains bytes that cannot appear in a
    /// header field value — control characters, or the `<`/`>` that delimit the target.
    /// That check is the reason this is fallible: a target built from user input could
    /// otherwise close the angle brackets early and inject arbitrary link parameters, or
    /// smuggle a `\r\n` and split the header block.
    #[must_use]
    pub fn to_header_value(&self) -> Option<HeaderValue> {
        if !is_safe_target(&self.target) {
            return None;
        }
        let mut rendered = String::with_capacity(self.target.len() + 32);
        rendered.push('<');
        rendered.push_str(&self.target);
        rendered.push_str(">; rel=");
        rendered.push_str(self.rel.as_str());

        if let Some(destination) = self.destination {
            rendered.push_str("; as=");
            rendered.push_str(destination.as_str());
        }
        if let Some(crossorigin) = self.crossorigin {
            rendered.push_str("; crossorigin=");
            rendered.push_str(crossorigin.as_str());
        }
        // `auto` is the browser default; emitting it is noise.
        if let Some(priority) = self.fetch_priority
            && priority != FetchPriority::Auto
        {
            rendered.push_str("; fetchpriority=");
            rendered.push_str(priority.as_str());
        }
        for (name, value) in [
            ("type", self.mime_type.as_deref()),
            ("media", self.media.as_deref()),
            ("imagesrcset", self.imagesrcset.as_deref()),
            ("imagesizes", self.imagesizes.as_deref()),
            ("integrity", self.integrity.as_deref()),
            ("nonce", self.nonce.as_deref()),
        ] {
            let Some(value) = value else { continue };
            // These carry commas, semicolons and spaces as a matter of course
            // (`imagesrcset`, `media`), so they are always quoted-string per RFC 8288 §3.
            if !is_safe_quoted(value) {
                return None;
            }
            rendered.push_str("; ");
            rendered.push_str(name);
            rendered.push_str("=\"");
            rendered.push_str(value);
            rendered.push('"');
        }

        HeaderValue::from_str(&rendered).ok()
    }
}

/// Whether a link target can safely sit between the `<` and `>` of a `Link` value.
///
/// Rejects the delimiters themselves, ASCII whitespace, and every control character —
/// including the CR and LF that would otherwise let a caller inject a header of their own.
/// Restricted to visible ASCII: everything a URI reference may legally contain, and nothing
/// else. `obs-text` (0x80-0xFF) is legal in a header value but never legal in a URI, so
/// accepting it would only widen what a target built from user input can smuggle through.
fn is_safe_target(target: &str) -> bool {
    !target.is_empty()
        && target
            .bytes()
            .all(|b| b > 0x20 && b < 0x7f && b != b'<' && b != b'>')
}

/// Whether a value can safely sit inside a `Link` parameter's quoted-string.
///
/// Rejects the closing quote, the backslash that would escape it, and everything outside
/// visible ASCII plus space — see [`is_safe_target`] on why `obs-text` is refused.
fn is_safe_quoted(value: &str) -> bool {
    value
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

/// Renders `links` into the header block of a `103` response, once.
///
/// Links that fail validation are dropped with a warning rather than poisoning the whole
/// block — one bad target should not cost the others their head start. At most
/// [`MAX_LINKS_PER_HINT`] survive; the rest are dropped so an oversized block cannot cost
/// the hint every link it carried.
#[must_use]
pub fn links_to_headers(links: impl IntoIterator<Item = Link>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for link in links {
        if headers.len() >= MAX_LINKS_PER_HINT {
            tracing::warn!("early-hint truncated at {MAX_LINKS_PER_HINT} links");
            break;
        }
        match link.to_header_value() {
            Some(value) => {
                let _ = headers.append(LINK, value);
            }
            None => {
                tracing::warn!(target = %link.target, "dropping unserialisable early-hint link");
            }
        }
    }
    headers
}

/// Configuration for [`Server::early_hints`](crate::Server::early_hints).
#[derive(Clone, Debug)]
pub struct EarlyHintsConfig {
    require_navigation: bool,
}

impl Default for EarlyHintsConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EarlyHintsConfig {
    /// The recommended configuration: hints only on top-level navigations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            require_navigation: true,
        }
    }

    /// Whether to send hints only for requests carrying `Sec-Fetch-Mode: navigate`
    /// (default: `true`).
    ///
    /// Leave this on unless you have a specific reason not to. Two independent arguments
    /// for it:
    ///
    /// - **Nothing else acts on a 103.** A browser applies early hints to a navigation. For
    ///   a `fetch()`, an image, or a subresource, the hint is parsed and discarded — pure
    ///   overhead on a request that already has a warm connection.
    /// - **Not everything tolerates an unexpected 1xx.** Older intermediaries, some
    ///   corporate proxies, and a long tail of non-browser clients mishandle an
    ///   informational response they did not ask for. Requiring `Sec-Fetch-Mode` confines
    ///   hints to clients modern enough to send Fetch Metadata in the first place, which is
    ///   the same population that understands 103.
    ///
    /// Turning it off is reasonable for a closed deployment — an internal service with a
    /// known client that wants hints on API calls — and a bad idea on the public internet.
    #[must_use]
    pub const fn require_navigation(mut self, require: bool) -> Self {
        self.require_navigation = require;
        self
    }

    /// Whether this request may receive early hints at all, given its method and headers.
    ///
    /// Applied by the transport before it hands a live [`EarlyHints`] to the handler, so a
    /// handler never has to repeat these checks.
    pub(crate) fn permits(&self, method: &hyper::Method, headers: &HeaderMap) -> bool {
        // A 103 accelerates the rendering of a page. `POST`/`PUT`/`DELETE` either redirect
        // afterwards or return no document, so hints attached to them preload for a page
        // that may never be shown.
        if method != hyper::Method::GET && method != hyper::Method::HEAD {
            return false;
        }
        if !self.require_navigation {
            return true;
        }
        headers
            .get("sec-fetch-mode")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|mode| mode.eq_ignore_ascii_case("navigate"))
    }
}

/// The channel a transport listens on for hints to emit. Bounded, so a handler in a loop
/// cannot queue unbounded header blocks against a slow connection.
pub(crate) type HintSender = tokio::sync::mpsc::Sender<HeaderMap>;

/// A handle for sending `103 Early Hints` before the final response.
///
/// Obtained as a handler argument — it is an extractor — and always succeeds: on a
/// transport that cannot emit a 103, or a request the configuration excludes, extraction
/// yields a handle whose [`send`](Self::send) is a no-op. Handlers therefore never need a
/// fallback path, and adding hints to a handler cannot make it start failing.
///
/// Cheap to clone; clones share one budget of [`MAX_HINTS_PER_REQUEST`] sends.
#[derive(Clone)]
pub struct EarlyHints {
    /// `None` on a transport that cannot emit informational responses, or when the request
    /// did not pass [`EarlyHintsConfig::permits`].
    sender: Option<Arc<HintChannel>>,
}

/// The sender plus this request's remaining hint budget, shared by every clone of a handle.
pub(crate) struct HintChannel {
    sender: HintSender,
    /// Counts sends that were accepted. Compared against [`MAX_HINTS_PER_REQUEST`] rather
    /// than relying on the channel filling up, because the transport drains it eagerly.
    sent: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for EarlyHints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EarlyHints")
            .field("supported", &self.is_supported())
            .finish()
    }
}

impl EarlyHints {
    /// A handle that discards everything sent to it — what a handler gets on HTTP/1.1, on a
    /// non-navigation request, or when the server has no early-hints configuration.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { sender: None }
    }

    /// Wires a handle to a transport's hint channel.
    pub(crate) fn new(sender: HintSender) -> Self {
        Self {
            sender: Some(Arc::new(HintChannel {
                sender,
                sent: std::sync::atomic::AtomicUsize::new(0),
            })),
        }
    }

    /// Whether a hint sent through this handle would actually reach the client.
    ///
    /// Worth checking only to skip *building* hints that would be discarded — the send
    /// itself is already free when unsupported.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.sender.is_some()
    }

    /// Sends a `103 Early Hints` response carrying `links`.
    ///
    /// Returns immediately without blocking: the hint is handed to the connection task,
    /// which writes it while this handler goes on to do its work. That is the whole point —
    /// awaiting it would serialise the hint against the think-time it exists to overlap.
    ///
    /// Returns `true` if the hint was queued. `false` means it was dropped, for one of:
    /// this transport cannot emit a 103; the request was excluded by
    /// [`EarlyHintsConfig`]; the final response has already been sent; or this request has
    /// used its budget of [`MAX_HINTS_PER_REQUEST`] hints. None of these are errors, and
    /// none need handling — the page still loads, just without the head start.
    pub fn send(&self, links: impl IntoIterator<Item = Link>) -> bool {
        let Some(sender) = self.sender.as_ref() else {
            return false;
        };
        let headers = links_to_headers(links);
        if headers.is_empty() {
            return false;
        }
        Self::send_headers_via(sender, headers)
    }

    /// [`send`](Self::send) with a pre-rendered header block, skipping the per-request cost
    /// of formatting `Link` values.
    ///
    /// This is what the declarative [`Router::early_hints`](crate::Router::early_hints)
    /// form uses. Reach for it directly when the same hints go out on a hot path: build the
    /// [`HeaderMap`] once with [`links_to_headers`] and clone it per request.
    ///
    /// The headers are sent as given. Only `Link` is meaningful to a browser in a 103;
    /// anything else is legal on the wire and ignored.
    #[must_use]
    pub fn send_headers(&self, headers: HeaderMap) -> bool {
        let Some(sender) = self.sender.as_ref() else {
            return false;
        };
        if headers.is_empty() {
            return false;
        }
        Self::send_headers_via(sender, headers)
    }

    fn send_headers_via(channel: &HintChannel, headers: HeaderMap) -> bool {
        use std::sync::atomic::Ordering;

        if channel
            .sent
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |sent| {
                (sent < MAX_HINTS_PER_REQUEST).then_some(sent + 1)
            })
            .is_err()
        {
            tracing::debug!("early-hint dropped: request already sent {MAX_HINTS_PER_REQUEST}");
            return false;
        }

        match channel.sender.try_send(headers) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}

impl<S> crate::routing::extract::FromRequestParts<S> for EarlyHints {
    /// Extraction cannot fail — an unsupported transport yields a no-op handle.
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<Self>()
            .cloned()
            .unwrap_or_else(Self::disabled))
    }
}

/// Builds the bounded channel a transport drives, plus the handle to put in the request's
/// extensions.
pub(crate) fn channel() -> (tokio::sync::mpsc::Receiver<HeaderMap>, EarlyHints) {
    let (tx, rx) = tokio::sync::mpsc::channel(MAX_HINTS_PER_REQUEST);
    (rx, EarlyHints::new(tx))
}

#[cfg(test)]
mod tests {
    use super::{As, CrossOrigin, EarlyHints, EarlyHintsConfig, FetchPriority, Link};
    use hyper::header::LINK;

    fn rendered(link: &Link) -> String {
        link.to_header_value()
            .expect("link must serialise")
            .to_str()
            .expect("ASCII")
            .to_string()
    }

    #[test]
    fn links_render_in_rfc_8288_form() {
        assert_eq!(
            rendered(&Link::preload("/static/app.css").as_style()),
            "</static/app.css>; rel=preload; as=style",
        );
        assert_eq!(
            rendered(&Link::preconnect("https://cdn.example.com")),
            "<https://cdn.example.com>; rel=preconnect",
        );
        assert_eq!(
            rendered(&Link::modulepreload("/static/app.mjs")),
            "</static/app.mjs>; rel=modulepreload",
        );
        assert_eq!(
            rendered(&Link::dns_prefetch("https://analytics.example.com")),
            "<https://analytics.example.com>; rel=dns-prefetch",
        );
    }

    #[test]
    fn parameters_render_in_a_stable_order_with_quoting_where_needed() {
        let link = Link::preload("/static/inter.woff2")
            .as_font()
            .mime_type("font/woff2")
            .crossorigin(CrossOrigin::Anonymous)
            .fetch_priority(FetchPriority::High);
        assert_eq!(
            rendered(&link),
            "</static/inter.woff2>; rel=preload; as=font; crossorigin=anonymous; \
             fetchpriority=high; type=\"font/woff2\"",
        );

        // `imagesrcset` is full of commas and spaces, so it must be a quoted-string.
        let responsive = Link::preload("/img/hero-800.avif")
            .destination(As::Image)
            .imagesrcset("/img/hero-400.avif 400w, /img/hero-800.avif 800w")
            .imagesizes("(max-width: 600px) 400px, 800px");
        assert_eq!(
            rendered(&responsive),
            "</img/hero-800.avif>; rel=preload; as=image; \
             imagesrcset=\"/img/hero-400.avif 400w, /img/hero-800.avif 800w\"; \
             imagesizes=\"(max-width: 600px) 400px, 800px\"",
        );
    }

    /// `fetchpriority=auto` is the browser default, so emitting it is pure wire noise.
    #[test]
    fn auto_fetch_priority_is_omitted() {
        let link = Link::preload("/a.js")
            .as_script()
            .fetch_priority(FetchPriority::Auto);
        assert_eq!(rendered(&link), "</a.js>; rel=preload; as=script");
    }

    /// A target built from user input must not be able to close the angle brackets, add
    /// parameters of its own, or split the header block.
    #[test]
    fn injection_attempts_are_refused_not_escaped() {
        for hostile in [
            "/a>; rel=preconnect; <//evil.example.com",
            "/a\r\nset-cookie: session=stolen",
            "/a\nlink: <//evil.example.com>",
            "/a b",
            "/a\u{7f}",
            "",
        ] {
            assert!(
                Link::preload(hostile)
                    .as_script()
                    .to_header_value()
                    .is_none(),
                "accepted hostile target {hostile:?}",
            );
        }

        // The same for a quoted parameter closing its own quote.
        assert!(
            Link::preload("/a.css")
                .as_style()
                .media("all\"; rel=\"preconnect")
                .to_header_value()
                .is_none()
        );
    }

    /// One unserialisable link must not cost the rest of the block its head start.
    #[test]
    fn unserialisable_links_are_dropped_individually() {
        let headers = super::links_to_headers([
            Link::preload("/good.css").as_style(),
            Link::preload("/bad\r\nx: y").as_script(),
            Link::preconnect("https://cdn.example.com"),
        ]);
        let values: Vec<_> = headers
            .get_all(LINK)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            values,
            vec![
                "</good.css>; rel=preload; as=style",
                "<https://cdn.example.com>; rel=preconnect",
            ],
        );
    }

    fn permits(
        config: &EarlyHintsConfig,
        method: &hyper::Method,
        sec_fetch_mode: Option<&str>,
    ) -> bool {
        let mut headers = hyper::HeaderMap::new();
        if let Some(mode) = sec_fetch_mode {
            let _ = headers.insert("sec-fetch-mode", mode.parse().unwrap());
        }
        config.permits(method, &headers)
    }

    #[test]
    fn only_navigations_are_hinted_by_default() {
        let config = EarlyHintsConfig::new();
        assert!(permits(&config, &hyper::Method::GET, Some("navigate")));
        assert!(permits(&config, &hyper::Method::GET, Some("NAVIGATE")));

        assert!(!permits(&config, &hyper::Method::GET, Some("cors")));
        assert!(!permits(&config, &hyper::Method::GET, Some("no-cors")));
        assert!(!permits(&config, &hyper::Method::GET, None));
        assert!(!permits(&config, &hyper::Method::POST, Some("navigate")));
    }

    #[test]
    fn relaxed_config_still_refuses_unsafe_methods() {
        let config = EarlyHintsConfig::new().require_navigation(false);
        assert!(permits(&config, &hyper::Method::GET, None));
        assert!(permits(&config, &hyper::Method::HEAD, None));
        // A `POST` either redirects or returns no document; hints on it preload for a page
        // that may never render.
        assert!(!permits(&config, &hyper::Method::POST, None));
    }

    #[tokio::test]
    async fn sends_are_capped_and_stop_once_the_transport_is_gone() {
        let (mut receiver, hints) = super::channel();
        assert!(hints.is_supported());

        for _ in 0..super::MAX_HINTS_PER_REQUEST {
            assert!(hints.send([Link::preconnect("https://cdn.example.com")]));
        }
        assert!(!hints.send([Link::preconnect("https://cdn.example.com")]));

        // The budget is for the request, not for the queue: draining what the transport
        // has already taken must not hand the handler a fresh allowance, or a handler
        // looping on `send` would emit frames without limit.
        let _ = receiver.recv().await;
        assert!(!hints.send([Link::preconnect("https://cdn.example.com")]));

        // A clone shares the budget rather than getting one of its own.
        assert!(
            !hints
                .clone()
                .send([Link::preconnect("https://cdn.example.com")])
        );

        // Once the final response is on the wire the transport drops the receiver.
        drop(receiver);
        assert!(!hints.send([Link::preconnect("https://cdn.example.com")]));
    }

    #[test]
    fn a_disabled_handle_swallows_everything() {
        let hints = EarlyHints::disabled();
        assert!(!hints.is_supported());
        assert!(!hints.send([Link::preload("/app.css").as_style()]));
        assert!(format!("{hints:?}").contains("supported: false"));
    }

    /// An empty hint block is not worth a frame.
    #[tokio::test]
    async fn empty_hints_are_not_sent() {
        let (_receiver, hints) = super::channel();
        assert!(!hints.send([]));
        assert!(!hints.send_headers(hyper::HeaderMap::new()));
    }
}
