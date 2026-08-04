//! [`ServeDir`]: static file serving from a preloaded in-memory directory.

use crate::http::compression::{Encoding, negotiate};
use crate::http::response::{Body, IntoResponse};
use bytes::Bytes;
use hyper::{
    Response, StatusCode,
    header::{
        CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, ETAG, IF_NONE_MATCH, VARY,
        X_CONTENT_TYPE_OPTIONS,
    },
};
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

/// Hash map keyed by asset path, using `FxHash` instead of the default
/// `SipHash`: the key set is fixed after `preload()`/`crawl_dir()`, so the
/// DoS-resistance `SipHash` provides buys nothing here, only lookup latency.
type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;

/// Configuration for in-memory file caching.
///
/// Defaults: enabled, 64 MiB total cap, 2 MiB per-file cap.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Whether RAM caching is *permitted*. This only takes effect once
    /// [`ServeDir::preload`] is actually called — `enabled: true` alone does not
    /// populate the cache; it just means a subsequent `.preload().await` won't be a
    /// no-op. [`Router::serve_static`](crate::routing::Router::serve_static), the
    /// most common entry point, never calls `.preload()`, so caching stays off by
    /// default there even though this field defaults to `true`. Set `false` to make
    /// `.preload()` itself a no-op and always serve from disk.
    pub enabled: bool,
    /// Maximum total RAM used by the cache in bytes. Default: 64 MiB.
    pub max_total_bytes: usize,
    /// Maximum size of a single file that will be cached. Default: 2 MiB.
    pub max_file_bytes: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_total_bytes: 64 * 1024 * 1024,
            max_file_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Maps a file extension to a MIME type, by extension only — this never inspects
/// file content, so a `.svg` is always reported as `image/svg+xml` regardless of
/// whether it contains a `<script>`. See the `ServeDir` docs' upload-safety
/// warning before pointing a `ServeDir` at a directory that can contain files an
/// untrusted user chose the bytes of.
pub(crate) fn guess_mime_type(path: &Path) -> &'static str {
    const DEFAULT: &str = "application/octet-stream";
    /// Longest extension in the table below (`webmanifest`), with headroom. Anything
    /// longer can't match, so it doesn't need lowercasing at all.
    const MAX_EXT_LEN: usize = 16;

    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return DEFAULT;
    };
    if ext.len() > MAX_EXT_LEN {
        return DEFAULT;
    }

    let mut buf = [0u8; MAX_EXT_LEN];
    let lowered = &mut buf[..ext.len()];
    lowered.copy_from_slice(ext.as_bytes());
    lowered.make_ascii_lowercase();
    let Ok(ext) = std::str::from_utf8(lowered) else {
        return DEFAULT;
    };

    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "wasm" => "application/wasm",
        "webmanifest" => "application/manifest+json",
        "xml" => "text/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" | "svgz" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "mp3" => "audio/mpeg",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        _ => DEFAULT,
    }
}

/// Validates that `candidate` lives inside `base` (path-traversal guard).
fn is_safe_path(base: &Path, candidate: &Path) -> bool {
    candidate.starts_with(base)
}

/// Files at or below this size are read into one buffer and served from memory; anything larger
/// is streamed off disk in [`STREAM_CHUNK`]-sized frames, keeping the per-request memory cost
/// constant rather than N × file size for N concurrent requests.
const STREAM_THRESHOLD: u64 = 1024 * 1024;

/// Chunk size used when streaming a file off disk.
const STREAM_CHUNK: usize = 64 * 1024;

/// Whether `accept_encoding` positively accepts `token`: a token match against each
/// comma-separated coding, honoring `q=0` (a client's explicit refusal of that coding).
/// Server preference among pre-compressed sidecars.
///
/// Brotli leads here even though [`DEFAULT_PREFERENCE`] leads with zstd. That default is
/// tuned for a body compressed once per request, where zstd's throughput dominates; a
/// sidecar was compressed once at build time, so only the ratio it achieved still matters,
/// and Brotli wins that. `deflate` is absent — nothing ships a `.zz` sidecar.
///
/// [`DEFAULT_PREFERENCE`]: crate::http::compression::DEFAULT_PREFERENCE
const SIDECAR_PREFERENCE: [Encoding; 3] = [Encoding::Brotli, Encoding::Zstd, Encoding::Gzip];

/// Whether `if_none_match` should suppress the body, per RFC 9110 §13.1.2.
///
/// The header is a comma-separated list of entity tags, or the wildcard `*`. Tags are compared
/// with the weak comparison function, so a `W/`-prefixed tag matches the same entity.
fn if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    let header = if_none_match.trim();
    if header.is_empty() {
        return false;
    }
    if header == "*" {
        return true;
    }
    let etag = strip_weak(etag);
    header
        .split(',')
        .any(|candidate| strip_weak(candidate.trim()) == etag)
}

/// Drops the `W/` weakness indicator from an entity tag, leaving the quoted opaque value.
fn strip_weak(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}

#[derive(Clone, Debug)]
struct StaticAsset {
    /// Raw (identity) content.
    content: Bytes,
    /// Pre-compressed gzip variant, if available alongside the original file.
    content_gz: Option<Bytes>,
    /// Pre-compressed brotli variant, if available alongside the original file.
    content_br: Option<Bytes>,
    /// Pre-compressed zstd variant, if available alongside the original file.
    content_zst: Option<Bytes>,
    /// `ETag` value: hex-encoded content length plus a cheap rolling-hash fingerprint
    /// of the content's first 8 and last 4 bytes (see `make_etag`) — not a
    /// cryptographic or full-content hash, so it's sized for change-detection, not
    /// collision resistance.
    etag: String,
    /// Pre-validated `HeaderValue` form of `etag`, computed once at crawl time so the
    /// request path only ever needs a cheap `Bytes`-backed clone instead of re-parsing
    /// (and re-validating) `etag` on every cache hit via `HeaderValue::from_str`.
    etag_header: hyper::header::HeaderValue,
    headers: hyper::HeaderMap,
}

impl StaticAsset {
    /// The pre-compressed variant for `encoding`, or `None` when no sidecar of that coding
    /// was found next to the file at crawl time. `Identity` never has a sidecar — it *is*
    /// the file — so it returns `None` and callers fall back to `content`.
    const fn sidecar(&self, encoding: Encoding) -> Option<&Bytes> {
        match encoding {
            Encoding::Brotli => self.content_br.as_ref(),
            Encoding::Zstd => self.content_zst.as_ref(),
            Encoding::Gzip => self.content_gz.as_ref(),
            Encoding::Identity | Encoding::Deflate => None,
        }
    }
}

/// High-performance static file server.
///
/// ## Nginx-like usage
///
/// ```rust,no_run
/// use tachyon_web::{Router, ServeDir};
///
/// # async fn example() -> std::io::Result<()> {
/// // Simple: serve ./public/ at /, index.html as default
/// let router: Router = Router::new()
///     .serve_static("./public");
///
/// // Advanced: with preloading
/// let sd = ServeDir::new("./public")
///     .index("index.html")
///     .preload().await?;
/// let router: Router = Router::new().serve_dir("/", sd);
/// # let _ = router;
/// # Ok(())
/// # }
/// ```
///
/// ## Never point this at a directory that accepts user uploads
///
/// `ServeDir` serves whatever bytes are on disk with the MIME type derived
/// from the file extension — it has no way to know
/// whether a file's *content* actually matches that extension. In particular,
/// `.svg` is served as `image/svg+xml`, and SVG is allowed to contain
/// `<script>`: if the served directory (or any subdirectory reachable through
/// it) can ever contain a file an untrusted user chose the bytes of — an
/// avatar/logo upload folder mixed into `./public/`, for example — that user
/// can plant a self-executing script that runs in your origin the moment
/// anyone views the "image" directly or via `<img>`/`<object>`. Every response
/// from `ServeDir` sets `X-Content-Type-Options: nosniff`, which stops browsers
/// from *guessing* a more dangerous type than what's declared, but it does
/// **not** stop an SVG correctly served as `image/svg+xml` from running the
/// script embedded inside it — nosniff and inline-SVG script execution are
/// orthogonal protections.
///
/// If a served directory can ever contain user-supplied files:
/// - Serve that subtree from a **separate route/directory** with
///   `Content-Disposition: attachment` (forces download, never inline render),
///   or
/// - Sanitize/strip `<script>` (and other active content) from SVGs before
///   they land in the served directory.
#[derive(Clone, Debug)]
pub struct ServeDir {
    base_path: PathBuf,
    memory_cache: Option<Arc<HashMap<String, StaticAsset>>>,
    index_file: Option<String>,
    cache_config: CacheConfig,
}

impl ServeDir {
    /// Create a `ServeDir` that reads files from disk on every request.
    ///
    /// `path` is canonicalized once, here, so later traversal checks
    /// (`is_safe_path`) compare against a symlink-resolved base. If `path`
    /// doesn't exist yet at construction time, canonicalization is skipped and
    /// `base_path` falls back to an uncanonicalized (but absolute) path —
    /// [`preload`](Self::preload) retries canonicalization once the directory
    /// exists. If you construct a `ServeDir` for a directory that doesn't exist
    /// yet and never call `preload`, and any path component involved is later a
    /// symlink, traversal checks may spuriously reject legitimate requests;
    /// prefer creating the directory before calling `new`.
    pub fn new(path: impl AsRef<Path>) -> Self {
        let base = path.as_ref().to_path_buf();
        let base = std::fs::canonicalize(&base)
            .or_else(|_| std::env::current_dir().map(|cd| cd.join(&base)))
            .unwrap_or(base);
        Self {
            base_path: base,
            memory_cache: None,
            index_file: None,
            cache_config: CacheConfig::default(),
        }
    }

    /// Configure in-memory caching behaviour.
    ///
    /// Use this to disable caching entirely (e.g. for development) or to tune RAM limits.
    #[must_use]
    pub const fn cache(mut self, config: CacheConfig) -> Self {
        self.cache_config = config;
        self
    }

    /// Serve `index_file` (e.g. `"index.html"`) when a directory or root is requested.
    /// This is equivalent to Nginx's `index` directive.
    #[must_use]
    pub fn index(mut self, file: impl Into<String>) -> Self {
        self.index_file = Some(file.into());
        self
    }

    /// Preload the entire directory tree into memory.
    ///
    /// After this call, every request is served from `Arc<Bytes>` with **zero disk I/O**.
    /// Set `cache_config.enabled = false` to skip preloading and serve directly from disk.
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if reading files or directories from disk fails.
    pub async fn preload(mut self) -> std::io::Result<Self> {
        if !self.cache_config.enabled {
            return Ok(self);
        }
        // `base_path` may not have been canonicalized in `new()` if the directory
        // didn't exist yet at construction time — retry now that `preload` is
        // about to walk it (and thus requires it to exist), so subsequent
        // request-time traversal checks compare against a symlink-resolved base.
        if let Ok(canonical) = fs::canonicalize(&self.base_path).await {
            self.base_path = canonical;
        }
        let mut cache = HashMap::default();
        let mut current_total = 0usize;
        Self::crawl_dir(
            &self.base_path.clone(),
            &self.base_path.clone(),
            &mut cache,
            &mut current_total,
            self.cache_config.max_file_bytes,
            self.cache_config.max_total_bytes,
        )
        .await?;
        // Also store the index file under the empty string key for root lookups.
        // `StaticAsset::content`/`content_gz`/`content_br` are `Bytes`, so this clone
        // shares the same underlying buffer rather than duplicating it — the extra
        // `HashMap` entry (key, headers, etag) is real but negligible overhead, not
        // counted against `max_total_bytes` since it isn't proportional to file size.
        if let Some(ref idx) = self.index_file
            && let Some(asset) = cache.get(idx.as_str()).cloned()
        {
            let _ = cache.insert(String::new(), asset);
        }
        self.memory_cache = Some(Arc::new(cache));
        Ok(self)
    }

    #[allow(clippy::too_many_lines)]
    async fn crawl_dir(
        base: &Path,
        current: &Path,
        cache: &mut HashMap<String, StaticAsset>,
        current_total: &mut usize,
        max_file_bytes: usize,
        max_total_bytes: usize,
    ) -> std::io::Result<()> {
        if !current.exists() {
            return Ok(());
        }
        let mut entries = fs::read_dir(current).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Guard against symlinks planted under the served directory that point
            // outside `base` (e.g. `ln -s /etc app/static/etc`). Unlike the dynamic
            // disk-serving path, preloaded assets are served straight from the
            // in-memory cache with no per-request traversal check, so this has to be
            // enforced once, here, at crawl time — otherwise a symlink escape would
            // get cached under an innocuous-looking key and served on every request.
            match fs::canonicalize(&path).await {
                Ok(real) if real.starts_with(base) => {}
                _ => {
                    tracing::warn!(
                        path = %path.display(),
                        "Skipping cache entry that resolves outside the served directory"
                    );
                    continue;
                }
            }

            if path.is_dir() {
                Box::pin(Self::crawl_dir(
                    base,
                    &path,
                    cache,
                    current_total,
                    max_file_bytes,
                    max_total_bytes,
                ))
                .await?;
                continue;
            }

            let path_str = path.to_string_lossy();
            if let Some(base_str) = path_str
                .strip_suffix(".gz")
                .or_else(|| path_str.strip_suffix(".br"))
                .or_else(|| path_str.strip_suffix(".zst"))
                && fs::metadata(base_str).await.is_ok()
            {
                continue;
            }

            let meta = fs::metadata(&path).await?;
            if usize::try_from(meta.len()).unwrap_or(usize::MAX) > max_file_bytes {
                tracing::debug!(
                    "Skipping cache for large file: {} ({} bytes)",
                    path.display(),
                    meta.len()
                );
                continue;
            }

            if *current_total >= max_total_bytes {
                tracing::warn!("ram cache budget exhausted, remaining files served from disk");
                break;
            }

            let content = fs::read(&path).await?;
            let relative = match path.strip_prefix(base) {
                Ok(rel) => rel
                    .to_string_lossy()
                    .trim_start_matches('/')
                    .replace('\\', "/"),
                Err(_) => continue,
            };

            // Attempt to load pre-compressed sidecar files.
            let gz_path = PathBuf::from(format!("{}.gz", path.display()));
            let br_path = PathBuf::from(format!("{}.br", path.display()));
            let zst_path = PathBuf::from(format!("{}.zst", path.display()));
            let content_gz = fs::read(&gz_path).await.ok().map(Bytes::from);
            let content_br = fs::read(&br_path).await.ok().map(Bytes::from);
            let content_zst = fs::read(&zst_path).await.ok().map(Bytes::from);

            // Compute a fast ETag from content length + first 8 bytes.
            let etag = make_etag(&content);
            let etag_header = hyper::header::HeaderValue::from_str(&etag)
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("\"0\""));

            let mut headers = base_asset_headers(guess_mime_type(&path));
            // Vary: Accept-Encoding whenever we have compressed variants.
            if content_gz.is_some() || content_br.is_some() || content_zst.is_some() {
                let _ = headers.insert(
                    VARY,
                    hyper::header::HeaderValue::from_static("Accept-Encoding"),
                );
            }

            *current_total += content.len()
                + content_gz.as_ref().map_or(0, Bytes::len)
                + content_br.as_ref().map_or(0, Bytes::len)
                + content_zst.as_ref().map_or(0, Bytes::len);

            let _ = cache.insert(
                relative,
                StaticAsset {
                    content: Bytes::from(content),
                    content_gz,
                    content_br,
                    content_zst,
                    etag,
                    etag_header,
                    headers,
                },
            );
        }
        Ok(())
    }
}

/// A bodyless `304 Not Modified`, the answer to a conditional request whose `If-None-Match`
/// matched the asset's current `ETag`.
fn not_modified() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// `Cache-Control` for a given MIME type: HTML is the entry point clients must re-check often,
/// everything else is treated as a versioned, immutable asset.
fn cache_control_for(mime_type: &str) -> &'static str {
    if mime_type.starts_with("text/html") {
        "public, max-age=300"
    } else {
        "public, max-age=3600, immutable"
    }
}

/// Builds the response for a file read off disk, with the same `ETag`/`Cache-Control` treatment
/// the preloaded path applies, so cacheability doesn't depend on whether `preload()` was called.
fn disk_response(path: &Path, content: Vec<u8>, if_none_match: &str) -> Response<Body> {
    let etag = make_etag(&content);
    if if_none_match_matches(if_none_match, &etag) {
        return not_modified();
    }
    finish_disk_response(path, Body::full(Bytes::from(content)), &etag)
}

/// Applies the shared `Content-Type`/`nosniff`/`Cache-Control`/`ETag` headers to a disk-served
/// body, whether that body was buffered whole or is being streamed.
fn finish_disk_response(path: &Path, body: Body, etag: &str) -> Response<Body> {
    let mut resp = Response::new(body);
    *resp.headers_mut() = base_asset_headers(guess_mime_type(path));
    if let Ok(etag_value) = hyper::header::HeaderValue::from_str(etag) {
        let _ = resp.headers_mut().insert(ETAG, etag_value);
    }
    resp
}

/// The `Content-Type`/`nosniff`/`Cache-Control` trio every static asset carries, whether it
/// was preloaded into the RAM cache or read off disk — built in one place so the two paths
/// can't drift apart.
fn base_asset_headers(mime_type: &'static str) -> hyper::HeaderMap {
    let mut headers = hyper::HeaderMap::with_capacity(4);
    let _ = headers.insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(mime_type),
    );
    let _ = headers.insert(
        X_CONTENT_TYPE_OPTIONS,
        hyper::header::HeaderValue::from_static("nosniff"),
    );
    let _ = headers.insert(
        CACHE_CONTROL,
        hyper::header::HeaderValue::from_static(cache_control_for(mime_type)),
    );
    headers
}

/// A response body that reads a file off disk incrementally instead of buffering it whole.
///
/// `size_hint` stays exact (counting down `remaining`), so hyper still emits a real
/// `Content-Length` rather than falling back to chunked transfer encoding.
struct FileBody {
    file: tokio::fs::File,
    /// Reused read buffer — one allocation for the whole response, not one per frame.
    buf: Box<[u8]>,
    remaining: u64,
}

impl hyper::body::Body for FileBody {
    type Data = Bytes;
    type Error = crate::http::error::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        use tokio::io::AsyncRead;

        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let mut read_buf = tokio::io::ReadBuf::new(&mut this.buf);
        match std::pin::Pin::new(&mut this.file).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(crate::http::error::Error::Internal(
                e.to_string(),
            )))),
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    this.remaining = 0;
                    return Poll::Ready(None);
                }
                this.remaining = this
                    .remaining
                    .saturating_sub(u64::try_from(filled.len()).unwrap_or(u64::MAX));
                Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::copy_from_slice(
                    filled,
                )))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
}

/// An `ETag` for a file served without reading its contents, derived from the length and
/// modification time its metadata reports — the same change-detection strength as
/// [`make_etag`], which the streaming path can't use because it never holds the full body.
fn metadata_etag(meta: &std::fs::Metadata) -> String {
    let len = meta.len();
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    format!("\"{len:x}-{modified:x}\"")
}

/// Produce a lightweight `ETag` string from content: `"<len>-<first8hex>"`.
/// No crypto, no allocation-heavy hashing — pure arithmetic on existing bytes.
#[inline]
fn make_etag(content: &[u8]) -> String {
    let len = content.len();
    let mut sample: u64 = 0;
    for &b in content.iter().take(8) {
        sample = sample.wrapping_mul(31).wrapping_add(u64::from(b));
    }
    for &b in content.iter().rev().take(4) {
        sample = sample.wrapping_mul(37).wrapping_add(u64::from(b));
    }
    format!("\"{len:x}-{sample:x}\"")
}

impl ServeDir {
    /// Serve a request; convenience wrapper with no encoding negotiation or `ETag` checking.
    ///
    /// # Errors
    ///
    /// Returns a `StatusCode` (like `404 Not Found` or `403 Forbidden`) if serving fails.
    pub async fn handle_request(&self, req_path: &str) -> Result<Response<Body>, StatusCode> {
        self.handle_request_with_encoding(req_path, "", "").await
    }

    /// Full request handler with content-encoding negotiation and `ETag` 304 support.
    ///
    /// `accept_encoding` — value of the request's `Accept-Encoding` header (empty if absent).
    /// `if_none_match` — value of `If-None-Match` for `ETag` 304 short-circuit.
    ///
    /// # Errors
    ///
    /// Returns a `StatusCode` if percent decoding fails, traversal is detected, or the file cannot be served.
    pub async fn handle_request_with_encoding(
        &self,
        req_path: &str,
        accept_encoding: &str,
        if_none_match: &str,
    ) -> Result<Response<Body>, StatusCode> {
        let Some(decoded) = crate::routing::percent_decode(req_path) else {
            return Err(StatusCode::BAD_REQUEST);
        };
        self.serve_decoded(&decoded, accept_encoding, if_none_match)
            .await
    }

    /// The body of [`handle_request_with_encoding`](Self::handle_request_with_encoding), minus
    /// the percent-decoding step, for callers whose path has already been decoded.
    ///
    /// Split out because [`into_method_router`](Self::into_method_router) reads the path from
    /// the `{*path}` capture, which the router has already percent-decoded. Decoding twice
    /// resolves the wrong file for names containing a percent sequence (`%2541` → `%41` → `A`)
    /// and, worse, reintroduces a path separator (`%252f` → `%2f` → `/`) after the router has
    /// finished segmenting the path.
    async fn serve_decoded(
        &self,
        decoded: &str,
        accept_encoding: &str,
        if_none_match: &str,
    ) -> Result<Response<Body>, StatusCode> {
        let req_clean = decoded.trim_start_matches('/');

        if req_clean.contains("..") || req_clean.contains('\0') {
            return Err(StatusCode::FORBIDDEN);
        }

        let resolved = self.resolve_index(req_clean)?;
        let resolved = resolved.as_ref();
        if resolved.is_empty() {
            return Err(StatusCode::NOT_FOUND);
        }

        if let Some(resp) = self.serve_from_cache(resolved, accept_encoding, if_none_match) {
            return Ok(resp);
        }

        self.serve_from_disk(resolved, if_none_match).await
    }

    /// Appends the configured index file to a request naming a directory rather than a file:
    /// the root (`""`) and any path with a trailing slash (`docs/` → `docs/index.html`),
    /// matching `tower_http`'s `ServeDir`.
    fn resolve_index<'a>(&'a self, req_clean: &'a str) -> Result<Cow<'a, str>, StatusCode> {
        if req_clean.is_empty() {
            self.index_file
                .as_deref()
                .map(Cow::Borrowed)
                .ok_or(StatusCode::NOT_FOUND)
        } else if req_clean.ends_with('/') {
            self.index_file
                .as_deref()
                .map(|idx| Cow::Owned(format!("{req_clean}{idx}")))
                .ok_or(StatusCode::NOT_FOUND)
        } else {
            Ok(Cow::Borrowed(req_clean))
        }
    }

    /// Serves `resolved` out of the preloaded RAM cache, or `None` if this `ServeDir` wasn't
    /// preloaded or the asset isn't in the cache (e.g. it exceeded `max_file_bytes`), in which
    /// case the caller falls through to the disk path.
    fn serve_from_cache(
        &self,
        resolved: &str,
        accept_encoding: &str,
        if_none_match: &str,
    ) -> Option<Response<Body>> {
        let asset = self.memory_cache.as_ref()?.get(resolved)?;

        if if_none_match_matches(if_none_match, &asset.etag) {
            return Some(not_modified());
        }

        // Only offer codings this asset actually has a sidecar for, so negotiation can't
        // settle on one that would then fall back to identity and lose to a coding the
        // client ranked lower but which was available.
        let mut available: smallvec::SmallVec<[Encoding; 3]> = smallvec::SmallVec::new();
        for encoding in SIDECAR_PREFERENCE {
            if asset.sidecar(encoding).is_some() {
                available.push(encoding);
            }
        }
        let encoding = negotiate(accept_encoding, &available);
        let body_bytes = asset
            .sidecar(encoding)
            .cloned()
            .unwrap_or_else(|| asset.content.clone());

        let mut resp = Response::new(Body::full(body_bytes));
        *resp.headers_mut() = asset.headers.clone();
        let _ = resp.headers_mut().insert(ETAG, asset.etag_header.clone());
        if encoding != Encoding::Identity {
            let _ = resp
                .headers_mut()
                .insert(CONTENT_ENCODING, encoding.header_value());
        }
        Some(resp)
    }

    /// Reads `resolved` from disk, after confirming it really lives under `base_path`.
    async fn serve_from_disk(
        &self,
        resolved: &str,
        if_none_match: &str,
    ) -> Result<Response<Body>, StatusCode> {
        let candidate = self.base_path.join(resolved);
        let Ok(canonical) = fs::canonicalize(&candidate).await else {
            return Err(StatusCode::NOT_FOUND);
        };

        if !is_safe_path(&self.base_path, &canonical) {
            tracing::warn!(
                path = %canonical.display(),
                base = %self.base_path.display(),
                "Rejected path traversal attempt"
            );
            return Err(StatusCode::FORBIDDEN);
        }

        let (canonical, meta) = self.resolve_disk_target(canonical).await?;

        if meta.len() > STREAM_THRESHOLD {
            return Self::stream_from_disk(&canonical, &meta, if_none_match).await;
        }

        match fs::read(&canonical).await {
            Ok(content) => Ok(disk_response(&canonical, content, if_none_match)),
            Err(e) => {
                tracing::error!(path = %canonical.display(), error = %e, "failed to read static file");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    /// Serves a file as a [`FileBody`] stream, using a metadata-derived `ETag` since the content
    /// is never held in full.
    async fn stream_from_disk(
        canonical: &Path,
        meta: &std::fs::Metadata,
        if_none_match: &str,
    ) -> Result<Response<Body>, StatusCode> {
        let etag = metadata_etag(meta);
        if if_none_match_matches(if_none_match, &etag) {
            return Ok(not_modified());
        }
        let file = fs::File::open(canonical).await.map_err(|e| {
            tracing::error!(path = %canonical.display(), error = %e, "failed to open static file");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let body = Body::stream(FileBody {
            file,
            buf: vec![0u8; STREAM_CHUNK].into_boxed_slice(),
            remaining: meta.len(),
        });
        Ok(finish_disk_response(canonical, body, &etag))
    }

    /// Narrows a canonicalized path to the regular file to actually read: a directory reached
    /// *without* a trailing slash (`/docs`, not `/docs/`) never had an index appended by
    /// [`resolve_index`](Self::resolve_index), so it's resolved here rather than 404ing on a
    /// directory that does have one. Anything that is neither a file nor an indexed directory
    /// (a socket, a fifo) is a 404.
    async fn resolve_disk_target(
        &self,
        canonical: PathBuf,
    ) -> Result<(PathBuf, std::fs::Metadata), StatusCode> {
        let Ok(meta) = fs::metadata(&canonical).await else {
            return Err(StatusCode::NOT_FOUND);
        };
        if meta.is_file() {
            return Ok((canonical, meta));
        }
        if !meta.is_dir() {
            return Err(StatusCode::NOT_FOUND);
        }
        let idx = self.index_file.as_deref().ok_or(StatusCode::NOT_FOUND)?;
        let with_index = canonical.join(idx);
        match fs::metadata(&with_index).await {
            Ok(idx_meta) if idx_meta.is_file() => Ok((with_index, idx_meta)),
            _ => Err(StatusCode::NOT_FOUND),
        }
    }

    /// Build a `MethodRouter` from this `ServeDir`.
    ///
    /// The path to serve is taken from the `{path}` or `{*path}` matchit capture.
    /// This is used internally by `Router::serve_static` — you rarely need this directly.
    #[must_use]
    pub fn into_method_router<S>(self) -> crate::routing::MethodRouter<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        self.into_method_router_at("")
    }

    /// [`into_method_router`](Self::into_method_router) for a `ServeDir` mounted under
    /// `mount_prefix` (`""` at the root).
    ///
    /// Only the capture-less routes need this: they fall back to the request `Uri`, which
    /// still carries the mount point, and `GET /assets` must resolve the index rather than a
    /// file named `assets`.
    pub(crate) fn into_method_router_at<S>(
        self,
        mount_prefix: &str,
    ) -> crate::routing::MethodRouter<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let self_arc = std::sync::Arc::new(self);
        let mount_prefix: Arc<str> = Arc::from(mount_prefix);
        crate::routing::get(move |req: hyper::Request<Bytes>| {
            let this = self_arc.clone();
            let mount_prefix = mount_prefix.clone();

            async move {
                let path_ext = req
                    .extensions()
                    .get::<crate::routing::extract::PathParams>();

                let captured = path_ext.and_then(|p| {
                    p.0.iter()
                        .find(|(k, _)| k.as_ref() == "path" || k.as_ref() == "*path")
                        .map(|(_, v)| v.as_str())
                });

                let accept_enc = req
                    .headers()
                    .get(hyper::header::ACCEPT_ENCODING)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let if_none_match = req
                    .headers()
                    .get(IF_NONE_MATCH)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                let result = if let Some(path) = captured {
                    this.serve_decoded(path, accept_enc, if_none_match).await
                } else {
                    let uri_path = req.uri().path();
                    let relative = uri_path
                        .strip_prefix(mount_prefix.as_ref())
                        .unwrap_or(uri_path);
                    this.handle_request_with_encoding(relative, accept_enc, if_none_match)
                        .await
                };
                match result {
                    Ok(resp) => resp,
                    Err(status) => status.into_response(),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::fs;

    fn make_temp_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("index.html"),
            b"<html><script>var x=1;</script></html>",
        )
        .unwrap();
        fs::write(dir.path().join("style.css"), b"body{}").unwrap();
        fs::write(dir.path().join("app.js"), b"console.log(1)").unwrap();
        dir
    }

    #[tokio::test]
    async fn test_serve_existing_file() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path()).preload().await.unwrap();
        let resp = sd.handle_request("style.css").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(ct.contains("text/css"), "ct: {ct}");
    }

    #[tokio::test]
    async fn test_nosniff_header_preloaded() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path()).preload().await.unwrap();
        let resp = sd.handle_request("style.css").await.unwrap();
        assert_eq!(
            resp.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
    }

    #[tokio::test]
    async fn test_nosniff_header_dynamic() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path());
        let resp = sd.handle_request("style.css").await.unwrap();
        assert_eq!(
            resp.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn test_svg_mime_type() {
        // Documented, deliberate behavior: `.svg` is reported by extension only,
        // never by content — see the `ServeDir` docs' upload-safety warning.
        assert_eq!(guess_mime_type(Path::new("logo.svg")), "image/svg+xml");
    }

    #[tokio::test]
    async fn test_not_found() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path()).preload().await.unwrap();
        assert_eq!(
            sd.handle_request("missing.txt").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_index_file_on_root_request() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path())
            .index("index.html")
            .preload()
            .await
            .unwrap();
        let resp = sd.handle_request("").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(ct.contains("text/html"), "ct: {ct}");
    }

    /// A subdirectory request must resolve to that directory's index file, with and without a
    /// trailing slash, in both preloaded and disk modes.
    #[tokio::test]
    async fn test_index_file_on_subdirectory_request() {
        let dir = make_temp_dir();
        fs::create_dir(dir.path().join("docs")).unwrap();
        fs::write(dir.path().join("docs/index.html"), b"<html>docs</html>").unwrap();

        for sd in [
            ServeDir::new(dir.path()).index("index.html"),
            ServeDir::new(dir.path())
                .index("index.html")
                .preload()
                .await
                .unwrap(),
        ] {
            for req in ["docs/", "docs"] {
                let resp = sd.handle_request(req).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK, "req: {req}");
                let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
                assert!(ct.contains("text/html"), "req: {req}, ct: {ct}");
            }
        }
    }

    /// A directory request with no configured index must still 404 rather than serving
    /// something, or erroring, on the directory itself.
    #[tokio::test]
    async fn test_directory_request_without_index_is_not_found() {
        let dir = make_temp_dir();
        fs::create_dir(dir.path().join("docs")).unwrap();
        let sd = ServeDir::new(dir.path());
        for req in ["docs/", "docs"] {
            assert_eq!(
                sd.handle_request(req).await.unwrap_err(),
                StatusCode::NOT_FOUND,
                "req: {req}"
            );
        }
    }

    /// The disk path must set the same `ETag`/`Cache-Control` the preloaded path does, and
    /// honor a matching `If-None-Match` with a `304`.
    #[tokio::test]
    async fn test_dynamic_mode_sets_etag_and_revalidates() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path());
        let resp = sd
            .handle_request_with_encoding("style.css", "", "")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(CACHE_CONTROL).is_some());
        let etag = resp
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp = sd
            .handle_request_with_encoding("style.css", "", &etag)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    /// The `{*path}` capture is already percent-decoded by the router, so the `ServeDir`
    /// handler must not decode it a second time — `file%2541.txt` on the wire names a file
    /// literally called `file%41.txt`, not `fileA.txt`.
    #[tokio::test]
    async fn test_captured_path_is_not_double_decoded() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file%41.txt"), b"percent").unwrap();
        fs::write(dir.path().join("fileA.txt"), b"letter").unwrap();
        let sd = ServeDir::new(dir.path());

        // What the router hands the handler after decoding `file%2541.txt` once.
        let resp = sd.serve_decoded("file%41.txt", "", "").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_path_traversal_dotdot() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path()).preload().await.unwrap();
        let err = sd.handle_request("../../etc/passwd").await.unwrap_err();
        assert_eq!(err, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_path_traversal_dynamic_mode() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path());
        let err = sd.handle_request("../../../etc/passwd").await.unwrap_err();
        assert!(err == StatusCode::FORBIDDEN || err == StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_null_byte_rejected() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path()).preload().await.unwrap();
        assert_eq!(
            sd.handle_request("style\x00.css").await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_guess_mime_types() {
        let cases = [
            ("index.html", "text/html; charset=utf-8"),
            ("style.css", "text/css; charset=utf-8"),
            ("app.js", "application/javascript; charset=utf-8"),
            ("data.json", "application/json"),
            ("file.wasm", "application/wasm"),
            ("manifest.webmanifest", "application/manifest+json"),
            ("feed.xml", "text/xml; charset=utf-8"),
            ("doc.txt", "text/plain; charset=utf-8"),
            ("sheet.csv", "text/csv; charset=utf-8"),
            ("img.png", "image/png"),
            ("pic.jpg", "image/jpeg"),
            ("anim.gif", "image/gif"),
            ("vector.svg", "image/svg+xml"),
            ("fav.ico", "image/x-icon"),
            ("pic.webp", "image/webp"),
            ("pic.avif", "image/avif"),
            ("pic.bmp", "image/bmp"),
            ("font.woff", "font/woff"),
            ("font.woff2", "font/woff2"),
            ("font.ttf", "font/ttf"),
            ("font.otf", "font/otf"),
            ("audio.mp3", "audio/mpeg"),
            ("video.mp4", "video/mp4"),
            ("video.webm", "video/webm"),
            ("doc.pdf", "application/pdf"),
            ("archive.zip", "application/zip"),
            ("archive.gz", "application/gzip"),
            ("no_ext", "application/octet-stream"),
            ("file.unknown", "application/octet-stream"),
        ];

        for (filename, expected) in cases {
            let path = Path::new(filename);
            assert_eq!(guess_mime_type(path), expected, "failed on {filename}");
        }
    }

    /// Sidecar selection runs through the shared RFC 9110 negotiator, so `Accept-Encoding`
    /// is matched as a list of tokens with `q` values rather than as a substring, and
    /// `q=0` is an explicit refusal — answering it with that coding would hand the client a
    /// body it just said it cannot decode.
    #[test]
    fn sidecar_negotiation_honors_tokens_and_q_values() {
        assert_eq!(negotiate("gzip, br", &SIDECAR_PREFERENCE), Encoding::Brotli);
        assert_eq!(
            negotiate("br;q=0.5, gzip;q=1.0", &SIDECAR_PREFERENCE),
            Encoding::Gzip,
        );
        assert_eq!(negotiate("BR", &SIDECAR_PREFERENCE), Encoding::Brotli);
        assert_eq!(negotiate("zstd", &SIDECAR_PREFERENCE), Encoding::Zstd);
        // Explicit refusals.
        assert_eq!(
            negotiate("br;q=0, gzip;q=0.000, zstd", &SIDECAR_PREFERENCE),
            Encoding::Zstd,
        );
        // Not a token match, only a substring one.
        assert_eq!(negotiate("brotli", &SIDECAR_PREFERENCE), Encoding::Identity);
        assert_eq!(negotiate("x-gzip", &SIDECAR_PREFERENCE), Encoding::Identity);
        assert_eq!(negotiate("", &SIDECAR_PREFERENCE), Encoding::Identity);
    }

    /// Negotiation is offered only the codings this asset actually has a sidecar for: a
    /// client that prefers Brotli but whose asset only has a gzip sidecar must get gzip,
    /// not identity.
    #[test]
    fn negotiation_is_limited_to_the_sidecars_that_exist() {
        let asset = StaticAsset {
            content: Bytes::from_static(b"original"),
            content_gz: Some(Bytes::from_static(b"gzipped")),
            content_br: None,
            content_zst: None,
            etag: "\"e\"".to_string(),
            etag_header: hyper::header::HeaderValue::from_static("\"e\""),
            headers: hyper::HeaderMap::new(),
        };

        let available: Vec<Encoding> = SIDECAR_PREFERENCE
            .into_iter()
            .filter(|&e| asset.sidecar(e).is_some())
            .collect();
        assert_eq!(negotiate("br, gzip, zstd", &available), Encoding::Gzip);
        assert_eq!(negotiate("br, zstd", &available), Encoding::Identity);
    }

    /// A large file must be served without ever holding its full contents in memory, and must
    /// still carry an exact `Content-Length` (from the streaming body's `size_hint`) rather
    /// than silently degrading to chunked encoding.
    #[tokio::test]
    async fn test_large_file_is_streamed_with_exact_length() {
        let dir = tempfile::tempdir().unwrap();
        let size = usize::try_from(STREAM_THRESHOLD).unwrap() + 4096;
        fs::write(dir.path().join("big.bin"), vec![7u8; size]).unwrap();
        let sd = ServeDir::new(dir.path());

        let resp = sd.handle_request("big.bin").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(matches!(resp.body(), Body::Stream(_)), "should stream");
        assert_eq!(
            hyper::body::Body::size_hint(resp.body()).exact(),
            Some(u64::try_from(size).unwrap())
        );

        // The streamed bytes must still be the whole, correct file.
        let collected = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(collected.len(), size);
        assert!(collected.iter().all(|&b| b == 7));
    }

    /// The streaming path derives its `ETag` from metadata rather than content, but must still
    /// revalidate — a `304` on a matching `If-None-Match` is the entire point of sending one.
    #[tokio::test]
    async fn test_large_file_revalidates() {
        let dir = tempfile::tempdir().unwrap();
        let size = usize::try_from(STREAM_THRESHOLD).unwrap() + 1;
        fs::write(dir.path().join("big.bin"), vec![0u8; size]).unwrap();
        let sd = ServeDir::new(dir.path());

        let resp = sd
            .handle_request_with_encoding("big.bin", "", "")
            .await
            .unwrap();
        let etag = resp
            .headers()
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp = sd
            .handle_request_with_encoding("big.bin", "", &etag)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    /// `If-None-Match` is a *list*, may be `*`, and compares weakly (RFC 9110 §13.1.2).
    /// Treating it as one opaque string re-sent the whole body to any client doing any of
    /// those three perfectly legal things.
    #[tokio::test]
    async fn test_if_none_match_list_wildcard_and_weak_tags() {
        let dir = make_temp_dir();
        for sd in [
            ServeDir::new(dir.path()),
            ServeDir::new(dir.path()).preload().await.unwrap(),
        ] {
            let resp = sd
                .handle_request_with_encoding("style.css", "", "")
                .await
                .unwrap();
            let etag = resp
                .headers()
                .get(ETAG)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            for header in [
                etag.clone(),
                format!("\"other\", {etag}"),
                format!("W/{etag}"),
                "*".to_string(),
            ] {
                let resp = sd
                    .handle_request_with_encoding("style.css", "", &header)
                    .await
                    .unwrap();
                assert_eq!(
                    resp.status(),
                    StatusCode::NOT_MODIFIED,
                    "If-None-Match: {header}"
                );
            }

            // A non-matching tag must still get the full body.
            let resp = sd
                .handle_request_with_encoding("style.css", "", "\"nope\"")
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[test]
    fn test_is_safe_path() {
        let base = Path::new("/var/www");
        let safe = Path::new("/var/www/index.html");
        let unsafe_path = Path::new("/var/etc/passwd");
        assert!(is_safe_path(base, safe));
        assert!(!is_safe_path(base, unsafe_path));
    }

    #[tokio::test]
    async fn test_crawl_dir_edge_cases() {
        let dir = tempfile::tempdir().unwrap();
        // Crawl non-existent path
        let mut cache = HashMap::default();
        let mut current_total = 0usize;
        let res = ServeDir::crawl_dir(
            dir.path(),
            &dir.path().join("missing"),
            &mut cache,
            &mut current_total,
            2 * 1024 * 1024,
            64 * 1024 * 1024,
        )
        .await;
        assert!(res.is_ok());

        // Crawl large file (> 5MB)
        let large_path = dir.path().join("large.txt");
        let large_content = vec![0u8; 6 * 1024 * 1024]; // 6MB
        fs::write(&large_path, large_content).unwrap();
        let sd = ServeDir::new(dir.path()).preload().await.unwrap();
        // Large file should not be preloaded in cache
        assert!(sd.memory_cache.as_ref().unwrap().get("large.txt").is_none());

        // Dynamic serving of large file should succeed
        let resp = sd.handle_request("large.txt").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handle_request_edge_cases() {
        let dir = make_temp_dir();
        // Dynamic mode
        let sd_dyn = ServeDir::new(dir.path());
        let resp = sd_dyn.handle_request("style.css").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Invalid percent encoding
        assert_eq!(
            sd_dyn.handle_request("style%x.css").await.unwrap_err(),
            StatusCode::BAD_REQUEST
        );

        // Empty path and empty index
        let sd_no_index = ServeDir::new(dir.path());
        assert_eq!(
            sd_no_index.handle_request("").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );

        // Canonicalization failure
        assert_eq!(
            sd_dyn.handle_request("nonexistent.txt").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );

        // Path traversal targeting a file that actually exists on disk (so
        // canonicalization succeeds) must still be rejected.
        let sd_traversal = ServeDir::new(dir.path());
        let res = sd_traversal
            .handle_request("../../../../../../../../../etc/passwd")
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_into_method_router_fallback() {
        let dir = make_temp_dir();
        let sd = ServeDir::new(dir.path()).preload().await.unwrap();
        let router = sd.into_method_router::<()>();
        // 1. Without extension, fallback to URI path
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/style.css")
            .body(Body::empty())
            .unwrap();
        let h = router.handlers[super::super::IDX_GET].as_ref().unwrap();
        let resp = h.call(req, Arc::new(())).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
