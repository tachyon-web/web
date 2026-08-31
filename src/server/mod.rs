//! The [`Server`] engine: wraps a [`CompiledRouter`] and dispatches incoming streams for
//! every supported transport.
//!
//! # Protocol support
//!
//! | Method | Protocol | Feature flag |
//! |---|---|---|
//! | [`serve_http`] | HTTP/1.1 plain TCP (+ HTTP/2 cleartext "h2c" with `http2`) | *(always)* |
//! | [`serve_https`] | HTTP/1.1 + HTTP/2 over TLS | `tls` |
//! | [`serve_https_config`] | Same but with custom `ServerConfig` | `tls` |
//! | [`serve_h3`] | HTTP/3 over QUIC | `http3` |
//! | [`start_all`] | All of the above via PEM cert/key strings | `cert-gen` |
//! | [`serve_all_acme`] | All of the above, certs managed by Let's Encrypt | `lets-encrypt` |
//! | [`serve_tor`] | HTTP/1.1 (+ h2c) over a native Tor `.onion` hidden service | `tor` |
//! | [`serve_i2p`] | HTTP/1.1 (+ h2c) over a native I2P `.b32.i2p` eepsite ([breaks `forbid(unsafe_code)`](i2p)) | `i2p` |
//!
//! [`serve_http`]: Server::serve_http
//! [`serve_https`]: Server::serve_https
//! [`serve_https_config`]: Server::serve_https_config
//! [`serve_h3`]: Server::serve_h3
//! [`start_all`]: Server::start_all
//! [`serve_all_acme`]: Server::serve_all_acme
//! [`serve_tor`]: Server::serve_tor
//! [`serve_i2p`]: Server::serve_i2p
//! [`CompiledRouter`]: crate::routing::CompiledRouter
//!
//! # Publishing over more than one transport at once
//!
//! Each `serve_*` method above consumes its `Server` and blocks for that one transport's
//! lifetime — the right building block for a single-transport deployment. To publish the same
//! app over several transports at once (e.g. clearnet HTTPS *and* a `.onion` mirror *and*
//! a `.i2p` mirror, all from one process), prefer [`MultiServer`] over hand-rolling
//! `tokio::spawn` + `tokio::select!` around the individual `serve_*` calls yourself — it owns
//! exactly that boilerplate:
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use tachyon_web::{Router, Server, get};
//!
//! let app: Router = Router::new().route("/", get(|| async { "hi" }));
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//!
//! Server::new(app)
//!     .with_http(listener)
//!     // .with_onion(onion_config)   // requires the `tor` feature
//!     // .with_i2p(i2p_config)       // requires the `i2p` feature
//!     .serve()
//!     .await?;
//! # Ok(())
//! # }
//! ```

#[cfg(any(feature = "tor", feature = "i2p"))]
mod anon_tls;
pub(crate) mod conn;
#[cfg(feature = "early-hints")]
mod h2;
#[cfg(feature = "http3")]
mod h3;
mod http;
#[cfg(feature = "i2p")]
pub mod i2p;
mod listener;
mod multi;
mod redirect;
pub mod serve;
#[cfg(feature = "tls")]
mod tls_config;
#[cfg(feature = "tor")]
pub mod tor;
mod worker_pool;

pub use listener::{Listener, ListenerExt, TapIo};
pub use multi::MultiServer;
pub use serve::{Serve, WithGracefulShutdown, serve};
#[cfg(feature = "tls")]
pub use tls_config::{HttpsServer, RustlsConfig, bind_rustls};

use crate::routing::CompiledRouter;
#[cfg(any(feature = "ws", feature = "tls"))]
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use crate::http::response::Body;
use hyper::{Request, Response};
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt", feature = "http3"))]
use tokio_rustls::TlsAcceptor;

use redirect::parse_addr;
#[cfg(feature = "tls")]
pub use redirect::{REDIRECT_MAX_CONNECTIONS, serve_http_redirect_and_challenges};
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
use redirect::{RedirectInfo, parse_port};
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt", feature = "http3"))]
pub(crate) use tls_config::alpn_protocols;
#[cfg(feature = "fips")]
use tls_config::assert_fips_server_config;
#[cfg(any(feature = "lets-encrypt", feature = "cert-gen"))]
use tls_config::tls_config_builder;
use worker_pool::IS_LOCAL_WORKER;
use worker_pool::run_worker_pool;

/// Default read timeout for both plaintext and TLS connections.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default handshake timeout for TLS connections.
#[cfg(feature = "tls")]
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// Default for [`Server::max_websocket_connections`] — see that field for how to size it.
///
/// *Tachyon extension: no `axum` equivalent.*
pub const DEFAULT_MAX_WEBSOCKET_CONNECTIONS: usize = 25_600;
/// Default for [`Server::max_h3_concurrent_streams`] — see that field for how to size it.
///
/// *Tachyon extension: no `axum` equivalent.*
#[cfg(feature = "http3")]
pub const DEFAULT_MAX_H3_CONCURRENT_STREAMS: usize = 256;
/// How long [`Server::serve_all_acme`] waits for the first certificate to be
/// cached or provisioned before starting the TLS listener regardless.
#[cfg(feature = "lets-encrypt")]
const FIRST_CERT_TIMEOUT: Duration = Duration::from_mins(1);

/// Main server configuration and runner.
///
/// Wraps a [`CompiledRouter`] and provides multiple `serve_*` methods for different
/// transport protocols. The server is cheaply cloneable via `Arc` internally.
///
/// # Example
///
/// ```rust,no_run
/// use tachyon_web::{Router, Server, get};
/// use tokio::net::TcpListener;
///
/// async fn hello() -> &'static str { "hello" }
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///     let app = Router::new().route("/", get(hello));
///     let listener = TcpListener::bind("0.0.0.0:8080").await?;
///     Server::new(app).serve_http(listener).await?;
///     Ok(())
/// }
/// ```
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Debug)]
pub struct Server<S> {
    pub(crate) router: CompiledRouter<S>,
    /// Maximum permitted request body size in bytes (default: 2 MiB, matching
    /// Axum's `DefaultBodyLimit` default).
    pub max_body_size: usize,
    /// Maximum number of concurrent active TCP connections **per worker thread**.
    ///
    /// Tachyon runs one worker (with its own `SO_REUSEPORT` listener and connection
    /// semaphore) per CPU core, so the effective process-wide ceiling is
    /// `max_connections × number of cores`, not a single global cap. Size this
    /// accordingly if you're relying on it for downstream resource planning (e.g.
    /// a connection-pooled database sized to the server's max concurrency).
    ///
    /// This per-core sharding applies to [`serve_http`] and [`serve_https`]
    /// (and anything built on them, like [`serve_all_acme`]). HTTP/3
    /// ([`serve_h3`]) runs a single QUIC endpoint with its own connection
    /// semaphore, not sharded across the worker pool — for H3 traffic the
    /// effective ceiling is `max_connections` alone. The same is true of the
    /// anonymity transports (`serve_tor`/`serve_onion`/`serve_i2p` and their
    /// `_with_client`/`_with_router` variants, behind the `tor`/`i2p`
    /// features): each runs one accept loop with its own semaphore, so
    /// `max_connections` is the whole ceiling for that transport rather than a
    /// per-core share.
    ///
    /// [`serve_http`]: Server::serve_http
    /// [`serve_https`]: Server::serve_https
    /// [`serve_all_acme`]: Server::serve_all_acme
    /// [`serve_h3`]: Server::serve_h3
    ///
    /// Default: 25,600 — matching `actix-server`'s own per-worker
    /// `max_concurrent_connections`.
    pub max_connections: usize,
    /// Maximum number of concurrent established WebSocket connections, process-wide.
    ///
    /// Upgraded connections escape [`max_connections`](Self::max_connections): hyper's
    /// connection future completes as soon as it hands the socket to the upgrade, releasing
    /// that permit while the WebSocket lives on in its own task. Without this ceiling a peer
    /// can hold open an unbounded number of them.
    ///
    /// Process-wide rather than per-worker — one semaphore shared by every worker clone and
    /// every transport.
    ///
    /// Size it by memory, not connection count: tungstenite defaults to a 128 KiB read plus
    /// 128 KiB write buffer per socket, so the default is worth several GiB at saturation.
    /// Lower it, or the buffers via
    /// [`WebSocketUpgrade::read_buffer_size`](crate::ws::WebSocketUpgrade::read_buffer_size)
    /// and [`write_buffer_size`](crate::ws::WebSocketUpgrade::write_buffer_size).
    ///
    /// Default: 25,600.
    pub max_websocket_connections: usize,
    /// Backs [`max_websocket_connections`](Self::max_websocket_connections). Shared by clone,
    /// not rebuilt per worker — that's what makes the limit process-wide.
    #[cfg(feature = "ws")]
    pub(crate) websocket_permits: Arc<tokio::sync::Semaphore>,
    /// Maximum number of HTTP/3 streams handled concurrently **per QUIC connection** — see
    /// [`serve_h3`](Server::serve_h3). Distinct from [`max_connections`](Self::max_connections),
    /// which caps whole connections, not streams within one: a single peer can open many
    /// streams on one connection, so this is what actually bounds the handler tasks (and
    /// request-body buffers) one connection can have in flight at once.
    ///
    /// Unlike the HTTP/1.1/HTTP/2 body path (which streams lazily into the handler), H3
    /// request bodies are read to completion — up to [`max_body_size`](Self::max_body_size) —
    /// *before* the handler runs (see `read_h3_body` in `server/h3.rs`). That makes this the
    /// dominant term in one QUIC connection's worst-case memory: roughly
    /// `max_h3_concurrent_streams × max_body_size`, e.g. 256 × 2 MiB = 512 MiB at the
    /// defaults, before `max_connections` multiplies it across connections. Size this and
    /// `max_body_size` together if H3 traffic is expected.
    ///
    /// Default: 256.
    #[cfg(feature = "http3")]
    pub max_h3_concurrent_streams: usize,
    /// Crypto/TLS policy shared across every listener this `Server` runs — see
    /// [`Server::tls_policy`]. `None` means each listener falls back to
    /// [`TlsPolicy::new`](crate::tls::TlsPolicy::new).
    #[cfg(feature = "tls")]
    pub(crate) tls_policy: Option<crate::tls::TlsPolicy>,
    /// Response compression, applied to every transport — see [`Server::compression`].
    /// `None` (the default) sends every response uncoded.
    pub(crate) compression: Option<crate::http::compression::Compression>,
    /// `103 Early Hints` policy — see [`Server::early_hints`]. `None` (the default) leaves
    /// HTTPS connections on `hyper`'s HTTP/2 server and hands handlers a no-op
    /// [`EarlyHints`](crate::http::early_hints::EarlyHints) handle.
    #[cfg(feature = "early-hints")]
    pub(crate) early_hints: Option<crate::http::early_hints::EarlyHintsConfig>,
}

impl<S> Clone for Server<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            router: self.router.clone(),
            max_body_size: self.max_body_size,
            max_connections: self.max_connections,
            max_websocket_connections: self.max_websocket_connections,
            #[cfg(feature = "ws")]
            websocket_permits: self.websocket_permits.clone(),
            #[cfg(feature = "http3")]
            max_h3_concurrent_streams: self.max_h3_concurrent_streams,
            #[cfg(feature = "tls")]
            tls_policy: self.tls_policy.clone(),
            compression: self.compression.clone(),
            #[cfg(feature = "early-hints")]
            early_hints: self.early_hints.clone(),
        }
    }
}

impl Server<()> {
    /// Creates a new `Server` with default settings and the given router.
    ///
    /// # Panics
    /// Panics if router compilation fails (e.g. a duplicate route was registered).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(router: crate::routing::Router<()>) -> Self {
        let compiled = router.compile().expect("Router compilation failed");
        Self {
            router: compiled,
            max_body_size: 2 * 1024 * 1024, // 2 MiB (matches Axum's `DefaultBodyLimit` default)
            max_connections: 25_600,
            max_websocket_connections: DEFAULT_MAX_WEBSOCKET_CONNECTIONS,
            #[cfg(feature = "ws")]
            websocket_permits: Arc::new(tokio::sync::Semaphore::new(
                DEFAULT_MAX_WEBSOCKET_CONNECTIONS,
            )),
            #[cfg(feature = "http3")]
            max_h3_concurrent_streams: DEFAULT_MAX_H3_CONCURRENT_STREAMS,
            #[cfg(feature = "tls")]
            tls_policy: None,
            compression: None,
            #[cfg(feature = "early-hints")]
            early_hints: None,
        }
    }
}

impl<S> Server<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Attaches the per-request extensions and routes the request.
    ///
    /// Every transport funnels through here — HTTP/1.1, HTTP/2, `.onion` and `.i2p` via
    /// `hyper_handler`, HTTP/3 directly — so they can't disagree about which extensions a
    /// handler sees.
    pub(crate) async fn dispatch(
        &self,
        mut req: Request<Body>,
        peer: std::net::SocketAddr,
    ) -> Response<Body> {
        #[cfg(feature = "original-uri")]
        {
            let original_uri = crate::routing::extract::OriginalUri(req.uri().clone());
            let _ = req.extensions_mut().insert(original_uri);
        }
        let extensions = req.extensions_mut();
        let _ = extensions.insert(crate::routing::extract::ConnectInfo(peer));
        let _ = extensions.insert(crate::routing::extract::MaxBodySize(self.max_body_size));
        // Threaded through extensions because the WebSocket extractor runs inside the router,
        // with no path back to the `Server`.
        #[cfg(feature = "ws")]
        let _ = extensions.insert(crate::ws::WebSocketLimit(self.websocket_permits.clone()));

        let Some(compression) = self.compression.as_ref() else {
            return self.router.handle_request(req).await;
        };
        // Taken before the request is consumed, because negotiation happens once the
        // handler has run and the request is gone by then. Cloning the `HeaderValue` rather
        // than copying out a `String` keeps this to a refcount bump on its backing bytes.
        let accept_encoding = req.headers().get(hyper::header::ACCEPT_ENCODING).cloned();
        let response = self.router.handle_request(req).await;
        match accept_encoding
            .as_ref()
            .and_then(|value| value.to_str().ok())
        {
            Some(accept_encoding) => compression.apply_to(accept_encoding, response).await,
            None => response,
        }
    }

    /// Compresses responses on every transport this `Server` runs, negotiating the coding
    /// against each request's `Accept-Encoding`.
    ///
    /// Applied once, at the point every transport funnels through, so HTTP/1.1, HTTP/2,
    /// HTTP/3, `.onion` and `.i2p` traffic all get identical treatment — including
    /// responses from [`ServeDir`](crate::ServeDir), fallbacks, and error paths that never
    /// reach a handler.
    ///
    /// See [`http::compression`](crate::http::compression) for what is and is not
    /// compressed, and [`Router::compression`](crate::Router::compression) to scope it to
    /// one router instead.
    ///
    /// ```rust,no_run
    /// # use tachyon_web::{Router, Server};
    /// use tachyon_web::http::compression::{Compression, CompressionLevel, Encoding};
    ///
    /// # let app: Router = Router::new();
    /// let server = Server::new(app).compression(
    ///     Compression::new()
    ///         .preference([Encoding::Zstd, Encoding::Gzip])
    ///         .quality(CompressionLevel::Fastest),
    /// );
    /// ```
    #[must_use]
    pub fn compression(mut self, compression: crate::http::compression::Compression) -> Self {
        self.compression = Some(compression);
        self
    }

    /// Enables `103 Early Hints` ([RFC 8297]) on the transports that can carry them.
    ///
    /// This does two things. It lets handlers' [`EarlyHints`] handles actually reach the
    /// wire, and — because `hyper` cannot emit an informational response — it moves HTTPS
    /// connections that negotiate `h2` onto Tachyon's own HTTP/2 driver. HTTP/1.1
    /// connections, h2c, Tor and I2P are untouched and continue to hand handlers a no-op
    /// handle.
    ///
    /// Read [`http::early_hints`](crate::http::early_hints) before enabling this: it covers
    /// the transport matrix, the `Sec-Fetch-Mode: navigate` gate, and the one behavioural
    /// difference the native HTTP/2 driver brings (RFC 8441 `WebSocket`s over HTTP/2 are
    /// answered `501`).
    ///
    /// ```rust,no_run
    /// # use tachyon_web::{Router, Server};
    /// use tachyon_web::http::early_hints::EarlyHintsConfig;
    ///
    /// # let app: Router = Router::new();
    /// let server = Server::new(app).early_hints(EarlyHintsConfig::new());
    /// ```
    ///
    /// [RFC 8297]: https://www.rfc-editor.org/rfc/rfc8297
    /// [`EarlyHints`]: crate::http::early_hints::EarlyHints
    #[cfg(feature = "early-hints")]
    #[must_use]
    pub const fn early_hints(mut self, config: crate::http::early_hints::EarlyHintsConfig) -> Self {
        self.early_hints = Some(config);
        self
    }

    /// Overrides the maximum request body size (in bytes).
    ///
    /// Requests whose body exceeds this limit are rejected with `413 Content Too Large`
    /// before the body bytes are fully buffered. The default is **2 MiB**, matching
    /// Axum's `DefaultBodyLimit` default.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use tachyon_web::{Router, Server};
    /// # let router = Router::new();
    /// let server = Server::new(router).max_body_size(64 * 1024 * 1024); // 64 MiB
    /// ```
    #[must_use]
    pub const fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Overrides the maximum number of concurrent connections **per worker thread**
    /// (default: 25,600 — see [`Server::max_connections`] for why this isn't a
    /// single process-wide cap).
    #[must_use]
    pub const fn max_connections(mut self, limit: usize) -> Self {
        self.max_connections = limit;
        self
    }

    /// Overrides the maximum number of concurrent established WebSocket connections
    /// (process-wide, default 25,600) — see
    /// [`Server::max_websocket_connections`](Self#structfield.max_websocket_connections) for
    /// why these need a ceiling of their own, and how to size it.
    ///
    /// Over-budget upgrades are refused with `426 Upgrade Required` before the handshake
    /// completes, rather than accepted and then starved.
    // Only `const`-eligible without `ws`, where there's no semaphore to rebuild — not worth
    // splitting the signature across features for.
    #[cfg_attr(not(feature = "ws"), allow(clippy::missing_const_for_fn))]
    #[must_use]
    pub fn max_websocket_connections(mut self, limit: usize) -> Self {
        self.max_websocket_connections = limit;
        #[cfg(feature = "ws")]
        {
            self.websocket_permits = Arc::new(tokio::sync::Semaphore::new(limit));
        }
        self
    }

    /// Overrides the maximum number of HTTP/3 streams handled concurrently **per QUIC
    /// connection** (default: 256) — see
    /// [`Server::max_h3_concurrent_streams`](Self#structfield.max_h3_concurrent_streams) for how
    /// this differs from [`max_connections`](Self::max_connections).
    ///
    /// Once a connection is at its limit, accepting its next stream simply waits for an
    /// in-flight one to finish rather than accepting it and starving the rest.
    #[cfg(feature = "http3")]
    #[must_use]
    pub const fn max_h3_concurrent_streams(mut self, limit: usize) -> Self {
        self.max_h3_concurrent_streams = limit;
        self
    }

    /// Sets a custom `rustls::crypto::CryptoProvider` to be used for TLS operations.
    ///
    /// This overrides the default provider (which uses `aws-lc-rs` with customized Kex and AEAD).
    /// Shorthand for `.tls_policy(TlsPolicy::with_provider(provider))` — use
    /// [`tls_policy`](Self::tls_policy) directly if you also want to restrict protocol
    /// versions (e.g. TLS 1.3-only) or install this provider process-wide for arti's Tor
    /// relay connections.
    ///
    /// Not available with the `fips` feature enabled: under `fips`, every `TlsPolicy` is forced
    /// onto the FIPS-140-3-compliant provider (see
    /// [`TlsPolicy`](crate::tls::TlsPolicy)'s `fips` docs) with no way to substitute a custom
    /// one, so this method doesn't compile in that build rather than silently ignoring the
    /// provider passed to it.
    #[cfg(all(feature = "tls", not(feature = "fips")))]
    #[must_use]
    pub fn crypto_provider(self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.tls_policy(crate::tls::TlsPolicy::with_provider(provider))
    }

    /// Sets the crypto/TLS policy shared by every listener this `Server` runs: clearnet HTTPS
    /// (static cert or Let's Encrypt), the onion `.onion` HTTPS termination, and the I2P
    /// eepsite's optional TLS layer. All three derive their `rustls::ServerConfig` (including
    /// self-signed certs) from the same [`TlsPolicy`](crate::tls::TlsPolicy) instead of each
    /// reconstructing their own defaults.
    ///
    /// Defaults to [`TlsPolicy::new`](crate::tls::TlsPolicy::new) if never called.
    ///
    /// See [`TlsPolicy`](crate::tls::TlsPolicy)'s docs for how this interacts with Tor's
    /// relay/channel TLS layer (a separate concern from HTTPS termination).
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_policy(mut self, policy: crate::tls::TlsPolicy) -> Self {
        self.tls_policy = Some(policy);
        self
    }

    /// Returns the effective [`TlsPolicy`](crate::tls::TlsPolicy) for this server: the one set
    /// via [`tls_policy`](Self::tls_policy)/[`crypto_provider`](Self::crypto_provider), or
    /// [`TlsPolicy::new`](crate::tls::TlsPolicy::new) if neither was called. With the `fips`
    /// feature enabled, every reachable `TlsPolicy` value is already FIPS-140-3-compliant by
    /// construction (see [`TlsPolicy`](crate::tls::TlsPolicy)'s `fips` docs), so there's nothing
    /// further to enforce here.
    ///
    /// Only consumed by the entry points that actually build a `rustls::ServerConfig`
    /// themselves — or, for `tor`, that install this policy's provider as rustls's
    /// process-wide default before bootstrapping (see `TlsPolicy`'s docs): `start_all`/
    /// `start_all_inner` (`cert-gen`), `serve_all_acme` (`lets-encrypt`, which implies
    /// `cert-gen`), `Server::serve_tor`/`serve_onion` (`tor` + `tls`, for the process-wide
    /// install — the plaintext-only `_with_client` variants never call this since they don't
    /// own the bootstrap), and the onion/i2p self-signed-cert paths in `server/tor.rs`/
    /// `server/i2p.rs` (both require `cert-gen`, already covered by that disjunct — a
    /// caller-supplied `OnionTls::Custom`/`I2pTls::Custom` config, needing only `tls`, doesn't
    /// call this at all). Gated the same way so builds that don't actually reach any of these
    /// paths don't trip `-D dead-code`.
    #[cfg(any(
        feature = "cert-gen",
        feature = "lets-encrypt",
        all(feature = "tor", feature = "tls"),
    ))]
    pub(crate) fn effective_tls_policy(&self) -> crate::tls::TlsPolicy {
        self.tls_policy.clone().unwrap_or_default()
    }

    /// Begins publishing this app over multiple transports at once — see
    /// [`MultiServer`] and the [module docs](self#publishing-over-more-than-one-transport-at-once).
    ///
    /// Adds a plaintext clearnet HTTP transport bound to `listener`; chain more `.with_*` calls
    /// (`.with_https`/`.with_h3`/`.with_onion`/`.with_i2p`) to add further transports, then
    /// finish with `.serve().await`.
    pub fn with_http(self, listener: TcpListener) -> MultiServer<S> {
        MultiServer::new(self).with_http(listener)
    }

    /// Begins publishing this app over multiple transports at once — see
    /// [`MultiServer`] and the [module docs](self#publishing-over-more-than-one-transport-at-once).
    ///
    /// Adds a clearnet HTTPS transport bound to `listener`, terminated with `config`. Requires
    /// the `tls` feature.
    #[cfg(feature = "tls")]
    pub fn with_https(self, listener: TcpListener, config: rustls::ServerConfig) -> MultiServer<S> {
        MultiServer::new(self).with_https(listener, config)
    }

    /// Begins publishing this app over multiple transports at once — see
    /// [`MultiServer`] and the [module docs](self#publishing-over-more-than-one-transport-at-once).
    ///
    /// Adds an HTTP/3-over-QUIC transport. Requires the `http3` feature.
    #[cfg(feature = "http3")]
    pub fn with_h3(self, quic_server: tachyon_quic::s2n_quic::Server) -> MultiServer<S> {
        MultiServer::new(self).with_h3(quic_server)
    }

    /// Begins publishing this app over multiple transports at once — see
    /// [`MultiServer`] and the [module docs](self#publishing-over-more-than-one-transport-at-once).
    ///
    /// Adds a Tor `.onion` hidden-service transport. Requires the `tor` feature.
    #[cfg(feature = "tor")]
    pub fn with_onion(self, config: tor::OnionConfig) -> MultiServer<S> {
        MultiServer::new(self).with_onion(config)
    }

    /// Begins publishing this app over multiple transports at once — see
    /// [`MultiServer`] and the [module docs](self#publishing-over-more-than-one-transport-at-once).
    ///
    /// Adds an I2P `.b32.i2p` eepsite transport. Requires the `i2p` feature
    /// ([breaks `forbid(unsafe_code)`](i2p)).
    #[cfg(feature = "i2p")]
    pub fn with_i2p(self, config: i2p::I2pConfig) -> MultiServer<S> {
        MultiServer::new(self).with_i2p(config)
    }

    /// Starts a pure plaintext HTTP server on an already-parsed address.
    ///
    /// # Errors
    /// Returns an error if the server fails to run.
    pub async fn start_http_addr(self, addr: std::net::SocketAddr) -> Result<(), std::io::Error> {
        run_worker_pool(self, addr, None, |server, listener| async move {
            server.serve_http(listener).await
        })
        .await
    }

    /// Starts a pure plaintext HTTP server on `http_addr` (e.g. `"0.0.0.0:80"`).
    ///
    /// # Errors
    /// Returns an error if `http_addr` does not parse or the server fails to run.
    pub async fn start_http(self, http_addr: &str) -> Result<(), std::io::Error> {
        self.start_http_addr(parse_addr(http_addr)?).await
    }

    /// HTTPS (HTTP/1.1 + HTTP/2) on an already-parsed address, with TLS configured by the
    /// caller rather than by `cert-gen` or the ACME automation.
    ///
    /// # Errors
    /// Returns an error if binding or the server itself fails.
    #[cfg(feature = "tls")]
    pub async fn start_https_with_config_addr(
        self,
        addr: std::net::SocketAddr,
        config: rustls::ServerConfig,
    ) -> Result<(), std::io::Error> {
        let config = Arc::new(config);
        run_worker_pool(self, addr, None, move |server, listener| {
            let config = config.clone();
            async move { server.serve_https_config(listener, (*config).clone()).await }
        })
        .await
    }

    /// HTTPS (HTTP/1.1 + HTTP/2) on `tls_addr` (e.g. `"0.0.0.0:443"`), with TLS configured by
    /// the caller rather than by `cert-gen` or the ACME automation.
    ///
    /// # Errors
    /// Returns an error if `tls_addr` does not parse or the server fails to run.
    #[cfg(feature = "tls")]
    pub async fn start_https_with_config(
        self,
        tls_addr: &str,
        config: rustls::ServerConfig,
    ) -> Result<(), std::io::Error> {
        self.start_https_with_config_addr(parse_addr(tls_addr)?, config)
            .await
    }

    /// HTTPS and HTTP/3 with a caller-supplied `rustls::ServerConfig`. Both listeners bind
    /// `tls_addr` — TCP for HTTPS, UDP for QUIC. The config's ALPN list is overwritten.
    ///
    /// # Errors
    /// Returns an error if FIPS enforcement, binding, or server initialization fails.
    #[cfg(all(feature = "tls", feature = "http3"))]
    pub async fn start_https_and_h3_with_config(
        self,
        tls_addr: &str,
        mut config: rustls::ServerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        enforce_fips_compliance()?;
        #[cfg(feature = "fips")]
        assert_fips_server_config(&config)?;

        config.alpn_protocols = alpn_protocols(true);
        let config = Arc::new(config);

        h3::spawn_h3(&self, config.clone(), tls_addr)?;

        let addr = parse_addr(tls_addr)?;
        let tls_acceptor = TlsAcceptor::from(config);
        let tls_acceptor = Arc::new(tls_acceptor);
        run_worker_pool(self, addr, None, move |server, listener| {
            let tls_acceptor = tls_acceptor.clone();
            async move { server.serve_https(listener, (*tls_acceptor).clone()).await }
        })
        .await?;

        Ok(())
    }

    /// Serves every enabled protocol from a PEM certificate chain and key: HTTPS on
    /// `tls_addr`, HTTP/3 on the same address when the `http3` feature is on, and — if
    /// `cleartext_addr` is `Some` — a redirect listener that still passes ACME HTTP-01
    /// challenges through, so an external client can renew while this server runs.
    ///
    /// Blocks on the HTTPS listener; the others run as spawned tasks.
    ///
    /// # Errors
    /// Returns an error if binding, TLS configuration, or certificate parsing fails.
    #[cfg(feature = "cert-gen")]
    pub async fn start_all(
        self,
        tls_addr: &str,
        cleartext_addr: Option<&str>,
        cert_pem: String,
        key_pem: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.start_all_inner(tls_addr, cleartext_addr, cert_pem, key_pem)
            .await
    }

    /// [`start_all`] plus an [`AcmeManager`], so certificates are issued and renewed in-process.
    ///
    /// The `cleartext_addr` listener answers HTTP-01 challenges and `308`s everything else to
    /// HTTPS, so port 80 must be publicly reachable for issuance to succeed. `domains` must all
    /// resolve to this server. `cache_dir` holds the account credentials and certificate and
    /// must be writable; reusing it across restarts is what keeps you under Let's Encrypt's
    /// rate limits. `staging` picks the staging environment — untrusted certs, far higher rate
    /// limits — and is what you want while testing.
    ///
    /// Waits up to a minute for the first certificate, then binds the TLS listener regardless.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tachyon_web::{Router, Server, get};
    ///
    /// async fn hello() -> &'static str { "Hello, HTTPS World!" }
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ///     #[cfg(feature = "lets-encrypt")]
    ///     {
    ///         let app = Router::new().route("/", get(hello));
    ///
    ///         Server::new(app)
    ///             .serve_all_acme(
    ///                 "0.0.0.0:443",
    ///                 "0.0.0.0:80",
    ///                 vec!["example.com".to_string(), "www.example.com".to_string()],
    ///                 "admin@example.com".to_string(),
    ///                 "/var/cache/tachyon/certs",
    ///                 false,  // false = production Let's Encrypt
    ///             )
    ///             .await?;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns an error if either address cannot be bound, the ACME account cannot be created
    /// or loaded, or provisioning fails after exhausting its retries.
    ///
    /// [`AcmeManager`]: crate::tls::acme::AcmeManager
    /// [`start_all`]: Server::start_all
    #[cfg(feature = "lets-encrypt")]
    pub async fn serve_all_acme(
        self,
        tls_addr: &str,
        cleartext_addr: &str,
        domains: Vec<String>,
        email: String,
        cache_dir: impl Into<std::path::PathBuf>,
        staging: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::tls::acme::AcmeManager;
        enforce_fips_compliance()?;

        // Built with this server's own policy so the ACME-issued certificate's signing key is
        // loaded through the same crypto provider the `ServerConfig` below negotiates with —
        // under `fips` those are distinct modules.
        let allowed_hosts: Arc<[String]> = Arc::from(domains.clone());
        let policy = self.effective_tls_policy();
        let acme = AcmeManager::with_policy(cache_dir, domains, email, staging, &policy);
        let resolver = acme.resolver();

        // Start the background renewal loop before attempting to serve.
        acme.start();

        // Give the renewal loop a bounded window to load a cached cert or
        // provision a fresh one before the TLS listener starts accepting —
        // otherwise every connection that lands before the first cert is
        // ready fails its handshake. If provisioning is still in flight after
        // the timeout (e.g. a slow ACME order), proceed anyway rather than
        // hang startup forever; those early connections will fail until the
        // cert lands, same as today, but the common case (cached or
        // fast-issued cert) now actually gets served from the start.
        let wait_start = tokio::time::Instant::now();
        while !resolver.has_certificate() {
            if wait_start.elapsed() >= FIRST_CERT_TIMEOUT {
                tracing::warn!(
                    "[acme] No certificate ready after {:?}; starting TLS listener anyway — \
                     connections will fail until provisioning completes",
                    FIRST_CERT_TIMEOUT
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Build the TLS config backed by the ACME hot-swap resolver, sharing the same
        // crypto/TLS policy as the onion/i2p listeners (see `Server::tls_policy`).
        let mut tls_config = tls_config_builder(&policy)?.with_cert_resolver(resolver);

        tls_config.alpn_protocols = alpn_protocols(cfg!(feature = "http3"));

        let tls_config = Arc::new(tls_config);
        let tls_acceptor = TlsAcceptor::from(tls_config.clone());

        #[cfg(feature = "http3")]
        h3::spawn_h3(&self, tls_config, tls_addr)?;

        // Bind the HTTPS listener and serve (blocks the calling task).
        let addr = parse_addr(tls_addr)?;
        let tls_acceptor = Arc::new(tls_acceptor);
        let redirect_addr = parse_addr(cleartext_addr)?;
        let https_port = parse_port(tls_addr, 443);
        run_worker_pool(
            self,
            addr,
            Some(RedirectInfo {
                addr: redirect_addr,
                https_port,
                allowed_hosts: Some(allowed_hosts),
            }),
            move |server, listener| {
                let tls_acceptor = tls_acceptor.clone();
                async move { server.serve_https(listener, (*tls_acceptor).clone()).await }
            },
        )
        .await?;

        Ok(())
    }

    /// Internal: shared setup logic for `start_all`.
    ///
    /// # Errors
    /// Returns an error if address binding, TLS configuration, or certificate parsing fails.
    #[cfg(feature = "cert-gen")]
    #[allow(clippy::too_many_lines)]
    async fn start_all_inner(
        self,
        tls_addr: &str,
        cleartext_addr: Option<&str>,
        cert_pem: String,
        key_pem: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        enforce_fips_compliance()?;

        let cert_chain: Vec<CertificateDer<'static>> = crate::tls::pem::certs(cert_pem.as_bytes());

        let key_der: PrivateKeyDer<'static> = crate::tls::pem::private_key(key_pem.as_bytes())
            .map_err(|e| crate::tls::pem::key_io_error(&e))?;

        // Shares the same crypto/TLS policy as the onion/i2p listeners — see
        // `Server::tls_policy`. Call `.tls_policy(TlsPolicy::new().tls13_only())` (or a
        // fully custom `TlsPolicy`) for stricter version pinning than the default (TLS 1.3
        // and 1.2 both offered).
        let policy = self.effective_tls_policy();
        let mut tls_config = tls_config_builder(&policy)?
            .with_single_cert(cert_chain, key_der)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid certificate or key: {e}"),
                )
            })?;

        tls_config.alpn_protocols = alpn_protocols(cfg!(feature = "http3"));

        let tls_config = Arc::new(tls_config);
        let tls_acceptor = TlsAcceptor::from(tls_config.clone());
        let https_port = parse_port(tls_addr, 443);

        let redirect_info = cleartext_addr
            .map(|cleartext_addr| {
                parse_addr(cleartext_addr).map(|addr| RedirectInfo {
                    addr,
                    https_port,
                    // No domain list is available here (only the cert/key PEM) — falls back
                    // to echoing the request's `Host` unchecked, as before. Prefer
                    // `serve_all_acme` when the domain list is known.
                    allowed_hosts: None,
                })
            })
            .transpose()?;

        // Start HTTP/3 QUIC Server (if the feature is enabled).
        #[cfg(feature = "http3")]
        h3::spawn_h3(&self, tls_config, tls_addr)?;

        // Start the HTTPS listener (blocks this task).
        let addr = parse_addr(tls_addr)?;
        let tls_acceptor = Arc::new(tls_acceptor);
        run_worker_pool(self, addr, redirect_info, move |server, listener| {
            let tls_acceptor = tls_acceptor.clone();
            async move { server.serve_https(listener, (*tls_acceptor).clone()).await }
        })
        .await?;

        Ok(())
    }
}

/// Enforces FIPS compliance on the cryptographic module.
/// If the `fips` feature is enabled and `aws-lc-rs` is not running in FIPS mode,
/// returns an error to prevent server startup.
///
/// This only checks that the *backend* is in FIPS mode — it says nothing about whether a
/// particular `rustls::ServerConfig` actually negotiates FIPS-approved algorithms. A config
/// built outside [`TlsPolicy`](crate::tls::TlsPolicy) (a caller-supplied one, or one built via
/// bare `rustls::ServerConfig::builder()`) can still offer non-approved suites/groups even
/// when this check passes. Every entry point that accepts such a config also calls
/// [`assert_fips_server_config`] to close that gap.
#[cfg_attr(
    not(feature = "fips"),
    allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)
)]
pub(crate) fn enforce_fips_compliance() -> Result<(), std::io::Error> {
    // `fips` implies `tls` (see the feature's Cargo.toml comment), so `aws_lc_rs` is always
    // linked whenever this branch is compiled.
    #[cfg(feature = "fips")]
    {
        if let Err(e) = aws_lc_rs::try_fips_mode() {
            return Err(std::io::Error::other(format!(
                "FIPS compliance check failed: {e}. Cryptographic backend is not in FIPS mode!"
            )));
        }
    }
    Ok(())
}

/// Whether an accept-loop I/O error indicates the process/system is transiently out of a
/// resource (file descriptors, or kernel memory for the new connection's own data
/// structures) rather than something wrong with the specific connection — the signal every
/// accept loop uses to back off briefly instead of spinning a tight retry loop.
///
/// `23`/`24`/`10024` are `ENFILE`/`EMFILE`/`WSAEMFILE`. The additional platform-gated codes
/// below are `ENOMEM`/`ENOBUFS` (or their BSD/Windows equivalents) — `accept(2)` can fail with
/// those under memory pressure just as readily as it can run out of descriptors, and a caller
/// spinning on either is equally counterproductive.
pub(crate) fn is_resource_exhaustion(e: &std::io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return false;
    };
    if matches!(code, 23 | 24 | 10024) {
        return true;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if matches!(code, 12 | 105) {
        // ENOMEM | ENOBUFS
        return true;
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    if matches!(code, 12 | 55) {
        // ENOMEM | ENOBUFS
        return true;
    }
    #[cfg(windows)]
    if matches!(code, 10055 | 8) {
        // WSAENOBUFS | WSA_NOT_ENOUGH_MEMORY
        return true;
    }
    false
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
