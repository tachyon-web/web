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
pub(crate) mod conn;
#[cfg(feature = "early-hints")]
mod h2;
#[cfg(feature = "http3")]
mod h3;
mod http;
#[cfg(feature = "i2p")]
pub mod i2p;
mod multi;
#[cfg(feature = "tor")]
pub mod tor;

pub use multi::MultiServer;

use crate::routing::CompiledRouter;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use crate::http::response::Body;
#[cfg(feature = "tls")]
use hyper::service::service_fn;
use hyper::{Request, Response};
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt", feature = "http3"))]
use tokio_rustls::TlsAcceptor;

/// Default read timeout for both plaintext and TLS connections.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default handshake timeout for TLS connections.
#[cfg(feature = "tls")]
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Per-worker connection ceiling for the plaintext port-80 redirect listener.
///
/// Far below [`Server::max_connections`] on purpose: every connection here gets a bodyless
/// `308` or a challenge token and closes, so the queue drains fast.
#[cfg(feature = "tls")]
pub const REDIRECT_MAX_CONNECTIONS: usize = 2048;
/// Default for [`Server::max_websocket_connections`] — see that field for how to size it.
pub const DEFAULT_MAX_WEBSOCKET_CONNECTIONS: usize = 25_600;
/// How long [`Server::serve_all_acme`] waits for the first certificate to be
/// cached or provisioned before starting the TLS listener regardless.
#[cfg(feature = "lets-encrypt")]
const FIRST_CERT_TIMEOUT: Duration = Duration::from_mins(1);

thread_local! {
    pub(crate) static IS_LOCAL_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn bind_reuseport(addr: std::net::SocketAddr) -> Result<std::net::TcpListener, std::io::Error> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        socket.set_reuse_port(true)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    socket.listen(4096)?;
    Ok(std::net::TcpListener::from(socket))
}

async fn run_worker_pool<S, F, Fut>(
    server: Server<S>,
    addr: std::net::SocketAddr,
    redirect_info: Option<(std::net::SocketAddr, u16)>,
    serve_fn: F,
) -> Result<(), std::io::Error>
where
    S: Clone + Send + Sync + 'static,
    F: Fn(Server<S>, TcpListener) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), std::io::Error>> + Send + 'static,
{
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let mut handles = Vec::new();
    let server = Arc::new(server);
    let serve_fn = Arc::new(serve_fn);
    // Each worker thread reports whether it managed to bind its listener, so
    // that a totally unbindable address (e.g. permission denied, or already
    // in use on every core) produces a real `Err` instead of hanging forever
    // on the `pending()` below with only a log line to show for it.
    let (bind_tx, bind_rx) = std::sync::mpsc::channel::<Result<(), std::io::Error>>();

    for i in 0..cores {
        let server = server.clone();
        let serve_fn = serve_fn.clone();
        let core_id = core_ids.get(i).copied();
        let bind_tx = bind_tx.clone();
        let handle = std::thread::Builder::new()
            .name(format!("tachyon-worker-{i}"))
            .stack_size(512 * 1024)
            .spawn(move || {
                if let Some(id) = core_id {
                    let _ = core_affinity::set_for_current(id);
                }

                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    tracing::error!("failed to build tokio runtime for worker thread");
                    return;
                };

                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    IS_LOCAL_WORKER.with(|flag| flag.set(true));

                    // Only used for the HTTP->HTTPS redirect listener, which requires TLS.
                    #[cfg(not(feature = "tls"))]
                    let _ = &redirect_info;

                    #[cfg(feature = "tls")]
                    if let Some((r_addr, https_port)) = redirect_info {
                        let r_listener_res = bind_reuseport(r_addr).and_then(TcpListener::from_std);
                        match r_listener_res {
                            Ok(l) => {
                                tokio::task::spawn_local(async move {
                                    serve_http_redirect_and_challenges(l, https_port).await;
                                });
                            }
                            Err(e) => {
                                tracing::error!("worker redirect bind error: {e}");
                            }
                        }
                    }

                    let listener_res = bind_reuseport(addr).and_then(TcpListener::from_std);
                    let listener = match listener_res {
                        Ok(l) => {
                            let _ = bind_tx.send(Ok(()));
                            l
                        }
                        Err(e) => {
                            tracing::error!("worker bind error: {e}");
                            let _ = bind_tx.send(Err(e));
                            return;
                        }
                    };

                    let server_clone = (*server).clone();

                    let _ = serve_fn(server_clone, listener).await;
                });
            })?;
        handles.push(handle);
    }
    drop(bind_tx);

    let bind_results = tokio::task::spawn_blocking(move || {
        (0..cores)
            .filter_map(|_| bind_rx.recv().ok())
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    let bound = bind_results.iter().filter(|r| r.is_ok()).count();
    if bound == 0 {
        return Err(bind_results
            .into_iter()
            .find_map(std::result::Result::err)
            .unwrap_or_else(|| {
                std::io::Error::other("all worker threads failed to bind their listener")
            }));
    }
    if bound < cores {
        tracing::warn!(
            "Only {bound}/{cores} worker threads bound successfully; running in a degraded state"
        );
    }

    let _ = handles;
    std::future::pending::<()>().await;
    Ok(())
}

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
    /// Crypto/TLS policy shared across every listener this `Server` runs — see
    /// [`Server::tls_policy`]. `None` means each listener falls back to
    /// [`TlsPolicy::hardened`](crate::tls::TlsPolicy::hardened).
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
        match accept_encoding.as_ref().and_then(|value| value.to_str().ok()) {
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
    ///         .level(CompressionLevel::Fastest),
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
    pub const fn early_hints(
        mut self,
        config: crate::http::early_hints::EarlyHintsConfig,
    ) -> Self {
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
    /// Over-budget upgrades are refused with `503 Service Unavailable` before the handshake
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

    /// Sets a custom `rustls::crypto::CryptoProvider` to be used for TLS operations.
    ///
    /// This overrides the default provider (which uses `aws-lc-rs` with customized Kex and AEAD).
    /// Shorthand for `.tls_policy(TlsPolicy::with_provider(provider))` — use
    /// [`tls_policy`](Self::tls_policy) directly if you also want to restrict protocol
    /// versions (e.g. TLS 1.3-only) or install this provider process-wide for arti's Tor
    /// relay connections.
    #[cfg(feature = "tls")]
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
    /// Defaults to [`TlsPolicy::hardened`](crate::tls::TlsPolicy::hardened) if never called.
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
    /// [`TlsPolicy::hardened`](crate::tls::TlsPolicy::hardened) if neither was called.
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
    pub fn with_h3(self, quic_server: s2n_quic::Server) -> MultiServer<S> {
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
        let addr: std::net::SocketAddr = http_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.start_http_addr(addr).await
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
        let addr: std::net::SocketAddr = tls_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.start_https_with_config_addr(addr, config).await
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

        config.alpn_protocols = alpn_protocols(true);
        let config = Arc::new(config);

        spawn_h3(&self, config.clone(), tls_addr)?;

        let addr: std::net::SocketAddr = tls_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
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
        let mut tls_config = rustls::ServerConfig::builder_with_provider(policy.provider())
            .with_protocol_versions(policy.versions())
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("TLS version configuration failed: {e}"),
                )
            })?
            .with_no_client_auth()
            .with_cert_resolver(resolver);

        tls_config.alpn_protocols = alpn_protocols(cfg!(feature = "http3"));

        let tls_config = Arc::new(tls_config);
        let tls_acceptor = TlsAcceptor::from(tls_config.clone());

        #[cfg(feature = "http3")]
        spawn_h3(&self, tls_config, tls_addr)?;

        // Bind the HTTPS listener and serve (blocks the calling task).
        let addr: std::net::SocketAddr = tls_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let tls_acceptor = Arc::new(tls_acceptor);
        let redirect_addr: std::net::SocketAddr = cleartext_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let https_port = parse_port(tls_addr, 443);
        run_worker_pool(
            self,
            addr,
            Some((redirect_addr, https_port)),
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
        // `Server::tls_policy`. Call `.tls_policy(TlsPolicy::hardened().tls13_only())` (or a
        // fully custom `TlsPolicy`) for stricter version pinning than the default (TLS 1.3
        // and 1.2 both offered).
        let policy = self.effective_tls_policy();
        let mut tls_config = rustls::ServerConfig::builder_with_provider(policy.provider())
            .with_protocol_versions(policy.versions())
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to configure TLS protocol versions: {e}"),
                )
            })?
            .with_no_client_auth()
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

        let redirect_info = if let Some(cleartext_addr) = cleartext_addr {
            let redirect_addr: std::net::SocketAddr = cleartext_addr
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            Some((redirect_addr, https_port))
        } else {
            None
        };

        // Start HTTP/3 QUIC Server (if the feature is enabled).
        #[cfg(feature = "http3")]
        spawn_h3(&self, tls_config, tls_addr)?;

        // Start the HTTPS listener (blocks this task).
        let addr: std::net::SocketAddr = tls_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let tls_acceptor = Arc::new(tls_acceptor);
        run_worker_pool(self, addr, redirect_info, move |server, listener| {
            let tls_acceptor = tls_acceptor.clone();
            async move { server.serve_https(listener, (*tls_acceptor).clone()).await }
        })
        .await?;

        Ok(())
    }
}

/// Builds the QUIC endpoint HTTP/3 is served over, from a rustls config and a bind address.
///
/// Shared by every `http3` entry point so their limits can't drift apart.
#[cfg(feature = "http3")]
fn build_quic_server(
    config: Arc<rustls::ServerConfig>,
    io: impl s2n_quic::provider::io::TryInto<Error: std::error::Error + Send + Sync + 'static>,
) -> Result<s2n_quic::Server, Box<dyn std::error::Error + Send + Sync>> {
    let limits = s2n_quic::provider::limits::Limits::new()
        // 1 MB flow-control windows match H/2 settings and saturate LAN pipes.
        .with_data_window(1_048_576)?
        .with_bidirectional_local_data_window(1_048_576)?
        .with_bidirectional_remote_data_window(1_048_576)?
        // 100ms is a safe, standard default initial RTT for public internet clients.
        .with_initial_round_trip_time(Duration::from_millis(100))?
        // More simultaneous streams per connection.
        .with_max_open_remote_bidirectional_streams(4096)?
        // Keep ACK overhead low: ACK every 4th packet (default is every 2nd).
        .with_ack_elicitation_interval(4)?
        // Disable active migration (saves state tracking).
        .with_active_connection_migration(false)?
        // Reduce connection-ID slots (fewer is fine for 0-RTT / stationary peers).
        .with_max_active_connection_ids(2)?
        // Aggressive handshake timeout: reject slow clients quickly.
        .with_max_handshake_duration(Duration::from_secs(5))?;

    Ok(s2n_quic::Server::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(config))?
        .with_limits(limits)?
        .with_io(io)?
        .start()?)
}

/// Spawns [`Server::serve_h3`] on a QUIC endpoint built for `config`/`io`, alongside whichever
/// TCP listener the caller goes on to run.
#[cfg(feature = "http3")]
fn spawn_h3<S>(
    server: &Server<S>,
    config: Arc<rustls::ServerConfig>,
    io: impl s2n_quic::provider::io::TryInto<Error: std::error::Error + Send + Sync + 'static>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    let quic_server = build_quic_server(config, io)?;
    let server = server.clone();
    drop(tokio::spawn(async move {
        let _ = server.serve_h3(quic_server).await;
    }));
    Ok(())
}

/// Enforces FIPS compliance on the cryptographic module.
/// If the `fips` feature is enabled and `aws-lc-rs` is not running in FIPS mode,
/// returns an error to prevent server startup.
#[allow(dead_code, clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
pub(crate) fn enforce_fips_compliance() -> Result<(), std::io::Error> {
    // `aws_lc_rs` is only linked when `tls` is enabled, so a `tor`/`i2p` + `fips` build without
    // `tls` has no crypto provider of ours to check. (`tachyon-i2p/fips` still governs
    // `libi2pd`'s separately-linked backend, independently of this check.)
    #[cfg(all(feature = "fips", feature = "tls"))]
    {
        if let Err(e) = aws_lc_rs::try_fips_mode() {
            return Err(std::io::Error::other(format!(
                "FIPS compliance check failed: {e}. Cryptographic backend is not in FIPS mode!"
            )));
        }
    }
    Ok(())
}

/// Builds the ALPN protocol list for a TLS `ServerConfig`, in preference order,
/// matching whichever of `http3`/`http2`/`http1` are actually compiled in — so
/// TLS never advertises a protocol the connection-handling code (gated on the
/// same features, see `server/http.rs`) has no branch to serve it with.
#[cfg(feature = "tls")]
pub(crate) fn alpn_protocols(include_h3: bool) -> Vec<Vec<u8>> {
    let mut protocols = Vec::with_capacity(3);
    if include_h3 {
        protocols.push(b"h3".to_vec());
    }
    #[cfg(feature = "http2")]
    protocols.push(b"h2".to_vec());
    #[cfg(feature = "http1")]
    protocols.push(b"http/1.1".to_vec());
    protocols
}

/// Parses the port number from a bind address string (e.g., `"0.0.0.0:443"`).
/// Falls back to `default_port` if parsing fails.
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
fn parse_port(addr: &str, default_port: u16) -> u16 {
    addr.split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default_port)
}

pub(crate) fn is_resource_exhaustion(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(23 | 24 | 10024))
}

/// Plain HTTP listener that answers `/.well-known/acme-challenge/<token>` from the global
/// challenge store and `308`s everything else to the equivalent HTTPS URL.
///
/// `308` rather than `301` because it preserves the request method, so redirected `POST`s stay
/// `POST`s.
///
/// Concurrency is capped at [`REDIRECT_MAX_CONNECTIONS`] per worker. This listener is bound to
/// port 80 and therefore reachable by anyone, but it answers only redirects and ACME
/// challenges — it never reaches the router — so it uses its own fixed ceiling rather than
/// [`Server::max_connections`], which sizes the listener that actually runs application
/// handlers.
#[cfg(feature = "tls")]
pub async fn serve_http_redirect_and_challenges(listener: TcpListener, https_port: u16) {
    let builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(REDIRECT_MAX_CONNECTIONS));

    loop {
        let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
            return;
        };
        let (stream, _peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("[http-redirect] accept error: {e}");
                drop(permit);
                if is_resource_exhaustion(&e) {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let io = hyper_util::rt::TokioIo::new(stream);
        let builder = builder.clone();

        drop(tokio::spawn(async move {
            let _ = builder
                .serve_connection(
                    io,
                    service_fn(move |req: Request<hyper::body::Incoming>| {
                        async move {
                            // Serve ACME HTTP-01 challenge response.
                            #[cfg(feature = "lets-encrypt")]
                            if let Some(token) = req
                                .uri()
                                .path()
                                .strip_prefix("/.well-known/acme-challenge/")
                                && let Some(key_auth) = crate::tls::acme::get_challenge(token)
                            {
                                let resp = Response::builder()
                                    .status(200)
                                    .header("content-type", "text/plain")
                                    .body(Body::full(bytes::Bytes::from(key_auth)))
                                    .unwrap_or_else(|_| Response::new(Body::empty()));
                                return Ok::<_, std::convert::Infallible>(resp);
                            }

                            // 308 Permanent Redirect to HTTPS (preserves method).
                            let host = req
                                .headers()
                                .get("host")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("localhost");
                            let host_no_port = host.split(':').next().unwrap_or("localhost");
                            let port_suffix = if https_port == 443 {
                                String::new()
                            } else {
                                format!(":{https_port}")
                            };
                            let path_and_query = req
                                .uri()
                                .path_and_query()
                                .map_or("/", hyper::http::uri::PathAndQuery::as_str);
                            let location =
                                format!("https://{host_no_port}{port_suffix}{path_and_query}");

                            let resp = Response::builder()
                                .status(308) // 308 Permanent Redirect preserves the HTTP method.
                                .header("location", &location)
                                .body(Body::empty())
                                .unwrap_or_else(|_| Response::new(Body::empty()));
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    }),
                )
                .await;
            drop(permit);
        }));
    }
}

/// Start serving requests from the given `TcpListener` using the provided `Router`.
///
/// This resolves the listener's local address, automatically compiles the router,
/// and runs the high-performance worker pool.
///
/// # `listener` is rebound, not adopted
///
/// The worker pool binds one `SO_REUSEPORT` socket per core, so `listener` is read for its
/// local address and then **dropped** before those are created. Two consequences worth
/// knowing about: the port is briefly unbound, so on a shared host another process can race
/// in and take it (the resulting bind failure surfaces as an `Err` here); and a listener bound
/// to port `0` resolves to a concrete port first, so the workers all land on the same one.
/// Pass the address to [`Server::start_http`]/[`Server::start_http_addr`] instead if you'd
/// rather never hold the binding twice.
///
/// # Errors
///
/// Returns an error if compiling the router fails, or if binding/running the server workers fails.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: crate::routing::Router<()>,
) -> Result<(), std::io::Error> {
    let addr = listener.local_addr()?;
    // drop the listener so the port is free to bind SO_REUSEPORT sockets in the worker pool
    drop(listener);

    let server = Server::new(router);
    server.start_http_addr(addr).await
}

/// Configuration for custom rustls server.
#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct RustlsConfig {
    pub(crate) server_config: Arc<rustls::ServerConfig>,
}

#[cfg(feature = "tls")]
impl std::fmt::Debug for RustlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsConfig").finish_non_exhaustive()
    }
}

#[cfg(feature = "tls")]
impl RustlsConfig {
    /// Create a new `RustlsConfig` from PEM-formatted certificate chain and private key bytes.
    ///
    /// # Errors
    /// Returns an error if the certificates or private key cannot be parsed, or if the config is invalid.
    #[allow(clippy::unused_async)]
    pub async fn from_pem(cert: Vec<u8>, key: Vec<u8>) -> Result<Self, std::io::Error> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let cert_chain: Vec<CertificateDer<'static>> = crate::tls::pem::certs(&cert);

        let key_der: PrivateKeyDer<'static> =
            crate::tls::pem::private_key(&key).map_err(|e| crate::tls::pem::key_io_error(&e))?;

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        server_config.alpn_protocols = alpn_protocols(false);

        Ok(Self {
            server_config: Arc::new(server_config),
        })
    }
}

/// Create an HTTPS server bound to the given `SocketAddr` using the provided `RustlsConfig`.
#[cfg(feature = "tls")]
#[must_use]
pub const fn bind_rustls(addr: std::net::SocketAddr, config: RustlsConfig) -> HttpsServer {
    HttpsServer {
        addr,
        config,
        serve_http3: false,
    }
}

/// An HTTPS server ready to be run.
#[cfg(feature = "tls")]
pub struct HttpsServer {
    addr: std::net::SocketAddr,
    config: RustlsConfig,
    serve_http3: bool,
}

#[cfg(feature = "tls")]
impl std::fmt::Debug for HttpsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsServer")
            .field("addr", &self.addr)
            .field("serve_http3", &self.serve_http3)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tls")]
impl HttpsServer {
    /// Enable or disable HTTP/3 (QUIC) support on the same port.
    ///
    /// Note: HTTP/3 requires the `http3` feature to be enabled.
    #[must_use]
    pub const fn serve_http3(mut self, enable: bool) -> Self {
        self.serve_http3 = enable;
        self
    }

    /// Run the server with the given router.
    ///
    /// # Errors
    /// Returns an error if compiling the router or running the server fails.
    pub async fn serve(self, router: crate::routing::Router<()>) -> Result<(), std::io::Error> {
        let server = Server::new(router);
        #[cfg_attr(not(feature = "http3"), allow(unused_mut))]
        let mut rustls_config = (*self.config.server_config).clone();

        #[cfg(feature = "http3")]
        if self.serve_http3 {
            // Ensure ALPN lists "h3"
            if !rustls_config.alpn_protocols.iter().any(|p| p == b"h3") {
                rustls_config.alpn_protocols.insert(0, b"h3".to_vec());
            }

            spawn_h3(&server, Arc::new(rustls_config.clone()), self.addr)
                .map_err(std::io::Error::other)?;
        }

        server
            .start_https_with_config_addr(self.addr, rustls_config)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Router;

    /// `Server::clone` is hand-written (the field list is feature-gated, so `derive` can't be
    /// used); this catches a field being dropped when a new one is added.
    #[test]
    #[allow(clippy::redundant_clone)]
    fn clone_preserves_every_field() {
        #[cfg_attr(not(feature = "tls"), allow(unused_mut))]
        let mut server = Server::new(Router::new())
            .max_body_size(4096)
            .max_connections(7)
            .max_websocket_connections(9);
        #[cfg(feature = "tls")]
        {
            server = server.tls_policy(crate::tls::TlsPolicy::hardened().tls13_only());
        }

        let cloned = server.clone();
        assert_eq!(cloned.max_body_size, 4096);
        assert_eq!(cloned.max_connections, 7);
        assert_eq!(cloned.max_websocket_connections, 9);
        #[cfg(feature = "ws")]
        {
            assert_eq!(cloned.websocket_permits.available_permits(), 9);
            let _held = server
                .websocket_permits
                .clone()
                .try_acquire_owned()
                .expect("permit available");
            assert_eq!(
                cloned.websocket_permits.available_permits(),
                8,
                "clones must draw on one shared budget"
            );
        }
        #[cfg(feature = "tls")]
        assert!(cloned.tls_policy.is_some());
    }

    #[test]
    fn is_resource_exhaustion_matches_only_known_codes() {
        for code in [23, 24, 10024] {
            assert!(
                is_resource_exhaustion(&std::io::Error::from_raw_os_error(code)),
                "code: {code}"
            );
        }
        assert!(!is_resource_exhaustion(&std::io::Error::from_raw_os_error(
            2
        )));
        assert!(!is_resource_exhaustion(&std::io::Error::other(
            "not an os error"
        )));
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn rustls_config_from_pem_rejects_garbage_input() {
        let err = RustlsConfig::from_pem(b"not a cert".to_vec(), b"not a key".to_vec())
            .await
            .expect_err("garbage PEM must not build a config");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(feature = "cert-gen")]
    #[tokio::test]
    async fn rustls_config_from_pem_builds_from_a_valid_self_signed_cert() {
        let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let config = RustlsConfig::from_pem(cert.cert_pem.into_bytes(), cert.key_pem.into_bytes())
            .await
            .expect("build config from valid PEM");
        assert!(!config.server_config.alpn_protocols.is_empty());
    }

    #[cfg(feature = "cert-gen")]
    #[test]
    fn bind_rustls_and_https_server_builders() {
        let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert_der], cert.key_der)
            .expect("build server config");
        server_config.alpn_protocols = alpn_protocols(false);
        let config = RustlsConfig {
            server_config: Arc::new(server_config),
        };
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("parse addr");

        let https_server = bind_rustls(addr, config);
        assert_eq!(https_server.addr, addr);
        assert!(!https_server.serve_http3);
        let dbg = format!("{https_server:?}");
        assert!(dbg.contains("HttpsServer"));
        assert!(dbg.contains("serve_http3: false"));

        let https_server = https_server.serve_http3(true);
        assert!(https_server.serve_http3);
        let dbg = format!("{https_server:?}");
        assert!(dbg.contains("serve_http3: true"));
    }
}
