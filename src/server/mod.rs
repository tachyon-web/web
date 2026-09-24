//! The [`Server`] engine: wraps an Axum [`Router`] and dispatches incoming streams for
//! every supported transport.
//!
//! # Protocol support
//!
//! Rows appear for the transports enabled in this build.
//!
//! | Method | Protocol | Feature flag |
//! |---|---|---|
//! | [`serve_http`](Server::serve_http) | HTTP/1.1 plain TCP (+ HTTP/2 cleartext "h2c" with `http2` and `SecurityPolicy::allow_h2c`) | *(always)* |
#![cfg_attr(
    feature = "tls",
    doc = "| [`serve_https`](Server::serve_https) | HTTP/1.1 + HTTP/2 over TLS | `tls` |"
)]
#![cfg_attr(
    feature = "tls",
    doc = "| [`serve_https_config`](Server::serve_https_config) | Same, from a `rustls::ServerConfig` | `tls` |"
)]
#![cfg_attr(
    feature = "http3",
    doc = "| [`serve_h3`](Server::serve_h3) | HTTP/3 over QUIC | `http3` |"
)]
#![cfg_attr(
    feature = "cert-gen",
    doc = "| [`start_all`](Server::start_all) | HTTPS (+ HTTP/3 with `http3`) and an optional HTTP→HTTPS redirect listener, from PEM cert/key strings | `cert-gen` |"
)]
#![cfg_attr(
    feature = "lets-encrypt",
    doc = "| [`serve_all_acme`](Server::serve_all_acme) | Same as `start_all`, with certs issued and renewed by Let's Encrypt | `lets-encrypt` |"
)]
#![cfg_attr(
    feature = "tor",
    doc = "| [`serve_tor`](Server::serve_tor) | HTTP/1.1 (+ h2c) over a native Tor `.onion` hidden service | `tor` |"
)]
#![cfg_attr(
    feature = "i2p",
    doc = "| [`serve_i2p`](Server::serve_i2p) | HTTP/1.1 (+ h2c) over a native I2P `.b32.i2p` eepsite ([breaks `forbid(unsafe_code)`](i2p)) | `i2p` |"
)]
//!
//! # Publishing over more than one transport at once
//!
//! Each `serve_*` method consumes its `Server` and blocks for that one transport's lifetime.
//! To publish the same app over several transports from one process, use [`MultiServer`]
//! rather than hand-rolling `tokio::spawn` + `tokio::select!`:
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use axum::{Router, routing::get};
//! use tachyon_web::Server;
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

mod accept;
#[cfg(any(feature = "tor", feature = "i2p"))]
mod anon_tls;
mod bind;
// Its tests need a protocol they can drive: HTTP/1.1, or HTTP/2 with `ws` (see `conn::tests`).
#[cfg(any(
    feature = "tor",
    feature = "i2p",
    all(test, any(feature = "http1", feature = "ws"))
))]
pub(crate) mod conn;
#[cfg(feature = "http3")]
mod h3;
mod http;
#[cfg(feature = "i2p")]
pub mod i2p;
mod multi;
mod redirect;
mod security;
mod stall;
#[cfg(feature = "tls")]
pub(crate) mod tls_config;
#[cfg(feature = "tls")]
mod tls_serve;
#[macro_use]
mod tuning;
#[cfg(feature = "tor")]
pub mod tor;

pub use multi::MultiServer;
pub use security::{IpNetwork, SecurityPolicy};
#[cfg(feature = "tls")]
pub use tls_config::{HttpsServer, RustlsConfig, bind_rustls};

use axum::Router;
use axum::body::Body;
use hyper::{Request, Response};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

use bind::bind_and_serve;
use redirect::parse_addr;
#[cfg(feature = "fips")]
use tls_config::assert_fips_server_config;

/// A server-owned sidecar task that cannot outlive the serving future that spawned it.
#[cfg(any(feature = "cert-gen", feature = "http3"))]
#[derive(Debug)]
pub(crate) struct BackgroundTask(tokio::task::JoinHandle<()>);

#[cfg(any(feature = "cert-gen", feature = "http3"))]
impl BackgroundTask {
    pub(crate) const fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self(task)
    }
}

#[cfg(any(feature = "cert-gen", feature = "http3"))]
impl Drop for BackgroundTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Preset for deployment controls owned by this transport layer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeploymentProfile {
    /// Conservative public-service limits and hardened response defaults.
    #[default]
    Hardened,
    /// Hardened limits plus disabled TLS resumption and smaller anonymity/linkability surface.
    ExtremePrivacy,
}

/// Default read timeout for both plaintext and TLS connections.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default handshake timeout for TLS connections.
#[cfg(feature = "tls")]
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a single write may make no progress before the connection (or, on HTTP/3, the
/// stream) is abandoned.
///
/// Per write rather than per response, so slow-but-draining clients and open SSE streams are
/// unaffected while a peer that has stopped reading is dropped. See `stall::WriteDeadline`.
pub(crate) const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The [`ConnectInfo`](axum::extract::ConnectInfo) reported where the transport has no peer
/// address (Tor/I2P both exist specifically to hide it).
///
/// Every such request reports the same `0.0.0.0:0`, so per-IP rate limiters collapse to one
/// bucket, and a "trust anything non-global" check trusts all of them. [`SecurityPolicy`]
/// never consults it: those transports pass no peer at all.
pub(crate) const NO_PEER_ADDR: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Default for [`Limits::max_connections`].
///
/// *Tachyon extension: no `axum` equivalent.*
pub const DEFAULT_MAX_CONNECTIONS: usize = 4_096;
/// Default for [`Limits::redirect_connection_share`].
///
/// *Tachyon extension: no `axum` equivalent.*
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
pub const DEFAULT_REDIRECT_CONNECTION_SHARE: u8 = 15;
/// Default for [`Limits::max_h3_concurrent_streams`].
///
/// *Tachyon extension: no `axum` equivalent.*
#[cfg(feature = "http3")]
pub const DEFAULT_MAX_H3_CONCURRENT_STREAMS: usize = 32;

/// The size and concurrency limits a [`Server`] enforces, as returned by [`Server::limits`].
///
/// Each is set through the [`Server`] builder method of the same name, which also keeps the
/// semaphores that enforce it in step. Connection and handler limits are shared by every
/// transport a `Server` (and its clones) runs, so adding listeners does not multiply them.
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum request body size in bytes. Default: 2 MiB, matching Axum's `DefaultBodyLimit`.
    pub max_body_size: usize,
    /// Maximum concurrent connections across all transports. Default:
    /// [`DEFAULT_MAX_CONNECTIONS`].
    pub max_connections: usize,
    /// Maximum application handlers executing concurrently. Default: 1,024.
    pub max_active_requests: usize,
    /// Maximum TLS handshakes in flight. Default: 1,024.
    #[cfg(feature = "tls")]
    pub max_tls_handshakes: usize,
    /// Maximum HTTP/3 streams handled concurrently per QUIC connection. Default:
    /// [`DEFAULT_MAX_H3_CONCURRENT_STREAMS`].
    #[cfg(feature = "http3")]
    pub max_h3_concurrent_streams: usize,
    /// Percentage of `max_connections` the plaintext redirect listener may hold. Default:
    /// [`DEFAULT_REDIRECT_CONNECTION_SHARE`].
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    pub redirect_connection_share: u8,
}

/// Main server configuration and runner.
///
/// Wraps an Axum [`Router`] and provides `serve_*` methods for each transport. Cloning is
/// cheap, and clones share one set of concurrency limits.
///
/// # Example
///
/// ```rust,no_run
/// use axum::{Router, routing::get};
/// use tachyon_web::Server;
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
#[derive(Clone, Debug)]
pub struct Server {
    router: Router,
    limits: Limits,
    connection_limit: accept::ConnectionLimit,
    request_limit: Arc<tokio::sync::Semaphore>,
    security_policy: SecurityPolicy,
    #[cfg(feature = "tls")]
    tls_handshake_limit: Arc<tokio::sync::Semaphore>,
    #[cfg(feature = "tls")]
    tls_policy: Option<crate::tls::TlsPolicy>,
    #[cfg(feature = "tls")]
    profile: DeploymentProfile,
    #[cfg(feature = "cnsa")]
    cnsa_identity_verified: bool,
}

impl From<Router> for Server {
    fn from(router: Router) -> Self {
        Self::new(router)
    }
}

impl Server {
    /// Creates a new `Server` with default settings and the given router.
    ///
    /// Defaults: see [`Limits`], and [`SecurityPolicy::new`]'s fail-safe request policy.
    #[must_use]
    pub fn new(router: Router) -> Self {
        let limits = Limits {
            max_body_size: 2 * 1024 * 1024,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_active_requests: 1_024,
            #[cfg(feature = "tls")]
            max_tls_handshakes: 1_024,
            #[cfg(feature = "http3")]
            max_h3_concurrent_streams: DEFAULT_MAX_H3_CONCURRENT_STREAMS,
            #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
            redirect_connection_share: DEFAULT_REDIRECT_CONNECTION_SHARE,
        };
        Self {
            router,
            limits,
            connection_limit: accept::ConnectionLimit::new(limits.max_connections),
            request_limit: Arc::new(tokio::sync::Semaphore::new(limits.max_active_requests)),
            security_policy: SecurityPolicy::new(),
            #[cfg(feature = "tls")]
            tls_handshake_limit: Arc::new(tokio::sync::Semaphore::new(limits.max_tls_handshakes)),
            #[cfg(feature = "tls")]
            tls_policy: None,
            #[cfg(feature = "tls")]
            profile: DeploymentProfile::default(),
            #[cfg(feature = "cnsa")]
            cnsa_identity_verified: false,
        }
    }

    /// Attaches the per-request extensions and routes the request.
    ///
    /// Every transport funnels through here so they can't disagree about which extensions a
    /// handler sees. `peer` is `None` on an anonymity transport — see [`NO_PEER_ADDR`].
    async fn dispatch(
        &self,
        mut req: Request<Body>,
        peer: Option<std::net::SocketAddr>,
        secure_transport: bool,
    ) -> Response<Body> {
        if let Some(response) = self.reject(&mut req, peer, secure_transport) {
            return response;
        }
        self.route(req, peer, secure_transport).await
    }

    /// The security policy's verdict on a request's head, finalized and ready to send.
    ///
    /// Split from [`route`](Self::route) so HTTP/3, which buffers bodies, can refuse a request
    /// before reading one.
    fn reject(
        &self,
        req: &mut Request<Body>,
        peer: Option<std::net::SocketAddr>,
        secure_transport: bool,
    ) -> Option<Response<Body>> {
        let mut response = self.security_policy.inspect(req, peer, secure_transport)?;
        self.security_policy
            .finalize_response(&mut response, secure_transport);
        Some(response)
    }

    /// Routes a request that [`reject`](Self::reject) already let through.
    async fn route(
        &self,
        mut req: Request<Body>,
        peer: Option<std::net::SocketAddr>,
        secure_transport: bool,
    ) -> Response<Body> {
        let Ok(_permit) = self.request_limit.clone().try_acquire_owned() else {
            let mut response = security::empty_response(hyper::StatusCode::SERVICE_UNAVAILABLE);
            self.security_policy
                .finalize_response(&mut response, secure_transport);
            return response;
        };
        let extensions = req.extensions_mut();
        let _ = extensions.insert(axum::extract::ConnectInfo(peer.unwrap_or(NO_PEER_ADDR)));
        match self.router.clone().oneshot(req).await {
            Ok(mut response) => {
                self.security_policy
                    .finalize_response(&mut response, secure_transport);
                response
            }
            Err(never) => match never {},
        }
    }

    /// The limits this server enforces.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Overrides the maximum request body size (in bytes).
    ///
    /// Request streams exceeding this limit are terminated before the excess bytes are
    /// buffered. The default is **2 MiB**, matching Axum's `DefaultBodyLimit` default.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use axum::Router;
    /// # use tachyon_web::Server;
    /// # let router = Router::new();
    /// let server = Server::new(router).max_body_size(64 * 1024 * 1024); // 64 MiB
    /// ```
    #[must_use]
    pub const fn max_body_size(mut self, size: usize) -> Self {
        self.limits.max_body_size = size;
        self
    }

    /// Overrides the maximum number of concurrent connections shared by all transports. Values
    /// below one are clamped to one so a configuration mistake cannot permanently stop
    /// acceptance.
    #[must_use]
    pub fn max_connections(mut self, limit: usize) -> Self {
        self.limits.max_connections = limit.max(1);
        self.connection_limit = accept::ConnectionLimit::new(self.limits.max_connections);
        self
    }

    /// Limits application handlers executing concurrently across every transport. Excess
    /// requests are shed immediately with `503 Service Unavailable` instead of being queued.
    #[must_use]
    pub fn max_active_requests(mut self, limit: usize) -> Self {
        self.limits.max_active_requests = limit.max(1);
        self.request_limit = Arc::new(tokio::sync::Semaphore::new(self.limits.max_active_requests));
        self
    }

    /// Limits concurrent TLS handshakes. Connections beyond the limit are dropped before
    /// performing asymmetric cryptographic work.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn max_tls_handshakes(mut self, limit: usize) -> Self {
        self.limits.max_tls_handshakes = limit.max(1);
        self.tls_handshake_limit =
            Arc::new(tokio::sync::Semaphore::new(self.limits.max_tls_handshakes));
        self
    }

    /// Overrides the maximum number of HTTP/3 streams handled concurrently **per QUIC
    /// connection**; further streams are refused. Values below one are clamped to one.
    ///
    /// H3 request bodies are buffered up to [`max_body_size`](Self::max_body_size) before the
    /// handler runs, so one connection can pin roughly `max_h3_concurrent_streams ×
    /// max_body_size` (32 × 2 MiB = 64 MiB at the defaults), and `max_connections` multiplies
    /// that. Size the three together for the memory you have.
    #[cfg(feature = "http3")]
    #[must_use]
    pub const fn max_h3_concurrent_streams(mut self, limit: usize) -> Self {
        self.limits.max_h3_concurrent_streams = if limit == 0 { 1 } else { limit };
        self
    }

    /// Caps the plaintext HTTP→HTTPS redirect listener at `percent` of
    /// [`max_connections`](Self::max_connections), so a flood of cheap port-80 connections
    /// cannot take the permits the TLS listener needs.
    ///
    /// A redirect connection still holds a permit from the shared pool as well, so this caps
    /// that listener's slice rather than adding a second budget. Values above 100 are clamped,
    /// and the resulting budget is never less than one permit, so redirects (and with them ACME
    /// renewals) can't be stopped entirely. Order-independent with `max_connections`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use axum::Router;
    /// # use tachyon_web::Server;
    /// # let router = Router::new();
    /// // 4,096 connections overall, of which at most 204 may be port-80 redirects.
    /// let server = Server::new(router).max_connections(4_096).redirect_connection_share(5);
    /// ```
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    #[must_use]
    pub const fn redirect_connection_share(mut self, percent: u8) -> Self {
        self.limits.redirect_connection_share = if percent > 100 { 100 } else { percent };
        self
    }

    /// The redirect listener's slice of the pool, in permits: rounded down, then floored at one.
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    fn redirect_connection_permits(&self) -> usize {
        self.limits
            .max_connections
            .saturating_mul(usize::from(self.limits.redirect_connection_share))
            .checked_div(100)
            .unwrap_or(0)
            .max(1)
    }

    /// Sets the request-boundary security policy.
    #[must_use]
    pub fn security_policy(mut self, policy: SecurityPolicy) -> Self {
        self.security_policy = policy;
        self
    }

    /// Applies a coherent deployment preset. Compile-time `fips` and `cnsa` restrictions still
    /// take precedence and cannot be weakened by selecting a profile.
    ///
    /// [`DeploymentProfile::ExtremePrivacy`]'s TLS resumption lockdown is applied whenever a
    /// listener's TLS config is built, so it holds regardless of when
    /// `tls_policy` is called. Its concurrency ceilings apply immediately
    /// and only ever *lower* the configured limits; a later limit setter overrides them.
    #[must_use]
    pub fn deployment_profile(mut self, profile: DeploymentProfile) -> Self {
        if profile == DeploymentProfile::ExtremePrivacy {
            let limits = self.limits;
            self = self
                .max_connections(limits.max_connections.min(2_048))
                .max_active_requests(limits.max_active_requests.min(512));
            #[cfg(feature = "http3")]
            {
                self.limits.max_h3_concurrent_streams = limits.max_h3_concurrent_streams.min(16);
            }
        }
        #[cfg(feature = "tls")]
        {
            self.profile = profile;
        }
        self
    }

    /// Sets a custom `rustls::crypto::CryptoProvider` for TLS — shorthand for
    /// `.tls_policy(TlsPolicy::with_provider(provider))`.
    ///
    /// Not available with the `fips` feature, where every `TlsPolicy` is forced onto the FIPS
    /// provider; the method doesn't compile rather than silently ignoring its argument.
    #[cfg(all(feature = "tls", not(feature = "fips")))]
    #[must_use]
    pub fn crypto_provider(self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.tls_policy(crate::tls::TlsPolicy::with_provider(provider))
    }

    /// Sets the crypto/TLS policy shared by every listener this `Server` runs: clearnet HTTPS
    /// (static cert or Let's Encrypt), `.onion` HTTPS termination, and the I2P eepsite's
    /// optional TLS layer. Defaults to [`TlsPolicy::new`](crate::tls::TlsPolicy::new).
    ///
    /// See [`TlsPolicy`](crate::tls::TlsPolicy)'s docs for how this interacts with Tor's
    /// relay/channel TLS layer.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_policy(mut self, policy: crate::tls::TlsPolicy) -> Self {
        self.tls_policy = Some(policy);
        self
    }

    /// The configured [`TlsPolicy`](crate::tls::TlsPolicy) (or the default), with the
    /// deployment profile's resumption lockdown folded in.
    #[cfg(feature = "tls")]
    fn effective_tls_policy(&self) -> crate::tls::TlsPolicy {
        let policy = self.tls_policy.clone().unwrap_or_default();
        if self.profile == DeploymentProfile::ExtremePrivacy {
            policy.disable_resumption(true)
        } else {
            policy
        }
    }

    /// Applies this server's effective policy to a `rustls::ServerConfig` this crate did not
    /// build, and freezes it. Every entry point that takes an outside config goes through here.
    #[cfg(feature = "tls")]
    fn finalize_tls_config(&self, mut config: rustls::ServerConfig) -> Arc<rustls::ServerConfig> {
        self.effective_tls_policy()
            .apply_to_server_config(&mut config);
        Arc::new(config)
    }

    /// Begins publishing this app over multiple transports at once, starting with plaintext
    /// HTTP on `listener` — see [`MultiServer`].
    pub fn with_http(self, listener: TcpListener) -> MultiServer {
        MultiServer::new(self).with_http(listener)
    }

    /// Begins a [`MultiServer`] with HTTPS on `listener`, terminated with `config`.
    #[cfg(feature = "tls")]
    pub fn with_https(self, listener: TcpListener, config: rustls::ServerConfig) -> MultiServer {
        MultiServer::new(self).with_https(listener, config)
    }

    /// Begins a [`MultiServer`] with an HTTP/3-over-QUIC transport.
    #[cfg(feature = "http3")]
    pub fn with_h3(self, quic_server: tachyon_quic::s2n_quic::Server) -> MultiServer {
        MultiServer::new(self).with_h3(quic_server)
    }

    /// Begins a [`MultiServer`] with a Tor `.onion` hidden-service transport.
    #[cfg(feature = "tor")]
    pub fn with_onion(self, config: tor::OnionConfig) -> MultiServer {
        MultiServer::new(self).with_onion(config)
    }

    /// Begins a [`MultiServer`] with an I2P `.b32.i2p` eepsite transport
    /// ([breaks `forbid(unsafe_code)`](i2p)).
    #[cfg(feature = "i2p")]
    pub fn with_i2p(self, config: i2p::I2pConfig) -> MultiServer {
        MultiServer::new(self).with_i2p(config)
    }

    /// Starts a pure plaintext HTTP server on an already-parsed address.
    ///
    /// # Errors
    /// Returns an error if binding fails or the server fails to run.
    pub async fn start_http_addr(self, addr: std::net::SocketAddr) -> Result<(), std::io::Error> {
        bind_and_serve(self, addr, None, Self::serve_http).await
    }

    /// Starts a pure plaintext HTTP server on `http_addr` (e.g. `"0.0.0.0:80"`).
    ///
    /// # Errors
    /// Returns an error if `http_addr` does not parse, binding fails, or the server fails to run.
    pub async fn start_http(self, http_addr: &str) -> Result<(), std::io::Error> {
        self.start_http_addr(parse_addr(http_addr)?).await
    }
}

/// Fails unless the `fips` build's AWS-LC backend is actually running in FIPS mode.
///
/// This checks the module, not a given `rustls::ServerConfig`; entry points that accept an
/// outside config also call `assert_fips_server_config`.
#[cfg_attr(
    not(feature = "fips"),
    allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)
)]
pub(crate) fn enforce_fips_compliance() -> Result<(), std::io::Error> {
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

/// Whether an accept error means the process is transiently out of descriptors or kernel
/// memory, rather than something wrong with one connection — the signal to back off instead
/// of spinning.
///
/// `23`/`24`/`10024` are `ENFILE`/`EMFILE`/`WSAEMFILE`; the platform-gated codes below are
/// `ENOMEM`/`ENOBUFS` or their equivalents.
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
