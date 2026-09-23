//! The [`Server`] engine: wraps an Axum [`Router`] and dispatches incoming streams for
//! every supported transport.
//!
//! # Protocol support
//!
//! | Method | Protocol | Feature flag |
//! |---|---|---|
//! | [`serve_http`] | HTTP/1.1 plain TCP (+ HTTP/2 cleartext "h2c" with `http2` and `SecurityPolicy::allow_h2c`) | *(always)* |
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
#[macro_use]
mod tuning;
#[cfg(feature = "tor")]
pub mod tor;

pub use multi::MultiServer;
pub use security::{IpNetwork, SecurityPolicy};
#[cfg(feature = "tls")]
pub use tls_config::{HttpsServer, RustlsConfig, bind_rustls};

use axum::Router;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

/// A server-owned sidecar task that cannot outlive the serving future that spawned it.
#[derive(Debug)]
pub(crate) struct BackgroundTask(tokio::task::JoinHandle<()>);

impl BackgroundTask {
    pub(crate) const fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self(task)
    }
}

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

use axum::body::Body;
use hyper::{Request, Response};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;

use bind::bind_and_serve;
#[cfg(feature = "http3")]
use h3::spawn_h3_beside;
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
use redirect::RedirectInfo;
use redirect::parse_addr;
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt", feature = "http3"))]
pub(crate) use tls_config::alpn_protocols;
#[cfg(feature = "fips")]
use tls_config::assert_fips_server_config;
#[cfg(any(feature = "lets-encrypt", feature = "cert-gen"))]
use tls_config::tls_config_builder;

/// Default read timeout for both plaintext and TLS connections.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default handshake timeout for TLS connections.
#[cfg(feature = "tls")]
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a single write may make no progress before the connection (or, on HTTP/3, the
/// stream) is abandoned.
///
/// Deliberately per-write rather than a budget for the whole response: a slow client that is
/// still consuming keeps resetting it, so long downloads and open SSE streams are unaffected,
/// while a peer that has simply stopped reading — holding its receive window shut to pin the
/// connection and its buffers — is dropped. See `stall::WriteDeadline` for TCP/Tor/I2P.
pub(crate) const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The [`ConnectInfo`](axum::extract::ConnectInfo) reported where the transport has no peer
/// address (Tor/I2P both exist specifically to hide it).
///
/// Every such request reports the *same* `0.0.0.0:0`, so per-IP logic keyed on it degrades in
/// two ways worth knowing about before relying on it: any per-peer rate limiter collapses to a
/// single shared bucket for all anonymous traffic, and a "trust anything that isn't a global
/// address" check will treat every one of these requests as trusted, since `0.0.0.0` is not a
/// global address — a real hazard in a process that also serves a clearnet listener. This
/// crate's own [`SecurityPolicy`] never consults it: those transports pass no peer at all.
pub(crate) const NO_PEER_ADDR: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Default for [`Server::max_connections`].
///
/// *Tachyon extension: no `axum` equivalent.*
pub const DEFAULT_MAX_CONNECTIONS: usize = 4_096;
/// Default for [`Server::redirect_connection_share`] — the percentage of
/// [`DEFAULT_MAX_CONNECTIONS`] the plaintext redirect listener may occupy.
///
/// *Tachyon extension: no `axum` equivalent.*
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
pub const DEFAULT_REDIRECT_CONNECTION_SHARE: u8 = 15;
/// Default for [`Server::max_h3_concurrent_streams`] — see that field for how to size it.
///
/// *Tachyon extension: no `axum` equivalent.*
#[cfg(feature = "http3")]
pub const DEFAULT_MAX_H3_CONCURRENT_STREAMS: usize = 32;
/// How long [`Server::serve_all_acme`] waits for the first certificate to be
/// cached or provisioned before starting the TLS listener regardless.
#[cfg(feature = "lets-encrypt")]
const FIRST_CERT_TIMEOUT: Duration = Duration::from_mins(1);

/// Main server configuration and runner.
///
/// Wraps an Axum [`Router`] and provides multiple `serve_*` methods for different
/// transport protocols. The server is cheaply cloneable via `Arc` internally.
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
#[derive(Debug)]
pub struct Server<S> {
    pub(crate) router: Router,
    pub(crate) state: PhantomData<fn() -> S>,
    /// Maximum permitted request body size in bytes (default: 2 MiB, matching
    /// Axum's `DefaultBodyLimit` default).
    pub max_body_size: usize,
    /// Maximum number of concurrent active connections across all transports — read it
    /// back with [`max_connections`](Self::max_connections) and set it with the builder
    /// method of the same name.
    ///
    /// Private because the value alone enforces nothing: the semaphore beside it is what
    /// the accept loops actually acquire from, and the two are only kept in step by the
    /// builder. A directly assignable field would let a caller "lower" a limit that stayed
    /// exactly where it was.
    ///
    /// Clones of this server share one semaphore, so adding HTTP, HTTPS, HTTP/3, Tor, or I2P
    /// listeners does not multiply the process-wide ceiling.
    ///
    /// One transport draws on a bounded slice of this rather than all of it: the plaintext
    /// port-80 redirect listener, capped by
    /// [`redirect_connection_share`](Self::redirect_connection_share). It still takes a permit
    /// from this pool per connection, so the ceiling here is unchanged.
    ///
    /// Default: 4,096.
    pub(crate) max_connections: usize,
    pub(super) connection_limit: accept::ConnectionLimit,
    /// Maximum number of application handlers executing concurrently across all transports —
    /// private for the same reason as [`max_connections`](Self#structfield.max_connections).
    pub(crate) max_active_requests: usize,
    pub(crate) request_limit: Arc<tokio::sync::Semaphore>,
    pub(crate) security_policy: SecurityPolicy,
    /// Percentage of [`max_connections`](Self::max_connections) the plaintext redirect
    /// listener may hold — private for the same reason as
    /// [`max_connections`](Self#structfield.max_connections), and read through
    /// [`redirect_connection_permits`](Self::redirect_connection_permits).
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    pub(crate) redirect_connection_share: u8,
    /// Maximum number of TLS handshakes executing concurrently — private for the same reason
    /// as [`max_connections`](Self#structfield.max_connections).
    #[cfg(feature = "tls")]
    pub(crate) max_tls_handshakes: usize,
    #[cfg(feature = "tls")]
    pub(crate) tls_handshake_limit: Arc<tokio::sync::Semaphore>,
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
    /// `max_h3_concurrent_streams × max_body_size`, e.g. 32 × 2 MiB = 64 MiB at the
    /// defaults, before `max_connections` multiplies it across connections (4,096 × 64 MiB
    /// is well past any real machine, so size at least one of the three for the memory you
    /// actually have). Size this and `max_body_size` together if H3 traffic is expected.
    ///
    /// Default: [`DEFAULT_MAX_H3_CONCURRENT_STREAMS`] (32).
    #[cfg(feature = "http3")]
    pub max_h3_concurrent_streams: usize,
    /// Crypto/TLS policy shared across every listener this `Server` runs — see
    /// [`Server::tls_policy`]. `None` means each listener falls back to
    /// [`TlsPolicy::new`](crate::tls::TlsPolicy::new).
    #[cfg(feature = "tls")]
    pub(crate) tls_policy: Option<crate::tls::TlsPolicy>,
    #[cfg(feature = "cnsa")]
    pub(crate) cnsa_identity_verified: bool,
}

impl<S> Clone for Server<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            router: self.router.clone(),
            state: PhantomData,
            max_body_size: self.max_body_size,
            max_connections: self.max_connections,
            connection_limit: self.connection_limit.clone(),
            max_active_requests: self.max_active_requests,
            request_limit: self.request_limit.clone(),
            security_policy: self.security_policy.clone(),
            #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
            redirect_connection_share: self.redirect_connection_share,
            #[cfg(feature = "tls")]
            max_tls_handshakes: self.max_tls_handshakes,
            #[cfg(feature = "tls")]
            tls_handshake_limit: self.tls_handshake_limit.clone(),
            #[cfg(feature = "http3")]
            max_h3_concurrent_streams: self.max_h3_concurrent_streams,
            #[cfg(feature = "tls")]
            tls_policy: self.tls_policy.clone(),
            #[cfg(feature = "cnsa")]
            cnsa_identity_verified: self.cnsa_identity_verified,
        }
    }
}

impl Server<()> {
    /// Creates a new `Server` with default settings and the given router.
    ///
    /// Defaults: 2 MiB bodies, [`DEFAULT_MAX_CONNECTIONS`] connections, 1,024 concurrent
    /// handlers, and [`SecurityPolicy::new`]'s fail-safe request policy.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self {
            router,
            state: PhantomData,
            max_body_size: 2 * 1024 * 1024, // 2 MiB (matches Axum's `DefaultBodyLimit` default)
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connection_limit: accept::ConnectionLimit::new(DEFAULT_MAX_CONNECTIONS),
            max_active_requests: 1_024,
            request_limit: Arc::new(tokio::sync::Semaphore::new(1_024)),
            security_policy: SecurityPolicy::new(),
            #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
            redirect_connection_share: DEFAULT_REDIRECT_CONNECTION_SHARE,
            #[cfg(feature = "tls")]
            max_tls_handshakes: 1024,
            #[cfg(feature = "tls")]
            tls_handshake_limit: Arc::new(tokio::sync::Semaphore::new(1024)),
            #[cfg(feature = "http3")]
            max_h3_concurrent_streams: DEFAULT_MAX_H3_CONCURRENT_STREAMS,
            #[cfg(feature = "tls")]
            tls_policy: None,
            #[cfg(feature = "cnsa")]
            cnsa_identity_verified: false,
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
    ///
    /// `peer` is `None` on an anonymity transport — see [`NO_PEER_ADDR`].
    pub(crate) async fn dispatch(
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
    pub(crate) fn reject(
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
    pub(crate) async fn route(
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
        self.max_body_size = size;
        self
    }

    /// Overrides the maximum number of concurrent connections shared by all transports. Values
    /// below one are clamped to one so a configuration mistake cannot permanently stop
    /// acceptance.
    #[must_use]
    pub fn max_connections(mut self, limit: usize) -> Self {
        self.max_connections = if limit == 0 { 1 } else { limit };
        self.connection_limit = accept::ConnectionLimit::new(self.max_connections);
        self
    }

    /// Limits application handlers executing concurrently across every transport. Excess
    /// requests are shed immediately with `503 Service Unavailable` instead of being queued.
    #[must_use]
    pub fn max_active_requests(mut self, limit: usize) -> Self {
        self.max_active_requests = if limit == 0 { 1 } else { limit };
        self.request_limit = Arc::new(tokio::sync::Semaphore::new(self.max_active_requests));
        self
    }

    /// The effective connection ceiling shared by every transport — see
    /// [`max_connections`](Self::max_connections).
    #[must_use]
    pub const fn connection_limit(&self) -> usize {
        self.max_connections
    }

    /// The effective concurrent-handler ceiling — see
    /// [`max_active_requests`](Self::max_active_requests).
    #[must_use]
    pub const fn active_request_limit(&self) -> usize {
        self.max_active_requests
    }

    /// Caps the plaintext HTTP→HTTPS redirect listener at `percent` of
    /// [`max_connections`](Self::max_connections), so a flood of cheap redirect connections
    /// cannot take the permits the TLS listener needs.
    ///
    /// That listener is bound to port 80 and reachable by anyone, but it never reaches an
    /// application handler — it answers ACME HTTP-01 challenges and `308`s everything else. It
    /// therefore has no business competing with real traffic for the whole pool, which is what
    /// it used to do: both listeners drew on one semaphore, so enough port-80 connections
    /// starved port 443 outright.
    ///
    /// A redirect connection still holds a permit from the shared pool as well, so this caps
    /// that listener's slice rather than granting a second budget on top of
    /// [`max_connections`](Self::max_connections) — the process-wide ceiling is unchanged.
    ///
    /// Values above 100 are clamped to 100, and the resulting budget is never less than one
    /// permit, so neither a percentage of zero nor a very small pool can stop redirects (and
    /// with them ACME renewals) entirely. Order-independent: the share is resolved against
    /// whatever [`max_connections`](Self::max_connections) ends up being.
    ///
    /// Default: [`DEFAULT_REDIRECT_CONNECTION_SHARE`] (15%).
    ///
    /// # Example
    /// ```rust,no_run
    /// # use axum::Router;
    /// # use tachyon_web::Server;
    /// # let router = Router::new();
    /// // 4,096 connections overall, of which at most 205 may be port-80 redirects.
    /// let server = Server::new(router).max_connections(4_096).redirect_connection_share(5);
    /// ```
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    #[must_use]
    pub const fn redirect_connection_share(mut self, percent: u8) -> Self {
        self.redirect_connection_share = if percent > 100 { 100 } else { percent };
        self
    }

    /// The configured redirect share, as a percentage — see
    /// [`redirect_connection_share`](Self::redirect_connection_share).
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    #[must_use]
    pub const fn redirect_connection_share_percent(&self) -> u8 {
        self.redirect_connection_share
    }

    /// The redirect listener's slice of the pool, in permits.
    ///
    /// Rounded down, then floored at one: a share that rounded to zero would leave the port-80
    /// listener unable to accept anything, taking ACME issuance and renewal down with it.
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    #[must_use]
    pub fn redirect_connection_permits(&self) -> usize {
        let budget = self
            .max_connections
            .saturating_mul(usize::from(self.redirect_connection_share))
            .checked_div(100)
            .unwrap_or(0);
        budget.max(1)
    }

    /// The effective concurrent-TLS-handshake ceiling — see
    /// [`max_tls_handshakes`](Self::max_tls_handshakes).
    #[cfg(feature = "tls")]
    #[must_use]
    pub const fn tls_handshake_limit(&self) -> usize {
        self.max_tls_handshakes
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
    /// A profile's concurrency ceilings only ever *lower* what is already configured. Applying
    /// one after a deliberately tighter `max_connections`/`max_active_requests` would otherwise
    /// raise that limit back up, which is the opposite of what selecting a hardening preset
    /// asks for.
    #[must_use]
    pub fn deployment_profile(mut self, profile: DeploymentProfile) -> Self {
        match profile {
            DeploymentProfile::Hardened => {}
            DeploymentProfile::ExtremePrivacy => {
                let (connections, requests) = (
                    self.max_connections.min(2_048),
                    self.max_active_requests.min(512),
                );
                self = self
                    .max_connections(connections)
                    .max_active_requests(requests);
                #[cfg(feature = "http3")]
                {
                    let streams = self.max_h3_concurrent_streams.min(16);
                    self = self.max_h3_concurrent_streams(streams);
                }
                #[cfg(feature = "tls")]
                {
                    self.tls_policy = Some(
                        self.tls_policy
                            .take()
                            .unwrap_or_default()
                            .disable_resumption(true),
                    );
                }
            }
        }
        self
    }

    /// Limits concurrent TLS handshakes. Connections beyond the limit are dropped before
    /// performing asymmetric cryptographic work.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn max_tls_handshakes(mut self, limit: usize) -> Self {
        self.max_tls_handshakes = if limit == 0 { 1 } else { limit };
        self.tls_handshake_limit = Arc::new(tokio::sync::Semaphore::new(self.max_tls_handshakes));
        self
    }

    /// Overrides the maximum number of HTTP/3 streams handled concurrently **per QUIC
    /// connection** (default: [`DEFAULT_MAX_H3_CONCURRENT_STREAMS`], 32) — see
    /// [`Server::max_h3_concurrent_streams`](Self#structfield.max_h3_concurrent_streams) for how
    /// this differs from [`max_connections`](Self::max_connections).
    ///
    /// Once a connection is at its limit, additional streams are refused. Values below one are
    /// clamped to one so a configuration mistake cannot permanently stop stream processing.
    #[cfg(feature = "http3")]
    #[must_use]
    pub const fn max_h3_concurrent_streams(mut self, limit: usize) -> Self {
        self.max_h3_concurrent_streams = if limit == 0 { 1 } else { limit };
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
    /// onto the FIPS 140-3 Level 1 approved-mode software provider (see
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
    /// feature enabled, every reachable `TlsPolicy` value already uses the FIPS 140-3 Level 1
    /// software module in approved mode by
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

    /// Applies this server's [`TlsPolicy`](crate::tls::TlsPolicy) to a `rustls::ServerConfig`
    /// this crate did not build, and freezes it.
    ///
    /// Every entry point that takes an outside config goes through here, so a policy-level
    /// setting — notably the resumption lockdown
    /// [`DeploymentProfile::ExtremePrivacy`] turns on — cannot reach some listeners and quietly
    /// miss others. It previously did: only `serve_https_config` applied the policy, while
    /// `start_https_with_config*` and `start_https_and_h3_with_config` served the config as
    /// handed to them.
    #[cfg(feature = "tls")]
    pub(crate) fn finalize_tls_config(
        &self,
        mut config: rustls::ServerConfig,
    ) -> Arc<rustls::ServerConfig> {
        if let Some(policy) = &self.tls_policy {
            policy.apply_to_server_config(&mut config);
        }
        Arc::new(config)
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
        bind_and_serve(self, addr, None, |server, listener| async move {
            server.serve_http(listener).await
        })
        .await
    }

    /// Starts a pure plaintext HTTP server on `http_addr` (e.g. `"0.0.0.0:80"`).
    ///
    /// # Errors
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
        let acceptor = TlsAcceptor::from(self.finalize_tls_config(config));
        bind_and_serve(self, addr, None, move |server, listener| async move {
            server.serve_https(listener, acceptor).await
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

        config.alpn_protocols = alpn_protocols(true);
        // Ordered as in `start_all_inner`/`serve_all_acme`: apply the policy, then assert the
        // config that will actually be served.
        let config = self.finalize_tls_config(config);
        #[cfg(feature = "fips")]
        assert_fips_server_config(&config)?;

        let addr = parse_addr(tls_addr)?;
        let tls_acceptor = TlsAcceptor::from(config.clone());
        bind_and_serve(self, addr, None, move |server, listener| async move {
            let _h3_task = spawn_h3_beside(&server, config, &listener)?;
            server.serve_https(listener, tls_acceptor).await
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
    /// use axum::{Router, routing::get};
    /// use tachyon_web::Server;
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
        mut self,
        tls_addr: &str,
        cleartext_addr: &str,
        domains: Vec<String>,
        email: String,
        cache_dir: impl Into<std::path::PathBuf>,
        staging: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::tls::acme::AcmeManager;
        enforce_fips_compliance()?;
        if domains.is_empty() {
            // An ACME order needs at least one identifier (RFC 8555 §7.4), and the port-80
            // listener below would otherwise come up with an allow-list it can never match.
            return Err("serve_all_acme requires at least one domain".into());
        }

        // Built with this server's own policy so the ACME-issued certificate's signing key is
        // loaded through the same crypto provider the `ServerConfig` below negotiates with —
        // under `fips` those are distinct modules.
        let allowed_hosts: Arc<[String]> = Arc::from(domains.clone());
        self.security_policy = self
            .security_policy
            .clone()
            .with_default_allowed_hosts(allowed_hosts.clone());
        let policy = self.effective_tls_policy();
        let acme = AcmeManager::with_policy(cache_dir, domains, email, staging, &policy);
        acme.validate_cache()?;
        let resolver = acme.resolver();

        let addr = parse_addr(tls_addr)?;
        let redirect_addr = parse_addr(cleartext_addr)?;
        // Bind before starting either sidecar so a TLS bind failure has no background work to
        // unwind.
        let listener = TcpListener::bind(addr).await?;

        // The HTTP-01 responder has to be listening *before* the ACME loop places its first
        // order: that loop provisions immediately when the cache is empty, and the challenge it
        // publishes is answered on this listener. Binding it afterwards meant every first-run
        // issuance failed validation, waited out the 5-minute backoff, and burned one of the
        // CA's per-hour failed-validation attempts before the retry could succeed. Binding here
        // also fails fast if the cleartext port is unavailable, rather than after an order.
        let _redirect_task = bind::spawn_redirect_listener(RedirectInfo {
            addr: redirect_addr,
            https_port: addr.port(),
            allowed_hosts: Some(allowed_hosts),
            limit: self
                .connection_limit
                .with_share(self.redirect_connection_permits()),
            policy: self.security_policy.clone(),
        })
        .await?;

        // Start the background renewal loop now that its challenges can be answered.
        let _acme_task = acme.start_guarded();

        // Give the renewal loop a bounded window to load a cached cert or
        // provision a fresh one before the TLS listener starts accepting —
        // otherwise every connection that lands before the first cert is
        // ready fails its handshake. If provisioning is still in flight after
        // the timeout (e.g. a slow ACME order), proceed anyway rather than
        // hang startup forever; those early connections will fail until the
        // cert lands, same as today, but the common case (cached or
        // fast-issued cert) now actually gets served from the start.
        let first_cert = async {
            while !resolver.has_certificate() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        if tokio::time::timeout(FIRST_CERT_TIMEOUT, first_cert)
            .await
            .is_err()
        {
            crate::telemetry_warn!(
                "[acme] No certificate ready after {:?}; starting TLS listener anyway — \
                 connections will fail until provisioning completes",
                FIRST_CERT_TIMEOUT
            );
        }

        // Build the TLS config backed by the ACME hot-swap resolver, sharing the same
        // crypto/TLS policy as the onion/i2p listeners (see `Server::tls_policy`).
        let mut tls_config = tls_config_builder(&policy)?.with_cert_resolver(resolver);

        tls_config.alpn_protocols = alpn_protocols(cfg!(feature = "http3"));
        policy.apply_to_server_config(&mut tls_config);
        // Defence in depth. `TlsPolicy` is meant to be incapable of producing a
        // non-approved config under `fips`, so this should never fire — which is exactly why
        // it is worth asserting rather than assumed: it turns "we believe the policy is
        // sound" into "the config actually offered is checked", and it is the only thing
        // that would catch a rustls upgrade changing what counts as approved.
        #[cfg(feature = "fips")]
        assert_fips_server_config(&tls_config)?;

        let tls_config = Arc::new(tls_config);
        let tls_acceptor = TlsAcceptor::from(tls_config.clone());

        #[cfg(feature = "http3")]
        let _h3_task = spawn_h3_beside(&self, tls_config, &listener)?;
        self.serve_https(listener, tls_acceptor).await?;

        Ok(())
    }

    /// Internal: shared setup logic for `start_all`.
    ///
    /// # Errors
    /// Returns an error if address binding, TLS configuration, or certificate parsing fails.
    #[cfg(feature = "cert-gen")]
    #[allow(clippy::too_many_lines)]
    async fn start_all_inner(
        mut self,
        tls_addr: &str,
        cleartext_addr: Option<&str>,
        cert_pem: String,
        key_pem: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        enforce_fips_compliance()?;
        let addr = parse_addr(tls_addr)?;

        let cert_chain: Vec<CertificateDer<'static>> = crate::tls::pem::certs(cert_pem.as_bytes());
        let mut allowed_hosts = cert_chain
            .first()
            .map(crate::tls::certificate_dns_names)
            .unwrap_or_default();
        if !addr.ip().is_unspecified() {
            allowed_hosts.push(addr.ip().to_string());
        }
        let allowed_hosts: Arc<[String]> = allowed_hosts.into();
        self.security_policy = self
            .security_policy
            .clone()
            .with_default_allowed_hosts(allowed_hosts.clone());

        let key_der: PrivateKeyDer<'static> = crate::tls::pem::private_key(key_pem.as_bytes())
            .map_err(|e| crate::tls::pem::key_io_error(&e))?;

        #[cfg(feature = "cnsa")]
        tls_config::assert_cnsa_identity(&cert_chain, &key_der)?;
        #[cfg(feature = "cnsa")]
        {
            self.cnsa_identity_verified = true;
        }

        // Shares the same crypto/TLS policy as the onion/i2p listeners — see
        // `Server::tls_policy`. The default is TLS 1.3 only; pass a custom `TlsPolicy` to
        // narrow the suites or groups further, or enable `tls12-legacy` to add a TLS 1.2
        // fallback.
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
        policy.apply_to_server_config(&mut tls_config);
        // Defence in depth. `TlsPolicy` is meant to be incapable of producing a
        // non-approved config under `fips`, so this should never fire — which is exactly why
        // it is worth asserting rather than assumed: it turns "we believe the policy is
        // sound" into "the config actually offered is checked", and it is the only thing
        // that would catch a rustls upgrade changing what counts as approved.
        #[cfg(feature = "fips")]
        assert_fips_server_config(&tls_config)?;

        let tls_config = Arc::new(tls_config);
        let tls_acceptor = TlsAcceptor::from(tls_config.clone());

        let redirect_info = cleartext_addr
            .map(|cleartext_addr| {
                parse_addr(cleartext_addr).map(|cleartext| RedirectInfo {
                    addr: cleartext,
                    https_port: addr.port(),
                    allowed_hosts: Some(allowed_hosts.clone()),
                    limit: self
                        .connection_limit
                        .with_share(self.redirect_connection_permits()),
                    policy: self.security_policy.clone(),
                })
            })
            .transpose()?;

        // Start the HTTPS listener (blocks this task), with HTTP/3 beside it when enabled.
        bind_and_serve(
            self,
            addr,
            redirect_info,
            move |server, listener| async move {
                #[cfg(feature = "http3")]
                let _h3_task = spawn_h3_beside(&server, tls_config, &listener)?;
                server.serve_https(listener, tls_acceptor).await
            },
        )
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
