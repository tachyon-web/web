//! [`Server`] and the transports it runs.

mod accept;
#[cfg(any(feature = "tor", feature = "i2p"))]
mod anonymous;
mod bind;
pub(crate) mod conn;
#[cfg(feature = "http3")]
mod h3;
mod http;
#[cfg(feature = "i2p")]
pub mod i2p;
mod limits;
#[cfg(feature = "tls")]
pub(crate) mod redirect;
mod run;
pub(crate) mod security;
mod shared;
mod stall;
#[macro_use]
mod tuning;
#[cfg(feature = "tor")]
pub mod tor;

pub use bind::Bind;
pub use limits::Limits;
pub use run::Serve;
pub use security::{IpNetwork, SecurityPolicy};

use axum::Router;
use std::time::Duration;

use crate::ServerInfo;

/// Read timeout for request heads and bodies, on every transport.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Handshake timeout for TLS connections.
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

/// Publishes an Axum [`Router`] over any mix of transports.
///
/// | Method | Serves | Feature |
/// |---|---|---|
/// | [`http`](Self::http) | HTTP/1.1, plus h2c with [`SecurityPolicy::allow_h2c`] | *(always)* |
/// | `https` | HTTP/1.1 + HTTP/2 over TLS, plus HTTP/3 on the same port with `http3` | `tls` |
/// | `redirect` | `308` to HTTPS, and ACME HTTP-01 answers | `tls` |
/// | `onion` | a Tor v3 onion service | `tor` |
/// | `i2p` | an I2P eepsite (breaks `forbid(unsafe_code)`, see the `i2p` module) | `i2p` |
///
/// All of them share one set of [`Limits`], one [`SecurityPolicy`], one TLS policy, and one
/// graceful shutdown. Add transports, optionally tune [`limits`](Self::limits),
/// [`security`](Self::security) and the TLS policy, then [`serve`](Self::serve):
///
/// ```rust,no_run
/// use axum::{Router, routing::get};
/// use tachyon_web::Server;
///
/// # async fn run() -> Result<(), tachyon_web::Error> {
/// let app = Router::new().route("/", get(|| async { "hello" }));
/// Server::new(app)
///     .http("0.0.0.0:8080")
///     .serve()
///     .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap_or(()) })
///     .await
/// # }
/// ```
///
/// Handlers can read what the server has published — endpoints, `.onion`/`.b32.i2p`
/// addresses, certificates — by taking a [`ServerInfo`] argument.
pub struct Server {
    router: Router,
    limits: Limits,
    security: SecurityPolicy,
    #[cfg(feature = "tls")]
    tls_policy: crate::tls::TlsPolicy,
    transports: Vec<Transport>,
    info: ServerInfo,
}

enum Transport {
    Http(Bind),
    #[cfg(feature = "tls")]
    Https(Bind, crate::tls::Tls),
    #[cfg(feature = "tls")]
    Redirect(Bind),
    #[cfg(feature = "tor")]
    Onion(tor::OnionConfig),
    #[cfg(feature = "i2p")]
    I2p(i2p::I2pConfig),
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("limits", &self.limits)
            .field("security", &self.security)
            .field("transports", &self.transports.len())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// A server for `router` with default [`Limits`], the default [`SecurityPolicy`], and no
    /// transports yet.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self {
            router,
            limits: Limits::default(),
            security: SecurityPolicy::new(),
            #[cfg(feature = "tls")]
            tls_policy: crate::tls::TlsPolicy::new(),
            transports: Vec::new(),
            info: ServerInfo::new(),
        }
    }

    /// Serves plaintext HTTP.
    #[must_use]
    pub fn http(mut self, bind: impl Into<Bind>) -> Self {
        self.transports.push(Transport::Http(bind.into()));
        self
    }

    /// Serves HTTPS with `tls`'s certificates — and, with the `http3` feature, HTTP/3 on the
    /// same port over UDP, advertised to browsers with `Alt-Svc`.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn https(mut self, bind: impl Into<Bind>, tls: crate::tls::Tls) -> Self {
        self.transports.push(Transport::Https(bind.into(), tls));
        self
    }

    /// Serves `308` redirects to the first HTTPS endpoint, and answers ACME HTTP-01
    /// challenges — so ACME needs one, publicly reachable on port 80.
    ///
    /// Redirects target the request's host when it is allowed, the first configured name
    /// otherwise, and are refused when the server has no names; the `Host` header is never
    /// echoed unchecked. Holds at most [`Limits::redirect_share`] of the connections.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn redirect(mut self, bind: impl Into<Bind>) -> Self {
        self.transports.push(Transport::Redirect(bind.into()));
        self
    }

    /// Publishes a Tor onion service.
    #[cfg(feature = "tor")]
    #[must_use]
    pub fn onion(mut self, config: tor::OnionConfig) -> Self {
        self.transports.push(Transport::Onion(config));
        self
    }

    /// Publishes an I2P eepsite ([breaks `forbid(unsafe_code)`](crate::i2p)).
    #[cfg(feature = "i2p")]
    #[must_use]
    pub fn i2p(mut self, config: i2p::I2pConfig) -> Self {
        self.transports.push(Transport::I2p(config));
        self
    }

    /// Sets the size and concurrency ceilings.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the request-boundary security policy.
    #[must_use]
    pub fn security(mut self, policy: SecurityPolicy) -> Self {
        self.security = policy;
        self
    }

    /// Sets the crypto policy for every TLS endpoint and the keys their certificates load
    /// with. A `fips` or `cnsa` build cannot express a non-compliant one.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_policy(mut self, policy: crate::tls::TlsPolicy) -> Self {
        self.tls_policy = policy;
        self
    }

    /// A handle onto what this server publishes once running — the same one handlers receive,
    /// for code outside a handler, such as a task reporting the `.onion` address.
    #[must_use]
    pub fn info(&self) -> ServerInfo {
        self.info.clone()
    }

    /// Starts every transport and serves until one fails or the
    /// [graceful shutdown](Serve::with_graceful_shutdown) signal fires.
    ///
    /// Nothing is bound until the returned future is awaited. The configuration is checked
    /// first, and every clearnet listener is bound and its certificates loaded before any
    /// request is served, so a mistake fails the start instead of a later request. Onion and
    /// I2P certificates load once their address is published.
    #[must_use = "a server does nothing until `.serve()` is awaited"]
    pub fn serve(self) -> Serve {
        Serve::new(self)
    }
}

/// The ALPN list a TLS endpoint offers, in preference order: only protocols this build serves.
#[cfg(feature = "tls")]
pub(crate) fn alpn(h3: bool) -> Vec<Vec<u8>> {
    let mut protocols = Vec::with_capacity(3);
    if h3 {
        protocols.push(b"h3".to_vec());
    }
    #[cfg(feature = "http2")]
    protocols.push(b"h2".to_vec());
    #[cfg(feature = "http1")]
    protocols.push(b"http/1.1".to_vec());
    protocols
}

/// Fails unless the `fips` build's AWS-LC backend is actually running in FIPS mode.
#[cfg_attr(
    not(feature = "fips"),
    allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)
)]
fn enforce_fips_compliance() -> Result<(), crate::Error> {
    #[cfg(feature = "fips")]
    if let Err(e) = aws_lc_rs::try_fips_mode() {
        return Err(crate::Error::config(format!(
            "FIPS compliance check failed: {e}. Cryptographic backend is not in FIPS mode"
        )));
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
