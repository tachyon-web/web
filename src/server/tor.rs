//! Native Tor `.onion` hidden-service support (see the `tor` feature).
//!
//! Wraps [`arti-client`](https://docs.rs/arti-client) and
//! [`tor-hsservice`](https://docs.rs/tor-hsservice) so a Tachyon [`Server`] can be published
//! directly as a v3 Tor hidden service — no external `tor` daemon, no reverse proxy — with the
//! same `serve_*` ergonomics as [`Server::serve_https`](crate::server::Server::serve_https).
//!
//! Two entry points are available:
//!
//! - [`Server::serve_tor`] / [`Server::serve_tor_with_client`] — the simplest possible onion
//!   service: plaintext HTTP on virtual port 80, nothing else configurable. Always available
//!   under the `tor` feature alone — no TLS stack required.
//! - [`Server::serve_onion`] / [`Server::serve_onion_with_client`], driven by an [`OnionConfig`] —
//!   adds custom state/cache directories, a vanguards toggle, and an `on_ready` hook for reading
//!   the published `.onion` address, all available under `tor` alone. Native HTTPS (virtual port
//!   443, terminated with the *same* `rustls::ServerConfig` type used by
//!   [`Server::serve_https_config`](crate::server::Server::serve_https_config), so a
//!   FIPS-constrained crypto provider or custom cert chain can be shared between the clearnet and
//!   onion listeners) is additionally available when the `tls` feature is enabled alongside
//!   `tor` — the self-signed-certificate convenience ([`OnionConfig::self_signed_tls`], the
//!   default whenever it's available) further requires `cert-gen`.
//!
//! # Example
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//!
//! async fn hello() -> &'static str { "Hello from an onion service!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     // Publishes the service, prints its `.onion` address once reachable, then
//!     // blocks serving requests arriving over Tor rendezvous circuits.
//!     Server::new(app).serve_tor("my-hidden-service").await?;
//!     Ok(())
//! }
//! ```
//!
//! # HTTPS, custom directories, and vanguards
//!
//! HTTPS support (this example) requires enabling `tls` (and `cert-gen` for the self-signed
//! certificate shown here) alongside `tor` — see the [module docs](self) above.
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//! use tachyon_web::server::tor::OnionConfig;
//!
//! async fn hello() -> &'static str { "Hello, secure onion world!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     let config = OnionConfig::new("my-hidden-service")
//!         .state_dir("/var/lib/tachyon/tor/state")
//!         .cache_dir("/var/lib/tachyon/tor/cache")
//!         // Default (with `cert-gen` enabled) is a self-signed cert for the onion address;
//!         // pass your own instead:
//!         // .tls_config(my_rustls_server_config)
//!         .redirect_http(false) // dual-stack by default: plaintext AND TLS both work
//!         .on_ready(|addr| tracing::info!("reachable at https://{addr}"));
//!
//!     Server::new(app).serve_onion(config).await?;
//!     Ok(())
//! }
//! ```
//!
//! Persistent onion service keys and Arti's own state/cache are stored under Arti's default
//! state directory unless overridden via [`OnionConfig::state_dir`]/[`OnionConfig::cache_dir`];
//! reusing the same `nickname` (and directories) across restarts keeps the same `.onion` address.
//! Pass an already-bootstrapped client (e.g. one configured with custom bridges) via
//! [`Server::serve_onion_with_client`]/[`Server::serve_tor_with_client`] instead of bootstrapping
//! a fresh one per service.
//!
//! # Vanguards
//!
//! [Vanguards](https://blog.torproject.org/vanguards-onion-services/) harden onion services
//! against guard-discovery attacks and are enabled by default (arti's own "lite" mode).
//! [`OnionConfig::vanguards`] overrides this at runtime, e.g. `OnionConfig::new(nickname).vanguards(false)`.

#[cfg(feature = "tls")]
use crate::http::response::Body;
use crate::server::Server;
use crate::server::conn::{NO_PEER_ADDR as ONION_PEER_ADDR, serve_connection};
use crate::server::http::hyper_handler;
use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use futures_util::StreamExt as _;
#[cfg(feature = "tls")]
use hyper::{Request, Response};
use safelog::DisplayRedacted as _;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tor_cell::relaycell::msg::Connected;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::Runtime;

/// The virtual port plaintext HTTP clients connect to — mirrors how a clearnet browser assumes
/// port 80 for a bare `http://` URL, regardless of what port the service actually listens on
/// inside the Tor network.
const ONION_HTTP_PORT: u16 = 80;
/// The virtual port HTTPS clients connect to, matching the clearnet `https://` convention.
/// Only meaningful when the `tls` feature is enabled.
#[cfg(feature = "tls")]
const ONION_HTTPS_PORT: u16 = 443;

/// How (or whether) an onion service published via [`OnionConfig`] terminates TLS.
#[derive(Clone)]
enum OnionTls {
    /// Plaintext only — no virtual port 443 listener.
    None,
    /// TLS on virtual port 443 using an ephemeral self-signed certificate, generated for the
    /// onion address once it's known. This is the default whenever `cert-gen` is enabled.
    /// Requires the `cert-gen` feature.
    #[cfg(feature = "cert-gen")]
    SelfSigned,
    /// TLS on virtual port 443 using a caller-supplied config — e.g. the same
    /// `rustls::ServerConfig` used for a clearnet [`Server::serve_https_config`] listener, so a
    /// custom crypto provider or FIPS constraints carry over unchanged. Requires the `tls`
    /// feature.
    #[cfg(feature = "tls")]
    Custom(Arc<rustls::ServerConfig>),
}

impl std::fmt::Debug for OnionTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            #[cfg(feature = "cert-gen")]
            Self::SelfSigned => f.write_str("SelfSigned"),
            #[cfg(feature = "tls")]
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

/// Callback invoked with the published `.onion` address — see [`OnionConfig::on_ready`].
type OnReadyHook = Box<dyn FnOnce(&str) + Send>;

/// Configuration for publishing a Tor `.onion` hidden service via
/// [`Server::serve_onion`]/[`Server::serve_onion_with_client`].
///
/// See the [module docs](self) for a full example.
pub struct OnionConfig {
    nickname: String,
    state_dir: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
    tls: OnionTls,
    redirect_http: bool,
    vanguards: bool,
    on_ready: Option<OnReadyHook>,
}

impl std::fmt::Debug for OnionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionConfig")
            .field("nickname", &self.nickname)
            .field("state_dir", &self.state_dir)
            .field("cache_dir", &self.cache_dir)
            .field("tls", &self.tls)
            .field("redirect_http", &self.redirect_http)
            .field("vanguards", &self.vanguards)
            .finish_non_exhaustive()
    }
}

impl OnionConfig {
    /// Creates a new configuration for a service published under `nickname`.
    ///
    /// Defaults: TLS enabled with a self-signed certificate if the `cert-gen` feature is
    /// enabled (virtual port 443, alongside plaintext on virtual port 80 — see
    /// [`redirect_http`](Self::redirect_http)); plaintext-only otherwise (or always, if the
    /// `tls` feature isn't enabled at all — see the [module docs](self)). No forced
    /// HTTP→HTTPS redirect, and vanguards on — see [`vanguards`](Self::vanguards) to change it.
    /// `nickname` is validated (as an [`HsNickname`]) when the service is actually launched.
    #[must_use]
    pub fn new(nickname: impl Into<String>) -> Self {
        Self {
            nickname: nickname.into(),
            state_dir: None,
            cache_dir: None,
            #[cfg(feature = "cert-gen")]
            tls: OnionTls::SelfSigned,
            #[cfg(not(feature = "cert-gen"))]
            tls: OnionTls::None,
            redirect_http: false,
            vanguards: true,
            on_ready: None,
        }
    }

    /// Overrides the directory Arti uses for persistent state — including this service's onion
    /// keys. Reusing the same directory (and `nickname`) across restarts keeps the same `.onion`
    /// address. Defaults to Arti's own platform-specific state directory.
    #[must_use]
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Overrides the directory Arti uses for cached network directory information. Defaults to
    /// Arti's own platform-specific cache directory.
    #[must_use]
    pub fn cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }

    /// Disables HTTPS entirely — only plaintext HTTP on virtual port 80 is served, matching
    /// [`Server::serve_tor`].
    // Only `const`-eligible when neither `Custom`/`SelfSigned` variant exists (their non-trivial
    // `Drop` glue — an `Arc<rustls::ServerConfig>` — can't run in a `const fn`), i.e. only
    // without `tls`/`cert-gen` — not worth splitting this method's signature across features
    // for.
    #[cfg_attr(not(feature = "tls"), allow(clippy::missing_const_for_fn))]
    #[must_use]
    pub fn no_tls(mut self) -> Self {
        self.tls = OnionTls::None;
        self
    }

    /// Re-enables HTTPS with a freshly generated self-signed certificate (the default when this
    /// feature is available), after a prior [`no_tls`](Self::no_tls) or
    /// [`tls_config`](Self::tls_config) call. Requires the `cert-gen` feature.
    #[cfg(feature = "cert-gen")]
    #[must_use]
    pub fn self_signed_tls(mut self) -> Self {
        self.tls = OnionTls::SelfSigned;
        self
    }

    /// Enables HTTPS using a caller-supplied `rustls::ServerConfig` instead of the default
    /// self-signed certificate — for example, the exact same config passed to
    /// [`Server::serve_https_config`](crate::server::Server::serve_https_config) for the clearnet
    /// listener, so a custom crypto provider, FIPS constraints, or a real cert chain carry over
    /// unchanged. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_config(mut self, config: rustls::ServerConfig) -> Self {
        self.tls = OnionTls::Custom(Arc::new(config));
        self
    }

    /// Controls what happens to plaintext HTTP (virtual port 80) requests when TLS is enabled.
    ///
    /// `false` (the default): plaintext and TLS are both served — a dual-stack onion service,
    /// same as browsing a clearnet site over either `http://` or `https://`. `true`: port 80
    /// instead issues a `308 Permanent Redirect` to the equivalent `https://` URL, forcing all
    /// traffic onto TLS. Has no effect when TLS is disabled ([`no_tls`](Self::no_tls)) or the
    /// `tls` feature isn't enabled.
    #[must_use]
    pub const fn redirect_http(mut self, enable: bool) -> Self {
        self.redirect_http = enable;
        self
    }

    /// Controls whether [vanguards](https://blog.torproject.org/vanguards-onion-services/) are
    /// used for this service. Defaults to `true`.
    #[must_use]
    pub const fn vanguards(mut self, enabled: bool) -> Self {
        self.vanguards = enabled;
        self
    }

    /// Registers a callback invoked exactly once — with the published `.onion` address (no
    /// scheme, e.g. `"abcd...xyz.onion"`) — as soon as the service is fully reachable, just
    /// before requests start being served. This is the only way to observe the address
    /// programmatically, since [`serve_onion`](Server::serve_onion) blocks for the lifetime of
    /// the service; the address is also always logged via `tracing` at `info` level.
    #[must_use]
    pub fn on_ready(mut self, f: impl FnOnce(&str) + Send + 'static) -> Self {
        self.on_ready = Some(Box::new(f));
        self
    }

    /// The nickname this service will be published under.
    #[must_use]
    pub fn nickname(&self) -> &str {
        &self.nickname
    }

    /// Whether HTTPS is enabled (via the default self-signed cert or a custom
    /// [`tls_config`](Self::tls_config)) — `false` after [`no_tls`](Self::no_tls), and always
    /// `false` when the `tls` feature isn't enabled.
    #[must_use]
    pub const fn tls_enabled(&self) -> bool {
        !matches!(self.tls, OnionTls::None)
    }

    /// Whether plaintext HTTP is forced to redirect to HTTPS — see
    /// [`redirect_http`](Self::redirect_http).
    #[must_use]
    pub const fn redirect_http_enabled(&self) -> bool {
        self.redirect_http
    }

    /// Whether vanguards will be requested for this service — see
    /// [`vanguards`](Self::vanguards).
    #[must_use]
    pub const fn vanguards_enabled(&self) -> bool {
        self.vanguards
    }
}

impl<S> Server<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Publishes this router as a Tor `.onion` hidden service and serves requests arriving
    /// over it, blocking until the service stops.
    ///
    /// Bootstraps a fresh [`TorClient`] with [`TorClientConfig::default`] — this alone can
    /// take from several seconds up to a minute or more, since it involves connecting to and
    /// syncing with the live Tor network — then behaves like
    /// [`serve_tor_with_client`](Server::serve_tor_with_client). Reuse a [`TorClient`] across
    /// calls (via `serve_tor_with_client`) rather than bootstrapping one per service.
    ///
    /// This is the plaintext-only entry point (virtual port 80 only, no HTTPS, no
    /// configuration) — available under the `tor` feature alone, no TLS stack required. For
    /// native onion HTTPS (needs the `tls` feature too), custom state/cache directories, or the
    /// other [`OnionConfig`] options, use [`serve_onion`](Server::serve_onion) instead.
    ///
    /// # Errors
    /// Returns an error if the Tor client fails to bootstrap, `nickname` is not a valid
    /// [`HsNickname`], or the onion service fails to launch.
    pub async fn serve_tor(
        self,
        nickname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Install this server's crypto/TLS policy as rustls's process-wide default *before*
        // bootstrapping — arti reads this global default for its own relay/channel TLS
        // connections (it has no API to accept a `ClientConfig` directly). See `TlsPolicy`'s
        // docs. Idempotent: a no-op if something already installed a default. Only relevant
        // (and only compiled) when this crate's own `tls` feature is enabled — without it,
        // arti simply falls back to whatever crypto provider it installs on its own.
        #[cfg(feature = "tls")]
        self.effective_tls_policy().install_as_process_default();
        let client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
        self.serve_tor_with_client(&client, nickname).await
    }

    /// Publishes this router as a Tor `.onion` hidden service using an already-bootstrapped
    /// [`TorClient`], and serves requests arriving over it, blocking until the service stops.
    ///
    /// Only rendezvous requests targeting virtual port 80 are accepted (the port every `.onion`
    /// HTTP client expects); anything else has its circuit shut down immediately. Requests are
    /// dispatched through the same handling pipeline as [`serve_http`](Server::serve_http) —
    /// HTTP/1.1, plus h2c with the `http2` feature — one Tokio task per stream.
    ///
    /// Since `client` is already bootstrapped, arti has already constructed its internal
    /// relay/channel TLS provider from whatever `rustls::crypto::CryptoProvider` was installed
    /// process-wide *before this call* — install one yourself (e.g.
    /// `server.effective_tls_policy()`, or simply `TlsPolicy::hardened().install_as_process_default()`,
    /// both requiring this crate's `tls` feature) before bootstrapping `client` if that matters
    /// to you; it's too late to affect `client` by the time this function runs.
    /// [`serve_tor`](Server::serve_tor) does this for you because it owns the bootstrap.
    ///
    /// # Errors
    /// Returns an error if `nickname` is not a valid [`HsNickname`], or the onion service
    /// fails to launch (for example, if onion services are disabled in `client`'s config).
    pub async fn serve_tor_with_client<R>(
        self,
        client: &TorClient<R>,
        nickname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        R: Runtime,
    {
        crate::server::enforce_fips_compliance()?;

        let hs_nickname = parse_nickname(nickname)?;
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname(hs_nickname)
            .build()?;

        let Some((service, request_stream)) = client.launch_onion_service(svc_cfg)? else {
            return Err("onion services are disabled in this TorClient's config".into());
        };

        if let Some(addr) = service.onion_address() {
            tracing::info!(
                "[tor] onion service published at {}",
                addr.display_unredacted()
            );
        }

        wait_until_reachable(&service).await;

        let state = Arc::new(self);
        let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(state.max_connections));
        let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
        tokio::pin!(stream_requests);

        while let Some(stream_request) = stream_requests.next().await {
            let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
                break;
            };
            let state = state.clone();
            drop(tokio::spawn(async move {
                if let Err(e) = handle_plaintext_only_stream(state, stream_request).await {
                    tracing::debug!("[tor] connection error: {e}");
                }
                drop(permit);
            }));
        }

        drop(service);
        Ok(())
    }

    /// Publishes this router as a Tor `.onion` hidden service according to `config`
    /// (state/cache directories, vanguards) and serves requests arriving over it, blocking
    /// until the service stops. Bootstraps a fresh [`TorClient`] — see the bootstrap-time note
    /// on [`serve_tor`](Server::serve_tor); prefer [`serve_onion_with_client`](Server::serve_onion_with_client)
    /// to reuse one across services.
    ///
    /// # Errors
    /// Returns an error if the Tor client fails to bootstrap, `config.nickname` is not a valid
    /// [`HsNickname`], or the onion service fails to launch.
    pub async fn serve_onion(
        self,
        config: OnionConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = TorClientConfigBuilder::default();

        if let Some(state_dir) = &config.state_dir {
            builder
                .storage()
                .state_dir(CfgPath::new_literal(state_dir.clone()));
        }
        if let Some(cache_dir) = &config.cache_dir {
            builder
                .storage()
                .cache_dir(CfgPath::new_literal(cache_dir.clone()));
        }
        if !config.vanguards {
            builder
                .vanguards()
                .mode(ExplicitOrAuto::Explicit(VanguardMode::Disabled));
        }

        // See the equivalent comment in `serve_tor` — must happen before bootstrapping.
        #[cfg(feature = "tls")]
        self.effective_tls_policy().install_as_process_default();
        let client_config = builder.build()?;
        let client = TorClient::create_bootstrapped(client_config).await?;
        self.serve_onion_with_client(&client, config).await
    }

    /// Publishes this router as a Tor `.onion` hidden service according to `config`, using an
    /// already-bootstrapped [`TorClient`], and serves requests arriving over it, blocking until
    /// the service stops.
    ///
    /// Dispatch depends on `config` and on which features are compiled in: virtual port 80
    /// serves plaintext HTTP unless [`redirect_http`](OnionConfig::redirect_http) is enabled
    /// (in which case it issues a `308` to the `https://` equivalent) — both only possible with
    /// the `tls` feature enabled; virtual port 443 terminates TLS — self-signed by default with
    /// `cert-gen`, or a caller-supplied config via [`tls_config`](OnionConfig::tls_config) with
    /// just `tls` — and is only listened on if the `tls` feature is enabled and
    /// [`no_tls`](OnionConfig::no_tls) wasn't called. Without the `tls` feature at all, this
    /// behaves exactly like [`serve_tor_with_client`](Server::serve_tor_with_client): plaintext
    /// on virtual port 80 only. Anything else has its circuit shut down immediately.
    ///
    /// Since `client` is already bootstrapped, install a `CryptoProvider` process-wide
    /// yourself *before* bootstrapping it if you want arti's relay/channel TLS to share this
    /// server's policy — see the equivalent note on
    /// [`serve_tor_with_client`](Server::serve_tor_with_client). The self-signed certificate on
    /// virtual port 443 always uses this server's [`TlsPolicy`](crate::tls::TlsPolicy)
    /// (see [`Server::tls_policy`]), regardless of what's installed process-wide.
    ///
    /// # Errors
    /// Returns an error if `config.nickname` is not a valid [`HsNickname`], the onion service
    /// fails to launch, or (when TLS is enabled) the TLS configuration is invalid.
    pub async fn serve_onion_with_client<R>(
        self,
        client: &TorClient<R>,
        config: OnionConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        R: Runtime,
    {
        crate::server::enforce_fips_compliance()?;

        let hs_nickname = parse_nickname(&config.nickname)?;
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname(hs_nickname)
            .build()?;

        let Some((service, request_stream)) = client.launch_onion_service(svc_cfg)? else {
            return Err("onion services are disabled in this TorClient's config".into());
        };

        let onion_host = service
            .onion_address()
            .map(|addr| addr.display_unredacted().to_string());
        if let Some(host) = &onion_host {
            tracing::info!("[tor] onion service published at {host}");
        }
        tracing::info!(
            vanguards = config.vanguards,
            tls = config.tls_enabled(),
            "[tor] hardening posture: vanguards={}, tls={}",
            if config.vanguards { "on" } else { "off" },
            if config.tls_enabled() { "on" } else { "off" },
        );

        wait_until_reachable(&service).await;

        if let Some(on_ready) = config.on_ready
            && let Some(host) = &onion_host
        {
            on_ready(host);
        }

        #[cfg(feature = "tls")]
        {
            let tls_acceptor = match &config.tls {
                OnionTls::None => None,
                #[cfg(feature = "cert-gen")]
                OnionTls::SelfSigned => {
                    let domain = onion_host
                        .clone()
                        .unwrap_or_else(|| "onion-service.invalid".to_string());
                    let cert = crate::tls::generate_self_signed_cert(vec![domain])?;
                    // Shares this server's crypto/TLS policy (see `Server::tls_policy`) rather
                    // than stock rustls defaults, so a hardened/FIPS/custom provider set for
                    // clearnet applies here too.
                    let server_config = self.effective_tls_policy().server_config_from_pem(
                        cert.cert_pem.as_bytes(),
                        cert.key_pem.as_bytes(),
                    )?;
                    Some(TlsAcceptor::from(Arc::new(server_config)))
                }
                OnionTls::Custom(server_config) => Some(TlsAcceptor::from(server_config.clone())),
            };
            let onion_host: Arc<str> = Arc::from(onion_host.unwrap_or_default());
            let redirect_http = config.redirect_http;

            let state = Arc::new(self);
            let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(state.max_connections));
            let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
            tokio::pin!(stream_requests);

            while let Some(stream_request) = stream_requests.next().await {
                let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
                    break;
                };
                let state = state.clone();
                let tls_acceptor = tls_acceptor.clone();
                let onion_host = onion_host.clone();
                drop(tokio::spawn(async move {
                    if let Err(e) = handle_onion_stream(
                        state,
                        stream_request,
                        tls_acceptor,
                        redirect_http,
                        onion_host,
                    )
                    .await
                    {
                        tracing::debug!("[tor] connection error: {e}");
                    }
                    drop(permit);
                }));
            }

            drop(service);
            Ok(())
        }

        // No `tls` feature compiled in at all: `config.tls` can only ever be `OnionTls::None`
        // (the only variant that exists in this build), so this is functionally identical to
        // `serve_tor_with_client`'s plaintext-only dispatch.
        #[cfg(not(feature = "tls"))]
        {
            let state = Arc::new(self);
            let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(state.max_connections));
            let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
            tokio::pin!(stream_requests);

            while let Some(stream_request) = stream_requests.next().await {
                let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
                    break;
                };
                let state = state.clone();
                drop(tokio::spawn(async move {
                    if let Err(e) = handle_plaintext_only_stream(state, stream_request).await {
                        tracing::debug!("[tor] connection error: {e}");
                    }
                    drop(permit);
                }));
            }

            drop(service);
            Ok(())
        }
    }
}

/// Validates `nickname` as an [`HsNickname`], wrapping the error with the offending value —
/// [`HsNickname::from_str`]'s own error doesn't otherwise echo it back.
fn parse_nickname(nickname: &str) -> Result<HsNickname, Box<dyn std::error::Error + Send + Sync>> {
    nickname
        .parse()
        .map_err(|e| format!("invalid onion service nickname {nickname:?}: {e}").into())
}

/// Awaits `service`'s status stream until it reports full reachability. This tracks real Tor
/// network activity (introduction points built, descriptor accepted by `HsDirs`) with no built-in
/// timeout, so it can legitimately take minutes on a slow or first-run bootstrap — every state
/// transition is logged so that wait doesn't look hung.
async fn wait_until_reachable(service: &tor_hsservice::RunningOnionService) {
    let mut status_events = service.status_events();
    let mut last_state = None;
    loop {
        let Some(status) = status_events.next().await else {
            tracing::warn!(
                "[tor] onion service status stream ended before reporting full reachability"
            );
            return;
        };
        let state = status.state();
        if last_state != Some(state) {
            tracing::info!("[tor] onion service status: {state:?}");
            last_state = Some(state);
        }
        if state.is_fully_reachable() {
            break;
        }
    }
    tracing::info!("[tor] onion service is fully reachable");
}

/// What to do with an incoming onion-service rendezvous request, given the virtual port it
/// targeted and the service's current TLS/redirect configuration. Kept as a pure function
/// (see the `tests` module below) independent of arti's stream types so the dispatch rules can
/// be unit-tested without a live Tor connection.
///
/// `Redirect`/`ServeTls` only exist when the `tls` feature is enabled — without it, an onion
/// service can only ever be plaintext, so [`route_onion_request`] never has a reason to produce
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnionAction {
    /// Shut the circuit down — not a port this service answers on.
    Reject,
    /// Serve the app directly over plaintext HTTP.
    ServePlaintext,
    /// Issue a `308 Permanent Redirect` to the `https://` equivalent. Requires the `tls`
    /// feature.
    #[cfg(feature = "tls")]
    Redirect,
    /// Perform a TLS handshake, then serve the app over it. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    ServeTls,
}

#[cfg_attr(not(feature = "tls"), allow(unused_variables))]
const fn route_onion_request(port: u16, tls_enabled: bool, redirect_http: bool) -> OnionAction {
    match port {
        #[cfg(feature = "tls")]
        ONION_HTTP_PORT if tls_enabled && redirect_http => OnionAction::Redirect,
        ONION_HTTP_PORT => OnionAction::ServePlaintext,
        #[cfg(feature = "tls")]
        ONION_HTTPS_PORT if tls_enabled => OnionAction::ServeTls,
        _ => OnionAction::Reject,
    }
}

/// Builds the `Location` header value for a plaintext→TLS onion redirect. Requires the `tls`
/// feature.
#[cfg(feature = "tls")]
fn redirect_location(onion_host: &str, path_and_query: &str) -> String {
    format!("https://{onion_host}{path_and_query}")
}

/// Handles a single rendezvous stream for [`Server::serve_tor_with_client`] — plaintext HTTP on
/// virtual port 80 only, everything else rejected.
async fn handle_plaintext_only_stream<S>(
    state: Arc<Server<S>>,
    stream_request: StreamRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    let IncomingStreamRequest::Begin(begin) = stream_request.request() else {
        stream_request.shutdown_circuit()?;
        return Ok(());
    };

    if route_onion_request(begin.port(), false, false) != OnionAction::ServePlaintext {
        stream_request.shutdown_circuit()?;
        return Ok(());
    }

    let onion_stream = stream_request.accept(Connected::new_empty()).await?;
    let svc =
        hyper::service::service_fn(move |req| hyper_handler(state.clone(), req, ONION_PEER_ADDR));
    serve_connection(onion_stream, svc).await
}

/// Handles a single rendezvous stream for [`Server::serve_onion_with_client`], dispatching per
/// [`route_onion_request`]. Requires the `tls` feature (see [`OnionAction`]'s docs for why the
/// non-TLS case never needs this — it reuses [`handle_plaintext_only_stream`] instead).
#[cfg(feature = "tls")]
async fn handle_onion_stream<S>(
    state: Arc<Server<S>>,
    stream_request: StreamRequest,
    tls_acceptor: Option<TlsAcceptor>,
    redirect_http: bool,
    onion_host: Arc<str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    let IncomingStreamRequest::Begin(begin) = stream_request.request() else {
        stream_request.shutdown_circuit()?;
        return Ok(());
    };

    match route_onion_request(begin.port(), tls_acceptor.is_some(), redirect_http) {
        OnionAction::Reject => {
            stream_request.shutdown_circuit()?;
            Ok(())
        }
        OnionAction::ServePlaintext => {
            let onion_stream = stream_request.accept(Connected::new_empty()).await?;
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, ONION_PEER_ADDR)
            });
            serve_connection(onion_stream, svc).await
        }
        OnionAction::Redirect => {
            let onion_stream = stream_request.accept(Connected::new_empty()).await?;
            let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let onion_host = onion_host.clone();
                async move { Ok::<_, std::io::Error>(redirect_response(&req, &onion_host)) }
            });
            serve_connection(onion_stream, svc).await
        }
        OnionAction::ServeTls => {
            let Some(acceptor) = tls_acceptor else {
                stream_request.shutdown_circuit()?;
                return Ok(());
            };
            let onion_stream = stream_request.accept(Connected::new_empty()).await?;
            let tls_stream = tokio::time::timeout(
                crate::server::TLS_HANDSHAKE_TIMEOUT,
                acceptor.accept(onion_stream),
            )
            .await
            .map_err(|_| "TLS handshake timed out")??;
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, ONION_PEER_ADDR)
            });
            serve_connection(tls_stream, svc).await
        }
    }
}

/// Builds the `308 Permanent Redirect` response for a plaintext request when
/// [`OnionConfig::redirect_http`] is enabled. Requires the `tls` feature.
#[cfg(feature = "tls")]
fn redirect_response(req: &Request<hyper::body::Incoming>, onion_host: &str) -> Response<Body> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let location = redirect_location(onion_host, path_and_query);
    Response::builder()
        .status(308) // preserves the HTTP method, unlike 301/302
        .header("location", location)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "tls")]
    use super::redirect_location;
    use super::{OnionAction, OnionConfig, parse_nickname, route_onion_request};

    #[test]
    fn plaintext_serves_port_80_and_rejects_everything_else() {
        assert_eq!(
            route_onion_request(80, false, false),
            OnionAction::ServePlaintext
        );
        assert_eq!(route_onion_request(443, false, false), OnionAction::Reject);
        assert_eq!(route_onion_request(22, false, false), OnionAction::Reject);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_dual_stack_serves_both_ports_without_redirect() {
        assert_eq!(
            route_onion_request(80, true, false),
            OnionAction::ServePlaintext
        );
        assert_eq!(route_onion_request(443, true, false), OnionAction::ServeTls);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_with_redirect_forces_port_80_to_redirect() {
        assert_eq!(route_onion_request(80, true, true), OnionAction::Redirect);
        assert_eq!(route_onion_request(443, true, true), OnionAction::ServeTls);
    }

    #[test]
    fn redirect_only_applies_when_tls_is_enabled() {
        // Requesting a redirect without TLS enabled is meaningless — plaintext still wins.
        assert_eq!(
            route_onion_request(80, false, true),
            OnionAction::ServePlaintext
        );
    }

    #[test]
    fn unknown_ports_are_always_rejected() {
        assert_eq!(route_onion_request(8080, false, false), OnionAction::Reject);
        assert_eq!(route_onion_request(8080, true, true), OnionAction::Reject);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn redirect_location_builds_the_https_equivalent_url() {
        assert_eq!(
            redirect_location("abcd1234.onion", "/foo?x=1"),
            "https://abcd1234.onion/foo?x=1"
        );
        assert_eq!(
            redirect_location("abcd1234.onion", "/"),
            "https://abcd1234.onion/"
        );
    }

    #[cfg(feature = "cert-gen")]
    #[test]
    fn onion_config_defaults_to_self_signed_tls_when_cert_gen_is_enabled() {
        let config = OnionConfig::new("test-nickname");
        assert_eq!(config.nickname, "test-nickname");
        assert!(config.vanguards);
        assert!(!config.redirect_http);
        assert!(matches!(config.tls, super::OnionTls::SelfSigned));
    }

    #[cfg(not(feature = "cert-gen"))]
    #[test]
    fn onion_config_defaults_to_no_tls_without_cert_gen() {
        let config = OnionConfig::new("test-nickname");
        assert_eq!(config.nickname, "test-nickname");
        assert!(config.vanguards);
        assert!(!config.redirect_http);
        assert!(matches!(config.tls, super::OnionTls::None));
    }

    #[test]
    fn onion_config_builder_methods_are_chainable() {
        let config = OnionConfig::new("nick")
            .state_dir("/tmp/state")
            .cache_dir("/tmp/cache")
            .redirect_http(true)
            .vanguards(false)
            .no_tls();
        assert_eq!(
            config.state_dir.as_deref(),
            Some(std::path::Path::new("/tmp/state"))
        );
        assert_eq!(
            config.cache_dir.as_deref(),
            Some(std::path::Path::new("/tmp/cache"))
        );
        assert!(config.redirect_http);
        assert!(!config.vanguards);
        assert!(matches!(config.tls, super::OnionTls::None));
    }

    #[test]
    fn parse_nickname_accepts_a_valid_name() {
        assert!(parse_nickname("valid-nickname").is_ok());
    }

    #[test]
    fn parse_nickname_rejects_an_invalid_name_and_echoes_it_back() {
        // Onion service nicknames are restricted (e.g. no spaces) — `HsNickname::from_str`
        // rejects this, and `parse_nickname` wraps that error with the offending value since
        // the underlying error doesn't otherwise include it.
        let err = parse_nickname("not a valid nickname!!").unwrap_err();
        assert!(err.to_string().contains("not a valid nickname!!"));
    }

    #[cfg(all(feature = "tls", feature = "cert-gen"))]
    #[test]
    fn tls_config_switches_to_a_custom_server_config() {
        let policy = crate::tls::TlsPolicy::hardened();
        let cert = crate::tls::generate_self_signed_cert(vec!["nick.onion".to_string()])
            .expect("generate self-signed cert");
        let server_config = policy
            .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .expect("build server config");

        let config = OnionConfig::new("nick").tls_config(server_config);
        assert!(matches!(config.tls, super::OnionTls::Custom(_)));
        // `OnionTls::Custom`'s `Debug` impl deliberately doesn't dump the whole
        // `rustls::ServerConfig` — just proves the variant is reachable and formats.
        assert!(format!("{config:?}").contains("nickname"));
    }

    #[test]
    fn on_ready_stores_the_callback() {
        let config = OnionConfig::new("nick").on_ready(|_addr| {});
        assert!(config.on_ready.is_some());
    }

    #[cfg(all(feature = "tls", feature = "http1"))]
    #[tokio::test]
    async fn redirect_response_builds_a_308_to_the_https_equivalent() {
        use hyper::Request;
        use hyper::service::service_fn;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_io, server_io) = tokio::io::duplex(8 * 1024);
        let onion_host: std::sync::Arc<str> = std::sync::Arc::from("abcd1234.onion");

        let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
            let onion_host = onion_host.clone();
            async move { Ok::<_, std::io::Error>(super::redirect_response(&req, &onion_host)) }
        });
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(server_io), svc)
                .await
        });

        client_io
            .write_all(b"GET /foo?x=1 HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");

        let mut buf = Vec::new();
        client_io
            .read_to_end(&mut buf)
            .await
            .expect("read response");
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("308"), "unexpected response: {response}");
        assert!(
            response.contains("location: https://abcd1234.onion/foo?x=1"),
            "unexpected response: {response}"
        );

        server
            .await
            .expect("server task join")
            .expect("serve_connection ok");
    }
}
