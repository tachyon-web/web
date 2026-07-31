//! Native I2P `.b32.i2p` eepsite support (see the `i2p` feature).
//!
//! Wraps [`tachyon_i2p`] (itself a safe wrapper around the vendored `libi2pd` router, see that
//! crate's docs) so a Tachyon [`Server`] can be published directly as an I2P eepsite — no
//! external `i2pd`/Java-I2P process, no SAM/BOB bridge — with the same `serve_*` ergonomics as
//! [`Server::serve_tor`](crate::server::Server::serve_tor).
//!
//! # ⚠️ This feature does not honor `tachyon-web`'s `forbid(unsafe_code)` guarantee
//!
//! `tachyon-web` itself has `#![forbid(unsafe_code)]` at its crate root, same as always. But
//! `libi2pd` is a C++ library with no stable C ABI, so reaching it at all requires an FFI
//! boundary — that boundary is [`i2pd-sys`](https://docs.rs/i2pd-sys) (a hand-written `extern
//! "C"` shim over `libi2pd`, vendored from [PurpleI2P/i2pd](https://github.com/PurpleI2P/i2pd))
//! and [`tachyon-i2p`](https://docs.rs/tachyon-i2p) (the safe wrapper crate built on top of it),
//! both **written for this project**, not a long-established, independently-audited pure-Rust
//! dependency the way `arti-client`/`tor-hsservice` are for the `tor` feature. Enabling `i2p`
//! pulls that FFI layer — and the statically-linked `libi2pd`/Boost/AWS-LC C/C++ code it
//! compiles from vendored source — into your binary.
//!
//! Concretely, this means:
//! - Memory safety for everything reachable through this feature rests on this project's own
//!   review of `libi2pd`'s threading/ownership contracts (documented inline in
//!   `i2pd-sys/shim/shim.h` and `tachyon-i2p`'s source), not on the Rust compiler.
//! - A memory-safety bug in `libi2pd` itself, or in the shim/wrapper glue, is a bug in *your*
//!   process — there is no separate-process/SAM-bridge isolation boundary the way there would
//!   be running a standalone `i2pd` daemon.
//! - This is meaningfully newer and less battle-tested than the `tor` feature. Treat it
//!   accordingly for anything security-sensitive: review `tachyon-i2p`'s source yourself, keep
//!   the crate updated, and don't expose it to hostile input without the same caution you'd
//!   apply to any other C/C++ dependency compiled into your binary.
//!
//! None of this is a knock on `libi2pd` itself (it's the reference I2P router implementation and
//! plenty battle-tested on its own), but *this specific FFI boundary* is new, project-specific
//! code, not something with years of independent scrutiny the way `arti`'s pure-Rust stack has.
//!
//! # Two entry points
//!
//! - [`Server::serve_i2p`] — the simplest possible eepsite: a persistent destination (keys
//!   stored under a data directory, so the address survives restarts), plaintext only.
//! - [`Server::serve_i2p_config`], driven by an [`I2pConfig`] — adds an `on_ready` hook and a
//!   custom keys-file location, always available under the `i2p` feature alone. Optional TLS
//!   ([`I2pConfig::tls_config`], and [`I2pConfig::self_signed_tls`] specifically) additionally
//!   requires enabling `tls` (and `cert-gen` for the self-signed convenience) alongside `i2p` —
//!   see the [module docs](self) below and the `i2p` feature's own docs in `Cargo.toml`.
//!
//! # Crypto backend: `aws-lc` (default) vs FIPS
//!
//! `i2pd-sys` (via `tachyon-i2p`) links one of two crypto backends: regular AWS-LC (the default,
//! selected here by the `i2p` feature) or the FIPS 140-3-validated AWS-LC-FIPS module. There's no
//! separate `i2p-fips` feature — this crate's single top-level `fips` feature reaches into
//! `tachyon-i2p/fips` too (taking priority over `i2p`'s `aws-lc` pick, harmlessly — see
//! `i2pd-sys`'s crate docs for why), so enabling `i2p` and `fips` together is all it takes to
//! publish this eepsite with FIPS-validated crypto everywhere, including the optional TLS layer
//! ([`I2pConfig::tls_config`]/[`I2pConfig::self_signed_tls`]). See
//! [`i2pd-sys`'s README](https://docs.rs/i2pd-sys) ("FIPS" section) for what this does and does
//! not get you before reaching for it to satisfy a compliance requirement.
//!
//! # Why there's no `redirect_http`/dual-stack option like `tor`'s `OnionConfig`
//!
//! A Tor onion service multiplexes plaintext (virtual port 80) and TLS (virtual port 443) over
//! the *same* `.onion` address, because Tor's rendezvous protocol carries a virtual port per
//! stream. I2P's streaming protocol has no equivalent convention actually wired up here — one
//! [`Destination`](tachyon_i2p::Destination) is one address serving *one* mode. Pick plaintext
//! (the default, and by far the more common real-world eepsite setup) or TLS
//! ([`I2pConfig::tls_config`]) up front; there's no in-band redirect between them the way there
//! is for Tor.
//!
//! # Example
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//!
//! async fn hello() -> &'static str { "Hello from an eepsite!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     // Publishes the service, prints its `.b32.i2p` address as soon as the destination is
//!     // created (not necessarily reachable on the network yet), then blocks serving requests
//!     // arriving over I2P streams.
//!     Server::new(app).serve_i2p("my-eepsite").await?;
//!     Ok(())
//! }
//! ```
//!
//! # Custom data directory and an `on_ready` hook
//!
//! ```rust,no_run
//! use tachyon_web::{Router, Server, get};
//! use tachyon_web::server::i2p::I2pConfig;
//!
//! async fn hello() -> &'static str { "Hello, eepsite world!" }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let app = Router::new().route("/", get(hello));
//!
//!     let config = I2pConfig::new("my-eepsite")
//!         .data_dir("/var/lib/tachyon/i2p")
//!         .on_ready(|addr| tracing::info!("reachable at http://{addr}"));
//!
//!     Server::new(app).serve_i2p_config(config).await?;
//!     Ok(())
//! }
//! ```
//!
//! Reusing the same `nickname` (and data directory) across restarts keeps the same `.b32.i2p`
//! address — the destination's keys file is created on first run and reused after that.
//!
//! # Choosing the identity's signature algorithm, and the destination's encryption capability
//!
//! [`I2pConfig::signature_type`] controls the identity's signature algorithm, used **the first
//! time** a destination's keys are generated (irrelevant once a keys file already exists — an
//! existing destination keeps whatever it was originally created with); it defaults to
//! [`tachyon_i2p::SigType::Eddsa25519`], the I2P network's own current default.
//!
//! [`I2pConfig::crypto_type`] is different: it controls which encryption algorithm(s) the
//! destination's `LeaseSet2` *advertises*, and applies on every run, not just first-time
//! generation (the identity's own certificate is always plain `ElGamal` regardless — that's a
//! hard requirement of real I2P clients, not something this crate exposes a choice over). Not
//! calling it at all (the default) already publishes a hybrid `ElGamal` + ECIES-X25519 set, plus
//! the post-quantum `ML-KEM-768` hybrid variant too if this was built against a
//! post-quantum-capable crypto backend — maximizing both reachability and, when available,
//! "harvest now, decrypt later" resistance, with no explicit opt-in needed. Call it only to
//! *narrow* that down to one specific algorithm, e.g. for a smaller `LeaseSet2` or to deliberately
//! exclude the post-quantum component:
//!
//! ```rust,no_run
//! use tachyon_web::server::i2p::I2pConfig;
//! use tachyon_i2p::{CryptoType, SigType};
//!
//! let config = I2pConfig::new("my-eepsite")
//!     .signature_type(SigType::Eddsa25519)
//!     .crypto_type(CryptoType::EciesX25519); // classical-only, no ML-KEM component
//! ```

use crate::server::Server;
use crate::server::conn::{NO_PEER_ADDR as I2P_PEER_ADDR, serve_connection};
use crate::server::http::hyper_handler;
use std::path::PathBuf;
use std::sync::Arc;
use tachyon_i2p::{CryptoType, I2pRouter, SigType};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;

/// How (or whether) an eepsite published via [`I2pConfig`] terminates TLS.
#[derive(Clone)]
enum I2pTls {
    /// Plaintext only. This is the default — see the [module docs](self) for why, unlike Tor's
    /// onion services, this isn't just cosmetic defense-in-depth: I2P's own transport is already
    /// end-to-end encrypted, so TLS on top mainly matters if you specifically want the
    /// destination itself to present a certificate.
    None,
    /// TLS using an ephemeral self-signed certificate, generated for the eepsite's `.b32.i2p`
    /// address once it's known. Requires the `cert-gen` feature.
    #[cfg(feature = "cert-gen")]
    SelfSigned,
    /// TLS using a caller-supplied config — e.g. the same `rustls::ServerConfig` used for a
    /// clearnet [`Server::serve_https_config`](crate::server::Server::serve_https_config)
    /// listener. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    Custom(Arc<rustls::ServerConfig>),
}

impl std::fmt::Debug for I2pTls {
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

/// Callback invoked with the published `.b32.i2p` address — see [`I2pConfig::on_ready`].
type OnReadyHook = Box<dyn FnOnce(&str) + Send>;

/// Configuration for publishing an I2P eepsite via [`Server::serve_i2p_config`].
///
/// See the [module docs](self) for a full example, and — importantly — for the
/// `forbid(unsafe_code)` disclosure that applies to this whole feature.
pub struct I2pConfig {
    nickname: String,
    data_dir: Option<PathBuf>,
    sig_type: SigType,
    encryption_types: Vec<CryptoType>,
    tls: I2pTls,
    on_ready: Option<OnReadyHook>,
}

impl std::fmt::Debug for I2pConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("I2pConfig")
            .field("nickname", &self.nickname)
            .field("data_dir", &self.data_dir)
            .field("sig_type", &self.sig_type)
            .field("encryption_types", &self.encryption_types)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

impl I2pConfig {
    /// Creates a new configuration for a service published under `nickname`. `nickname` also
    /// seeds libi2pd's own default data directory name (its router keys/netDb cache, separate
    /// from this eepsite's own persistent destination keys — see [`data_dir`](Self::data_dir)).
    ///
    /// Defaults: plaintext only (see the [module docs](self) for why TLS defaults off here,
    /// unlike Tor's `OnionConfig`), no `on_ready` hook, destination keys stored under
    /// `./.tachyon-i2p/<nickname>.keys` relative to the current working directory,
    /// [`SigType::default`] for the identity's signature algorithm (only used the first time
    /// this destination's keys are generated — see
    /// [`signature_type`](Self::signature_type)), and no explicit
    /// [`crypto_type`](Self::crypto_type) override — which means the destination publishes
    /// libi2pd's own automatic hybrid encryption set rather than a single fixed algorithm; see
    /// [`crypto_type`](Self::crypto_type)'s docs before assuming a specific one is always used.
    #[must_use]
    pub fn new(nickname: impl Into<String>) -> Self {
        Self {
            nickname: nickname.into(),
            data_dir: None,
            sig_type: SigType::default(),
            encryption_types: Vec::new(),
            tls: I2pTls::None,
            on_ready: None,
        }
    }

    /// Overrides the directory this eepsite's persistent destination keys file is stored under
    /// (as `<data_dir>/<nickname>.keys`). Reusing the same directory (and `nickname`) across
    /// restarts keeps the same `.b32.i2p` address. Defaults to `./.tachyon-i2p` relative to the
    /// current working directory.
    #[must_use]
    pub fn data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    /// Overrides the signature algorithm used **the first time** this destination's keys are
    /// generated — irrelevant if a keys file already exists at the resolved path (an existing
    /// destination keeps whatever algorithm it was originally created with). See
    /// [`tachyon_i2p::SigType`]'s own docs for what's available and why RSA isn't one of the
    /// options; defaults to [`SigType::default`] (`Eddsa25519`, the I2P network's own default).
    #[must_use]
    pub const fn signature_type(mut self, sig: SigType) -> Self {
        self.sig_type = sig;
        self
    }

    /// Overrides which encryption algorithm this destination's `LeaseSet2` advertises as usable —
    /// convenience for the common single-algorithm case; see
    /// [`encryption_types`](Self::encryption_types) (which this is built on) for the general
    /// case, including "prefer post-quantum but still accept classical" multi-algorithm setups.
    /// See [`tachyon_i2p::CryptoType`]'s own docs for the available options.
    ///
    /// Not calling this at all (the default) publishes libi2pd's own automatic hybrid set —
    /// `ElGamal` + ECIES-X25519, plus ML-KEM-768+X25519 if this was built against a
    /// post-quantum-capable crypto backend — which is what most callers want. Call this to
    /// *narrow* that down to exactly one algorithm instead, e.g. for a smaller `LeaseSet2` or to
    /// deliberately exclude the post-quantum component.
    #[must_use]
    pub fn crypto_type(mut self, crypto: CryptoType) -> Self {
        self.encryption_types = vec![crypto];
        self
    }

    /// Overrides which encryption algorithm(s) this destination's `LeaseSet2` advertises as usable
    /// — unlike [`signature_type`](Self::signature_type), this applies on *every* run, not just
    /// first-time key generation (the identity's own certificate is always plain `ElGamal`
    /// regardless of this setting, per real I2P clients' requirements — this only controls the
    /// destination's advertised encryption capability).
    ///
    /// Order matters: the **first** entry becomes the preferred type (published first in the
    /// actual `LeaseSet2`, and what a peer that understands multiple of the listed types will
    /// choose), with every later entry a fallback for peers that don't recognize it — publishing
    /// something a given peer doesn't understand at all is harmless, not an error, since it
    /// simply skips entries it can't use and tries the next one. This is how to express "prefer
    /// post-quantum, but still reachable by peers that don't support it yet":
    ///
    /// ```rust,no_run
    /// use tachyon_web::server::i2p::I2pConfig;
    /// use tachyon_i2p::CryptoType;
    ///
    /// let config = I2pConfig::new("my-eepsite").encryption_types(&[
    ///     CryptoType::EciesMlkem1024X25519, // preferred: strongest post-quantum option
    ///     CryptoType::EciesX25519,          // fallback: peers that don't understand ML-KEM yet
    /// ]);
    /// ```
    ///
    /// An empty slice restores the default automatic hybrid set described on
    /// [`crypto_type`](Self::crypto_type)'s docs.
    #[must_use]
    pub fn encryption_types(mut self, types: &[CryptoType]) -> Self {
        self.encryption_types = types.to_vec();
        self
    }

    /// Enables TLS using a caller-supplied `rustls::ServerConfig` instead of the plaintext
    /// default — for example, the exact same config passed to
    /// [`Server::serve_https_config`](crate::server::Server::serve_https_config) for a clearnet
    /// listener. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_config(mut self, config: rustls::ServerConfig) -> Self {
        self.tls = I2pTls::Custom(Arc::new(config));
        self
    }

    /// Enables TLS using a freshly generated self-signed certificate for the eepsite's
    /// `.b32.i2p` address, instead of the plaintext default. Requires the `cert-gen` feature.
    #[cfg(feature = "cert-gen")]
    #[must_use]
    pub fn self_signed_tls(mut self) -> Self {
        self.tls = I2pTls::SelfSigned;
        self
    }

    /// Disables TLS (the default) after a prior [`tls_config`](Self::tls_config)/
    /// [`self_signed_tls`](Self::self_signed_tls) call.
    // Only `const`-eligible when neither `Custom`/`SelfSigned` variant exists (their
    // non-trivial `Drop` glue can't run in a `const fn`), i.e. only without `tls`/`cert-gen` —
    // not worth splitting this method's signature across features for.
    #[cfg_attr(not(feature = "tls"), allow(clippy::missing_const_for_fn))]
    #[must_use]
    pub fn no_tls(mut self) -> Self {
        self.tls = I2pTls::None;
        self
    }

    /// Registers a callback invoked exactly once — with the published `.b32.i2p` address (no
    /// scheme, e.g. `"abcd...xyz.b32.i2p"`) — as soon as the destination is created, just before
    /// requests start being served. This is the only way to observe the address
    /// programmatically, since [`serve_i2p_config`](Server::serve_i2p_config) blocks for the
    /// lifetime of the service; the address is also always logged via `tracing` at `info` level.
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

    /// Whether TLS is enabled — `false` (the default) unless
    /// [`tls_config`](Self::tls_config)/[`self_signed_tls`](Self::self_signed_tls) was called.
    #[must_use]
    pub const fn tls_enabled(&self) -> bool {
        !matches!(self.tls, I2pTls::None)
    }

    /// The keys-file path this configuration resolves to (`<data_dir>/<nickname>.keys`).
    fn keys_path(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".tachyon-i2p"))
            .join(format!("{}.keys", self.nickname))
    }
}

impl<S> Server<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Publishes this router as an I2P eepsite and serves requests arriving over it, blocking
    /// indefinitely — the accept loop retries forever on error and has no graceful-stop
    /// mechanism today; abort the surrounding task (e.g. via `JoinHandle::abort`) to end it.
    ///
    /// Starts a fresh [`I2pRouter`] and a persistent destination under
    /// `./.tachyon-i2p/<nickname>.keys` — plaintext only, no other configuration. For a custom
    /// data directory, TLS, or an `on_ready` hook, use [`serve_i2p_config`](Self::serve_i2p_config)
    /// instead.
    ///
    /// **See the [module docs](crate::server::i2p) for why this feature does not honor
    /// `tachyon-web`'s `forbid(unsafe_code)` guarantee.**
    ///
    /// # Errors
    /// Returns an error if the I2P router fails to start (most commonly:
    /// [`tachyon_i2p::I2pError::AlreadyRunning`] if another [`I2pRouter`] is already running in
    /// this process — only one may exist per process) or the destination fails to load/create.
    pub async fn serve_i2p(
        self,
        nickname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.serve_i2p_config(I2pConfig::new(nickname)).await
    }

    /// Publishes this router as an I2P eepsite according to `config`, starting a fresh
    /// [`I2pRouter`], and serves requests arriving over it, blocking indefinitely — the accept
    /// loop retries forever on error and has no graceful-stop mechanism today; abort the
    /// surrounding task (e.g. via `JoinHandle::abort`) to end it.
    ///
    /// **See the [module docs](crate::server::i2p) for why this feature does not honor
    /// `tachyon-web`'s `forbid(unsafe_code)` guarantee.**
    ///
    /// # Errors
    /// Returns an error if the I2P router fails to start (most commonly:
    /// [`tachyon_i2p::I2pError::AlreadyRunning`] if another [`I2pRouter`] is already running in
    /// this process — only one may exist per process; use
    /// [`serve_i2p_config_with_router`](Self::serve_i2p_config_with_router) to reuse one instead),
    /// the destination fails to load/create, or (when TLS is enabled) the TLS configuration is
    /// invalid.
    pub async fn serve_i2p_config(
        self,
        config: I2pConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let router = I2pRouter::start(config.nickname.clone()).await?;
        self.serve_i2p_config_with_router(&router, config).await
    }

    /// Publishes this router as an I2P eepsite according to `config`, using an already-started
    /// [`I2pRouter`] (only one may run per process — this is how a second eepsite, or a second
    /// destination used purely as an outbound client, shares the same router instead of hitting
    /// [`tachyon_i2p::I2pError::AlreadyRunning`]), and serves requests arriving over it, blocking
    /// indefinitely — the accept loop retries forever on error and has no graceful-stop
    /// mechanism today; abort the surrounding task (e.g. via `JoinHandle::abort`) to end it.
    ///
    /// **See the [module docs](crate::server::i2p) for why this feature does not honor
    /// `tachyon-web`'s `forbid(unsafe_code)` guarantee.**
    ///
    /// The self-signed certificate (when [`I2pConfig::self_signed_tls`] is used) shares this
    /// server's crypto/TLS policy — see [`Server::tls_policy`].
    ///
    /// # Errors
    /// Returns an error if `nickname` contains path separators or `..` (it's used verbatim to
    /// build the destination keys file path, as `<data_dir>/<nickname>.keys`), the destination
    /// fails to load/create, or (when TLS is enabled) the TLS configuration is invalid.
    pub async fn serve_i2p_config_with_router(
        self,
        router: &I2pRouter,
        config: I2pConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        crate::server::enforce_fips_compliance()?;
        validate_nickname(&config.nickname)?;

        let keys_path = config.keys_path();
        let is_public = true;
        let mut destination = router
            .destination_from_keys_file(
                keys_path,
                is_public,
                config.sig_type,
                &config.encryption_types,
            )
            .await?;

        let address = destination.b32_address().to_string();
        tracing::info!("[i2p] eepsite published at {address}");
        if let Some(on_ready) = config.on_ready {
            on_ready(&address);
        }

        #[cfg(feature = "tls")]
        {
            let tls_acceptor = match &config.tls {
                I2pTls::None => None,
                #[cfg(feature = "cert-gen")]
                I2pTls::SelfSigned => {
                    let cert = crate::tls::generate_self_signed_cert(vec![address.clone()])?;
                    let server_config = self.effective_tls_policy().server_config_from_pem(
                        cert.cert_pem.as_bytes(),
                        cert.key_pem.as_bytes(),
                    )?;
                    Some(TlsAcceptor::from(Arc::new(server_config)))
                }
                I2pTls::Custom(server_config) => Some(TlsAcceptor::from(server_config.clone())),
            };

            let state = Arc::new(self);
            loop {
                let stream = match destination.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        // Unlike the TCP `accept()` loops (`serve_http`/`serve_https`), a
                        // persistently failing `destination.accept()` (e.g. the underlying I2P
                        // tunnel is down) has no OS-level resource-exhaustion signal to detect —
                        // so back off unconditionally rather than risk a tight, CPU-spinning
                        // retry loop if every future `accept()` keeps failing immediately.
                        tracing::debug!("[i2p] accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let state = state.clone();
                let tls_acceptor = tls_acceptor.clone();
                drop(tokio::spawn(async move {
                    if let Err(e) = handle_i2p_stream(state, stream, tls_acceptor).await {
                        tracing::debug!("[i2p] connection error: {e}");
                    }
                }));
            }
        }

        // No `tls` feature compiled in at all: `config.tls` can only ever be `I2pTls::None`
        // (the only variant that exists in this build), so this is unconditionally plaintext.
        #[cfg(not(feature = "tls"))]
        {
            let state = Arc::new(self);
            loop {
                let stream = match destination.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("[i2p] accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let state = state.clone();
                drop(tokio::spawn(async move {
                    if let Err(e) = handle_i2p_stream_plaintext(state, stream).await {
                        tracing::debug!("[i2p] connection error: {e}");
                    }
                }));
            }
        }
    }
}

/// Rejects nicknames that could escape [`I2pConfig::data_dir`] when used to build the
/// destination keys file path (`<data_dir>/<nickname>.keys`) — unlike the Tor `nickname`, which
/// is validated as a typed `HsNickname` before any file I/O, I2P has no equivalent typed
/// nickname to lean on, so it's checked directly here.
fn validate_nickname(nickname: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if nickname.is_empty() || nickname.contains(['/', '\\']) || nickname == "." || nickname == ".."
    {
        return Err(format!("invalid I2P eepsite nickname {nickname:?}").into());
    }
    Ok(())
}

/// Handles a single accepted I2P stream when the `tls` feature is off: plaintext HTTP dispatch
/// only, sharing the same [`serve_connection`] helper (and thus HTTP/1.1-vs-HTTP/2 negotiation
/// logic) `tor.rs` uses.
#[cfg(not(feature = "tls"))]
async fn handle_i2p_stream_plaintext<S>(
    state: Arc<Server<S>>,
    stream: tachyon_i2p::I2pStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    let svc =
        hyper::service::service_fn(move |req| hyper_handler(state.clone(), req, I2P_PEER_ADDR));
    serve_connection(stream, svc).await
}

/// Handles a single accepted I2P stream: TLS (if configured) then HTTP dispatch, sharing the
/// same [`serve_connection`] helper (and thus HTTP/1.1-vs-HTTP/2 negotiation logic) `tor.rs` uses.
/// Requires the `tls` feature (see [`handle_i2p_stream_plaintext`] for the non-TLS build).
#[cfg(feature = "tls")]
async fn handle_i2p_stream<S>(
    state: Arc<Server<S>>,
    stream: tachyon_i2p::I2pStream,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    match tls_acceptor {
        None => {
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, I2P_PEER_ADDR)
            });
            serve_connection(stream, svc).await
        }
        Some(acceptor) => {
            let tls_stream = tokio::time::timeout(
                crate::server::TLS_HANDSHAKE_TIMEOUT,
                acceptor.accept(stream),
            )
            .await
            .map_err(|_| "TLS handshake timed out")??;
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, I2P_PEER_ADDR)
            });
            serve_connection(tls_stream, svc).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{I2pConfig, validate_nickname};

    #[test]
    fn validate_nickname_accepts_a_normal_name() {
        assert!(validate_nickname("my-eepsite").is_ok());
    }

    #[test]
    fn validate_nickname_rejects_path_traversal() {
        assert!(validate_nickname("..").is_err());
        assert!(validate_nickname(".").is_err());
        assert!(validate_nickname("").is_err());
        assert!(validate_nickname("../../etc/passwd").is_err());
        assert!(validate_nickname("a/b").is_err());
        assert!(validate_nickname("a\\b").is_err());
    }

    #[test]
    fn i2p_config_defaults_are_sensible() {
        let config = I2pConfig::new("test-nickname");
        assert_eq!(config.nickname(), "test-nickname");
        assert!(!config.tls_enabled());
        assert_eq!(
            config.keys_path(),
            std::path::Path::new(".tachyon-i2p/test-nickname.keys")
        );
    }

    #[cfg(feature = "cert-gen")]
    #[test]
    fn i2p_config_builder_methods_are_chainable() {
        let config = I2pConfig::new("nick")
            .data_dir("/tmp/i2p-data")
            .self_signed_tls();
        assert_eq!(
            config.keys_path(),
            std::path::Path::new("/tmp/i2p-data/nick.keys")
        );
        assert!(config.tls_enabled());

        let config = config.no_tls();
        assert!(!config.tls_enabled());
    }

    #[cfg(not(feature = "cert-gen"))]
    #[test]
    fn i2p_config_data_dir_is_chainable_without_cert_gen() {
        let config = I2pConfig::new("nick").data_dir("/tmp/i2p-data");
        assert_eq!(
            config.keys_path(),
            std::path::Path::new("/tmp/i2p-data/nick.keys")
        );
        assert!(!config.tls_enabled());
    }

    #[test]
    fn i2p_config_signature_and_crypto_type_defaults_and_overrides() {
        let config = I2pConfig::new("nick");
        assert_eq!(config.sig_type, tachyon_i2p::SigType::default());
        assert!(
            config.encryption_types.is_empty(),
            "no explicit crypto_type() call should mean \"use libi2pd's automatic hybrid set\""
        );

        let config = config
            .signature_type(tachyon_i2p::SigType::EcdsaP521)
            .crypto_type(tachyon_i2p::CryptoType::EciesMlkem768X25519);
        assert_eq!(config.sig_type, tachyon_i2p::SigType::EcdsaP521);
        assert_eq!(
            config.encryption_types,
            vec![tachyon_i2p::CryptoType::EciesMlkem768X25519]
        );
    }

    #[test]
    fn i2p_config_encryption_types_preserves_preference_order() {
        let config = I2pConfig::new("nick").encryption_types(&[
            tachyon_i2p::CryptoType::EciesMlkem1024X25519,
            tachyon_i2p::CryptoType::EciesX25519,
        ]);
        assert_eq!(
            config.encryption_types,
            vec![
                tachyon_i2p::CryptoType::EciesMlkem1024X25519,
                tachyon_i2p::CryptoType::EciesX25519,
            ],
            "the preferred type must stay first -- it's what libi2pd publishes as preferred"
        );

        // A later crypto_type()/encryption_types() call replaces, rather than appends to, the
        // previous one -- confirms these two builder methods share one underlying field.
        let config = config.crypto_type(tachyon_i2p::CryptoType::EciesX25519);
        assert_eq!(
            config.encryption_types,
            vec![tachyon_i2p::CryptoType::EciesX25519]
        );
    }

    #[test]
    fn i2p_config_debug_does_not_panic() {
        let debug = format!("{:?}", I2pConfig::new("nick"));
        assert!(debug.contains("I2pConfig"));
        assert!(debug.contains("nick"));
    }

    #[cfg(all(feature = "tls", feature = "cert-gen"))]
    #[test]
    fn tls_config_switches_to_a_custom_server_config() {
        let policy = crate::tls::TlsPolicy::hardened();
        let cert = crate::tls::generate_self_signed_cert(vec!["nick.b32.i2p".to_string()])
            .expect("generate self-signed cert");
        let server_config = policy
            .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .expect("build server config");

        let config = I2pConfig::new("nick").tls_config(server_config);
        assert!(matches!(config.tls, super::I2pTls::Custom(_)));
        assert!(config.tls_enabled());
    }

    #[test]
    fn on_ready_stores_the_callback() {
        let config = I2pConfig::new("nick").on_ready(|_addr| {});
        assert!(config.on_ready.is_some());
    }
}
