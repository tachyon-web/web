//! [`I2pConfig`]: the builder for
//! [`Server::serve_i2p_config`](crate::server::Server::serve_i2p_config)/
//! [`Server::serve_i2p_config_with_router`](crate::server::Server::serve_i2p_config_with_router).

use crate::server::anon_tls::{AnonTls, OnReadyHook};
use std::path::PathBuf;
#[cfg(feature = "tls")]
use std::sync::Arc;
use tachyon_i2p::{CryptoType, SigType};

/// Configuration for publishing an I2P eepsite via
/// [`Server::serve_i2p_config`](crate::server::Server::serve_i2p_config).
///
/// See the [module docs](super) for a full example, and — importantly — for the
/// `forbid(unsafe_code)` disclosure that applies to this whole feature.
pub struct I2pConfig {
    pub(super) nickname: String,
    pub(super) data_dir: Option<PathBuf>,
    pub(super) sig_type: SigType,
    pub(super) encryption_types: Vec<CryptoType>,
    pub(super) tls: AnonTls,
    pub(super) on_ready: Option<OnReadyHook>,
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
    /// Defaults: plaintext only (see the [module docs](super) for why TLS defaults off here,
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
            tls: AnonTls::None,
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
        self.tls = AnonTls::Custom(Arc::new(config));
        self
    }

    /// Enables TLS using a freshly generated self-signed certificate for the eepsite's
    /// `.b32.i2p` address, instead of the plaintext default. Requires the `cert-gen` feature.
    #[cfg(feature = "cert-gen")]
    #[must_use]
    pub fn self_signed_tls(mut self) -> Self {
        self.tls = AnonTls::SelfSigned;
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
        self.tls = AnonTls::None;
        self
    }

    /// Registers a callback invoked exactly once — with the published `.b32.i2p` address (no
    /// scheme, e.g. `"abcd...xyz.b32.i2p"`) — as soon as the destination is created, just before
    /// requests start being served. This is the only way to observe the address
    /// programmatically, since
    /// [`serve_i2p_config`](crate::server::Server::serve_i2p_config) blocks for the lifetime of
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

    /// Whether TLS is enabled — `false` (the default) unless
    /// [`tls_config`](Self::tls_config)/[`self_signed_tls`](Self::self_signed_tls) was called.
    #[must_use]
    pub const fn tls_enabled(&self) -> bool {
        !matches!(self.tls, AnonTls::None)
    }

    /// The keys-file path this configuration resolves to (`<data_dir>/<nickname>.keys`).
    pub(super) fn keys_path(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".tachyon-i2p"))
            .join(format!("{}.keys", self.nickname))
    }
}

/// Rejects nicknames that could escape [`I2pConfig::data_dir`] when used to build the
/// destination keys file path (`<data_dir>/<nickname>.keys`) — unlike the Tor `nickname`, which
/// is validated as a typed `HsNickname` before any file I/O, I2P has no equivalent typed
/// nickname to lean on, so it's checked directly here.
pub(super) fn validate_nickname(
    nickname: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The nickname becomes a single path component under `data_dir` (see
    // `I2pConfig::keys_path`), so reject anything the OS could read as more than a plain file
    // name. Both separators are checked by hand — `\\` is only one to Windows, but a nickname
    // carrying it has no business on disk anywhere — and `components()` covers the rest by the
    // running platform's own path rules: empty, `.`, `..`, and a Windows drive prefix like
    // `C:`, which `Path::join` treats as absolute and would silently escape `data_dir`.
    let mut components = std::path::Path::new(nickname).components();
    let is_plain_name = !nickname.contains(['/', '\\'])
        && matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !is_plain_name {
        return Err(format!("invalid I2P eepsite nickname {nickname:?}").into());
    }
    Ok(())
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
        // Drive-relative on Windows, where `Path::join` would drop `data_dir` entirely.
        #[cfg(windows)]
        assert!(validate_nickname("C:keys").is_err());
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

    #[cfg(all(feature = "tls", feature = "cert-gen"))]
    #[test]
    fn tls_config_switches_to_a_custom_server_config() {
        let policy = crate::tls::TlsPolicy::new();
        let cert = crate::tls::generate_self_signed_cert(vec!["nick.b32.i2p".to_string()])
            .expect("generate self-signed cert");
        let server_config = policy
            .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .expect("build server config");

        let config = I2pConfig::new("nick").tls_config(server_config);
        assert!(matches!(
            config.tls,
            crate::server::anon_tls::AnonTls::Custom(_)
        ));
        assert!(config.tls_enabled());
    }

    #[test]
    fn on_ready_stores_the_callback() {
        let config = I2pConfig::new("nick").on_ready(|_addr| {});
        assert!(config.on_ready.is_some());
    }
}
