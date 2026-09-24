//! [`OnionConfig`]: the builder for [`Server::serve_onion`](crate::server::Server::serve_onion)/
//! [`Server::serve_onion_with_client`](crate::server::Server::serve_onion_with_client).

use crate::server::anon_tls::{AnonTls, OnReadyHook};
use std::path::PathBuf;
#[cfg(feature = "tls")]
use std::sync::Arc;
use tor_hsservice::HsNickname;

/// Configuration for publishing a Tor `.onion` hidden service.
///
/// Passed to [`Server::serve_onion`](crate::server::Server::serve_onion)/
/// [`Server::serve_onion_with_client`](crate::server::Server::serve_onion_with_client) — see the
/// [module docs](super) for a full example.
pub struct OnionConfig {
    pub(super) nickname: String,
    pub(super) state_dir: Option<PathBuf>,
    pub(super) cache_dir: Option<PathBuf>,
    pub(super) tls: AnonTls,
    pub(super) redirect_http: bool,
    pub(super) vanguards: bool,
    pub(super) on_ready: Option<OnReadyHook>,
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
    /// Defaults: with `cert-gen`, HTTPS on virtual port 443 from a self-signed certificate
    /// beside plaintext on port 80; otherwise plaintext only. No forced redirect, vanguards on.
    /// `nickname` is validated (as an [`HsNickname`]) when the service is launched.
    #[must_use]
    pub fn new(nickname: impl Into<String>) -> Self {
        Self {
            nickname: nickname.into(),
            state_dir: None,
            cache_dir: None,
            #[cfg(feature = "cert-gen")]
            tls: AnonTls::SelfSigned,
            #[cfg(not(feature = "cert-gen"))]
            tls: AnonTls::None,
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
    /// [`Server::serve_tor`](crate::server::Server::serve_tor).
    // `const`-eligible only without `tls`, where `AnonTls` has no drop glue.
    #[cfg_attr(not(feature = "tls"), allow(clippy::missing_const_for_fn))]
    #[must_use]
    pub fn no_tls(mut self) -> Self {
        self.tls = AnonTls::None;
        self
    }

    /// Re-enables HTTPS with a freshly generated self-signed certificate (the default with
    /// `cert-gen`), after a prior [`no_tls`](Self::no_tls) or `tls_config` call.
    #[cfg(feature = "cert-gen")]
    #[must_use]
    pub fn self_signed_tls(mut self) -> Self {
        self.tls = AnonTls::SelfSigned;
        self
    }

    /// Enables HTTPS using a caller-supplied `rustls::ServerConfig` — e.g. the same one passed
    /// to [`Server::serve_https_config`](crate::server::Server::serve_https_config) for the
    /// clearnet listener. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls_config(mut self, config: rustls::ServerConfig) -> Self {
        self.tls = AnonTls::Custom(Arc::new(config));
        self
    }

    /// With TLS enabled, `true` makes virtual port 80 `308`-redirect to the `https://` URL;
    /// `false` (the default) serves both. No effect without TLS.
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

    /// Registers a callback invoked at most once — with the published `.onion` address (no
    /// scheme, e.g. `"abcd...xyz.onion"`) — as soon as the service is fully reachable, just
    /// before requests start being served. It is skipped if arti never reports an address.
    /// This is the only way to observe the address programmatically, since
    /// [`serve_onion`](crate::server::Server::serve_onion) blocks for the lifetime of
    /// the service; with the `telemetry` feature the address is also logged at `info` level.
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

    /// Whether HTTPS is enabled — `false` after [`no_tls`](Self::no_tls), and always without
    /// the `tls` feature.
    #[must_use]
    pub const fn tls_enabled(&self) -> bool {
        !matches!(self.tls, AnonTls::None)
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

/// Validates `nickname` as an [`HsNickname`], wrapping the error with the offending value —
/// [`HsNickname::from_str`]'s own error doesn't otherwise echo it back.
pub(super) fn parse_nickname(
    nickname: &str,
) -> Result<HsNickname, Box<dyn std::error::Error + Send + Sync>> {
    nickname
        .parse()
        .map_err(|e| format!("invalid onion service nickname {nickname:?}: {e}").into())
}

#[cfg(test)]
mod tests {
    use super::{OnionConfig, parse_nickname};

    #[cfg(all(feature = "tls", feature = "cert-gen"))]
    #[test]
    fn tls_config_switches_to_a_custom_server_config() {
        let policy = crate::tls::TlsPolicy::new();
        let cert = crate::tls::generate_self_signed_cert(vec!["nick.onion".to_string()])
            .expect("generate self-signed cert");
        let server_config = policy
            .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .expect("build server config");

        let config = OnionConfig::new("nick").tls_config(server_config);
        assert!(matches!(
            config.tls,
            crate::server::anon_tls::AnonTls::Custom(_)
        ));
        // `AnonTls`'s `Debug` impl deliberately doesn't dump the whole `rustls::ServerConfig` —
        // just proves the variant is reachable and formats.
        assert!(format!("{config:?}").contains("nickname"));
    }

    #[cfg(feature = "cert-gen")]
    #[test]
    fn onion_config_defaults_to_self_signed_tls_when_cert_gen_is_enabled() {
        let config = OnionConfig::new("test-nickname");
        assert_eq!(config.nickname, "test-nickname");
        assert!(config.vanguards);
        assert!(!config.redirect_http);
        assert!(matches!(
            config.tls,
            crate::server::anon_tls::AnonTls::SelfSigned
        ));
    }

    #[cfg(not(feature = "cert-gen"))]
    #[test]
    fn onion_config_defaults_to_no_tls_without_cert_gen() {
        let config = OnionConfig::new("test-nickname");
        assert_eq!(config.nickname, "test-nickname");
        assert!(config.vanguards);
        assert!(!config.redirect_http);
        assert!(matches!(config.tls, crate::server::anon_tls::AnonTls::None));
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
        assert!(matches!(config.tls, crate::server::anon_tls::AnonTls::None));
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

    #[test]
    fn on_ready_stores_the_callback() {
        let config = OnionConfig::new("nick").on_ready(|_addr| {});
        assert!(config.on_ready.is_some());
    }
}
