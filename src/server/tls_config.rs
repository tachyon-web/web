//! TLS configuration: [`RustlsConfig`]/[`bind_rustls`]/[`HttpsServer`], ALPN, and the FIPS
//! config check.

use std::sync::Arc;

use crate::server::Server;

/// Rejects a `rustls::ServerConfig` that doesn't itself negotiate FIPS-approved algorithms,
/// under the `fips` feature.
///
/// A `TlsPolicy` can only hold the FIPS provider under `fips`, but a caller-supplied config
/// (`serve_https_config`, `start_https_with_config*`, `with_https`, `OnionConfig::tls_config`,
/// `I2pConfig::tls_config`) never went through one. `rustls::ServerConfig::fips()` is rustls's
/// own predicate: an approved provider *and* `require_ems` (FIPS 140-3 IG D.Q, which only bites
/// under `tls12-legacy`).
#[cfg(feature = "fips")]
pub(super) fn assert_fips_server_config(
    config: &rustls::ServerConfig,
) -> Result<(), std::io::Error> {
    if !config.fips() {
        return Err(std::io::Error::other(
            "TLS config is not using the FIPS 140-3 Level 1 software module in approved mode \
             (a non-approved cipher suite or key-exchange group is offered, or TLS 1.2 \
             extended-master-secret isn't required) — build it via `TlsPolicy` rather than \
             `rustls::ServerConfig::builder()` directly",
        ));
    }

    #[cfg(feature = "cnsa")]
    {
        let provider = config.crypto_provider();
        let suites_are_cnsa = provider.cipher_suites.len() == 1
            && provider.cipher_suites.first().is_some_and(|suite| {
                suite.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
            });
        let groups_are_cnsa = provider.kx_groups.len() == 1
            && provider
                .kx_groups
                .first()
                .is_some_and(|group| group.name() == rustls::NamedGroup::MLKEM1024);
        let resumption_is_disabled = config.send_tls13_tickets == 0
            && config.max_tls13_tickets == 0
            && config.max_early_data_size == 0
            && !config.session_storage.can_cache();
        if !suites_are_cnsa || !groups_are_cnsa || !resumption_is_disabled {
            return Err(std::io::Error::other(
                "TLS config violates the compile-time CNSA profile: require TLS 1.3 \
                 AES-256-GCM-SHA384, ML-KEM-1024, and disabled session resumption",
            ));
        }
    }

    Ok(())
}

/// The ALPN list for a TLS `ServerConfig`, in preference order, advertising only protocols
/// this build can serve.
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

/// Configuration for custom rustls server.
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Clone)]
pub struct RustlsConfig {
    pub(crate) server_config: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for RustlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsConfig").finish_non_exhaustive()
    }
}

impl RustlsConfig {
    /// Create a new `RustlsConfig` from PEM-formatted certificate chain and private key bytes,
    /// using [`TlsPolicy::default`](crate::tls::TlsPolicy::default) — the FIPS 140-3 Level 1
    /// approved-mode policy under the `fips` feature.
    ///
    /// The serving [`Server`]'s own [`tls_policy`](Server::tls_policy) resumption setting is
    /// applied on top when [`HttpsServer::serve`] runs. For a different provider or version
    /// restriction, build a `rustls::ServerConfig` yourself and use
    /// [`Server::serve_https_config`].
    ///
    /// # Errors
    /// Returns an error if the certificates or private key cannot be parsed, or if the config is invalid.
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn from_pem(cert: Vec<u8>, key: Vec<u8>) -> Result<Self, std::io::Error> {
        let server_config = crate::tls::TlsPolicy::default().server_config_from_pem(&cert, &key)?;
        Ok(Self {
            server_config: Arc::new(server_config),
        })
    }
}

/// Create an HTTPS server bound to the given `SocketAddr` using the provided `RustlsConfig`.
///
/// *Tachyon extension: no `axum` equivalent.*
#[must_use]
pub const fn bind_rustls(addr: std::net::SocketAddr, config: RustlsConfig) -> HttpsServer {
    HttpsServer {
        addr,
        config,
        serve_http3: false,
    }
}

/// An HTTPS server ready to be run.
///
/// *Tachyon extension: no `axum` equivalent.*
pub struct HttpsServer {
    pub(crate) addr: std::net::SocketAddr,
    config: RustlsConfig,
    pub(crate) serve_http3: bool,
}

impl std::fmt::Debug for HttpsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsServer")
            .field("addr", &self.addr)
            .field("serve_http3", &self.serve_http3)
            .finish_non_exhaustive()
    }
}

impl HttpsServer {
    /// Enable or disable HTTP/3 (QUIC) support on the same port.
    ///
    /// Silently ignored without the `http3` feature.
    #[must_use]
    pub const fn serve_http3(mut self, enable: bool) -> Self {
        self.serve_http3 = enable;
        self
    }

    /// Run the server: a bare [`Router`](axum::Router) for the defaults, or a configured
    /// [`Server`] for custom limits and policies.
    ///
    /// # Example
    /// ```rust,no_run
    /// # async fn example(config: tachyon_web::RustlsConfig) -> std::io::Result<()> {
    /// use axum::Router;
    /// use tachyon_web::{Server, bind_rustls};
    ///
    /// let addr = "0.0.0.0:443".parse().expect("valid address");
    /// let server = Server::new(Router::new()).max_connections(1_024);
    /// bind_rustls(addr, config).serve(server).await
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns an error if binding, starting HTTP/3, or running the server fails.
    pub async fn serve(self, server: impl Into<Server>) -> Result<(), std::io::Error> {
        let server = server.into();
        // `RustlsConfig::from_pem` already verified the identity.
        #[cfg(feature = "cnsa")]
        let server = Server {
            cnsa_identity_verified: true,
            ..server
        };
        #[cfg_attr(not(feature = "http3"), allow(unused_mut))]
        let mut config = (*self.config.server_config).clone();
        #[cfg(feature = "http3")]
        if self.serve_http3 && !config.alpn_protocols.iter().any(|p| p == b"h3") {
            config.alpn_protocols.insert(0, b"h3".to_vec());
        }
        let config = server.finalize_tls_config(config);
        let h3 = self.serve_http3;
        super::bind::bind_and_serve(server, self.addr, None, move |server, listener| {
            server.serve_tls(listener, config, h3)
        })
        .await
    }
}
