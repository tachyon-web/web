//! TLS configuration: [`RustlsConfig`]/[`bind_rustls`]/[`HttpsServer`], the shared
//! `rustls::ServerConfig` builder prefix ([`tls_config_builder`]), and FIPS-config checks.

#[cfg(feature = "tls")]
use std::sync::Arc;

use crate::server::Server;

#[cfg(feature = "cnsa")]
pub(crate) fn assert_cnsa_identity(
    certs: &[rustls::pki_types::CertificateDer<'static>],
    key: &rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<(), std::io::Error> {
    const ML_DSA_87_OID: [u8; 11] = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    ];
    let leaf_is_ml_dsa_87 = certs.first().is_some_and(|cert| {
        cert.as_ref()
            .windows(ML_DSA_87_OID.len())
            .any(|window| window == ML_DSA_87_OID)
    });
    if !leaf_is_ml_dsa_87 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CNSA mode requires an ML-DSA-87 leaf certificate",
        ));
    }

    let provider = crate::tls::TlsPolicy::new().provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if signing_key
        .choose_scheme(&[rustls::SignatureScheme::ML_DSA_87])
        .is_none()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CNSA mode requires an ML-DSA-87 private key",
        ));
    }
    Ok(())
}

/// Rejects a caller-supplied `rustls::ServerConfig` that doesn't itself negotiate
/// FIPS-140-3-approved algorithms, under the `fips` feature.
///
/// [`TlsPolicy::fips`](crate::tls::TlsPolicy::fips) is the only provider a `TlsPolicy` can hold
/// under `fips` (see its docs), but a `ServerConfig` can also reach this crate through doors
/// that never touch `TlsPolicy` at all: [`Server::serve_https_config`],
/// [`Server::start_https_with_config`]/[`Server::start_https_with_config_addr`],
/// [`Server::start_https_and_h3_with_config`],
/// [`Server::with_https`]/[`MultiServer::with_https`](crate::server::multi::MultiServer::with_https),
/// [`RustlsConfig::from_pem`], `OnionTls::Custom`, and `I2pTls::Custom`. Without this check, a
/// caller could hand any of those a ChaCha20-only or X25519-only config and it would be served
/// as-is even in a build that otherwise enforces FIPS. `rustls::ServerConfig::fips()` is the
/// same predicate rustls itself uses: the negotiated provider is FIPS-approved *and*
/// `require_ems` is set (FIPS 140-3 IG D.Q). The EMS half only has anything to bite on in a
/// `tls12-legacy` build — extended master secret is a TLS 1.2 extension, and the default
/// TLS-1.3-only policy has no 1.2 handshake for it to apply to.
#[cfg(all(feature = "tls", feature = "fips"))]
pub(super) fn assert_fips_server_config(
    config: &rustls::ServerConfig,
) -> Result<(), std::io::Error> {
    if !config.fips() {
        return Err(std::io::Error::other(
            "TLS config is not using the FIPS 140-3 Level 1 software module in approved mode \
             (a non-approved cipher suite or \
             key-exchange group is offered, or TLS 1.2 extended-master-secret isn't required) \
             — build it via `TlsPolicy::fips()`/`TlsPolicy::new()` rather than \
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
/// Builds the ALPN protocol list for a TLS `ServerConfig`, in preference order,
/// matching whichever of `http3`/`http2`/`http1` are actually compiled in — so
/// TLS never advertises a protocol the connection-handling code (gated on the
/// same features, see `server/http.rs`) has no branch to serve it with.
// `pub(crate)` here is genuinely needed (used from `crate::tls::policy`, outside this
// module's own subtree) — `redundant_pub_crate` and `unreachable_pub` disagree about how to
// spell exactly-crate-wide visibility on an item in a private module, so this one narrow
// exception breaks that tie in favor of the visibility that's actually correct.
#[cfg(feature = "tls")]
#[allow(clippy::redundant_pub_crate)]
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
/// Builds the shared prefix of every `rustls::ServerConfig` this crate constructs from a
/// [`TlsPolicy`](crate::tls::TlsPolicy): the provider/protocol-version negotiation, mapped to
/// an `io::Error` the same way at every call site, followed by `.with_no_client_auth()`.
///
/// Callers finish the config with whichever server-cert step they need
/// (`.with_single_cert(..)` for a fixed cert/key, `.with_cert_resolver(..)` for a hot-swap
/// resolver like the ACME one) — those two return different builder shapes, so unifying past
/// this point isn't worthwhile. This one shared prefix is what previously drifted into three
/// near-identical, independently-maintained copies.
pub(super) fn tls_config_builder(
    policy: &crate::tls::TlsPolicy,
) -> Result<
    rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>,
    std::io::Error,
> {
    rustls::ServerConfig::builder_with_provider(policy.provider())
        .with_protocol_versions(policy.versions())
        .map(<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>>::with_no_client_auth)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("TLS version configuration failed: {e}"),
            )
        })
}

/// Configuration for custom rustls server.
///
/// *Tachyon extension: no `axum` equivalent.*
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
    /// Create a new `RustlsConfig` from PEM-formatted certificate chain and private key bytes,
    /// using [`TlsPolicy::default`](crate::tls::TlsPolicy::default) — the same crypto/TLS
    /// policy `Server::start_all`/`serve_all_acme` build from, and the FIPS 140-3 Level 1
    /// approved-mode software policy
    /// one under the `fips` feature (see [`TlsPolicy`](crate::tls::TlsPolicy)'s `fips` docs).
    ///
    /// Previously this built from `rustls::ServerConfig::builder()`'s process-wide default
    /// provider instead: besides not respecting `fips`, that provider depends on load order —
    /// whichever crate first called `CryptoProvider::install_default()` (for example,
    /// `Server::serve_tor`/`serve_onion` install this crate's [`TlsPolicy`](crate::tls::TlsPolicy) process-wide for
    /// arti's benefit) determined the actual cipher suites in effect. Going through
    /// [`TlsPolicy`](crate::tls::TlsPolicy) removes that nondeterminism. Use
    /// [`Server::tls_policy`](crate::server::Server::tls_policy) plus a hand-built
    /// `rustls::ServerConfig` if you need a non-default provider or protocol-version
    /// restriction here.
    ///
    /// # Errors
    /// Returns an error if the certificates or private key cannot be parsed, or if the config is invalid.
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn from_pem(cert: Vec<u8>, key: Vec<u8>) -> Result<Self, std::io::Error> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let cert_chain: Vec<CertificateDer<'static>> = crate::tls::pem::certs(&cert);

        let key_der: PrivateKeyDer<'static> =
            crate::tls::pem::private_key(&key).map_err(|e| crate::tls::pem::key_io_error(&e))?;

        #[cfg(feature = "cnsa")]
        assert_cnsa_identity(&cert_chain, &key_der)?;

        let policy = crate::tls::TlsPolicy::default();
        let mut server_config = tls_config_builder(&policy)?
            .with_single_cert(cert_chain, key_der)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        server_config.alpn_protocols = alpn_protocols(false);
        policy.apply_to_server_config(&mut server_config);

        #[cfg(feature = "fips")]
        assert_fips_server_config(&server_config)?;

        Ok(Self {
            server_config: Arc::new(server_config),
        })
    }
}
/// Create an HTTPS server bound to the given `SocketAddr` using the provided `RustlsConfig`.
///
/// *Tachyon extension: no `axum` equivalent.*
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
///
/// *Tachyon extension: no `axum` equivalent.*
#[cfg(feature = "tls")]
pub struct HttpsServer {
    pub(crate) addr: std::net::SocketAddr,
    config: RustlsConfig,
    pub(crate) serve_http3: bool,
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
    pub async fn serve(self, router: axum::Router<()>) -> Result<(), std::io::Error> {
        #[cfg_attr(not(feature = "cnsa"), allow(unused_mut))]
        let mut server = Server::new(router);
        #[cfg(feature = "cnsa")]
        {
            server.cnsa_identity_verified = true;
        }
        #[cfg_attr(not(feature = "http3"), allow(unused_mut))]
        let mut rustls_config = (*self.config.server_config).clone();

        #[cfg(feature = "http3")]
        if self.serve_http3 && !rustls_config.alpn_protocols.iter().any(|p| p == b"h3") {
            rustls_config.alpn_protocols.insert(0, b"h3".to_vec());
        }
        let config = server.finalize_tls_config(rustls_config);
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
        #[cfg(feature = "http3")]
        let serve_http3 = self.serve_http3;

        super::bind::bind_and_serve(
            server,
            self.addr,
            None,
            move |server, listener| async move {
                #[cfg(feature = "http3")]
                let _h3_task = if serve_http3 {
                    Some(super::h3::spawn_h3_beside(&server, config, &listener)?)
                } else {
                    None
                };
                server.serve_https(listener, acceptor).await
            },
        )
        .await
    }
}
