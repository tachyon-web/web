//! A crypto/TLS policy shared across every listener a [`Server`](crate::server::Server) runs.

use rustls::SupportedProtocolVersion;
use rustls::crypto::CryptoProvider;
#[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// A crypto provider + protocol-version policy shared across every listener a
/// [`Server`](crate::server::Server) runs.
///
/// Configure it **once** and it covers clearnet HTTPS (static cert or Let's Encrypt via
/// [`AcmeManager`](crate::tls::acme::AcmeManager)), the onion `.onion` HTTPS termination
/// ([`OnionConfig`](crate::server::tor::OnionConfig)), and the I2P eepsite's optional TLS layer
/// ([`I2pConfig`](crate::server::i2p::I2pConfig)), instead of being reconstructed by hand for
/// each one.
///
/// Pass it once via [`Server::tls_policy`](crate::server::Server::tls_policy); every listener
/// that generates its own self-signed certificate (onion, I2P) will build it with this same
/// provider, and clearnet's ACME/static `ServerConfig` uses it too.
///
/// # The Tor relay/channel layer is a separate concern
///
/// This policy governs TLS *termination* — the handshake a browser or I2P/Tor client
/// completes with this process. It does **not** reach the TLS arti uses internally to connect
/// *out* to Tor relays (the "channel" layer) — arti has no API to accept a custom
/// `rustls::ClientConfig` for that. Instead, arti reads whatever `CryptoProvider` is installed
/// as rustls's *process-wide* default. Call [`install_as_process_default`](Self::install_as_process_default)
/// with this same policy before bootstrapping a [`TorClient`](arti_client::TorClient) (this is
/// done for you by [`Server::serve_tor`](crate::server::Server::serve_tor)/
/// [`serve_onion`](crate::server::Server::serve_onion)) so the relay layer uses the same
/// AEAD/KEM choices as your HTTPS listeners.
///
/// Restricting this policy to post-quantum-only or a single cipher suite is safe for the
/// termination side (you control both ends), but risks breaking Tor bootstrap connectivity if
/// also installed process-wide: plenty of relays on the live network don't yet support hybrid
/// PQ key-exchange groups on their TLS link layer. Prefer PQ, don't require it exclusively, if
/// this same policy will also be installed as the process default.
#[derive(Clone)]
pub struct TlsPolicy {
    provider: Arc<CryptoProvider>,
    versions: Vec<&'static SupportedProtocolVersion>,
}

impl std::fmt::Debug for TlsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPolicy")
            .field("tls13", &self.versions.contains(&&rustls::version::TLS13))
            .field("tls12", &self.versions.contains(&&rustls::version::TLS12))
            .finish_non_exhaustive()
    }
}

impl TlsPolicy {
    /// Tachyon's curated default: hybrid post-quantum key-exchange groups preferred
    /// (`X25519MLKEM768`, `SECP256R1MLKEM768`, `MLKEM1024`, `MLKEM768`), falling back to
    /// classical ECDHE groups (`SECP384R1`, `X25519`, `SECP256R1`) for interoperability;
    /// AES-256-GCM and ChaCha20-Poly1305 preferred over AES-128 for both TLS 1.3 and TLS 1.2
    /// cipher suites. Both TLS 1.3 and 1.2 are offered — see [`tls13_only`](Self::tls13_only)
    /// to pin more strictly.
    #[must_use]
    pub fn hardened() -> Self {
        Self::with_provider(hardened_provider())
    }

    /// Builds a policy from a fully custom [`CryptoProvider`] — for example one pinned to
    /// `TLS13_AES_256_GCM_SHA384` only, or built from `rustls::crypto::default_fips_provider()`
    /// (with the `fips` feature) for FIPS-140-3-validated `aws-lc-rs` primitives.
    ///
    /// Defaults to offering both TLS 1.3 and TLS 1.2 — see [`tls13_only`](Self::tls13_only).
    #[must_use]
    pub fn with_provider(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            versions: vec![&rustls::version::TLS13, &rustls::version::TLS12],
        }
    }

    /// Restricts this policy to TLS 1.3 only (default: TLS 1.3 and 1.2 both offered).
    #[must_use]
    pub fn tls13_only(mut self) -> Self {
        self.versions = vec![&rustls::version::TLS13];
        self
    }

    /// The underlying crypto provider.
    #[must_use]
    pub fn provider(&self) -> Arc<CryptoProvider> {
        self.provider.clone()
    }

    /// The protocol versions this policy negotiates.
    #[must_use]
    pub fn versions(&self) -> &[&'static SupportedProtocolVersion] {
        &self.versions
    }

    /// Installs this policy's crypto provider as rustls's process-wide default, via
    /// [`CryptoProvider::install_default`].
    ///
    /// Idempotent and safe to call redundantly (e.g. once per listener sharing this policy):
    /// rustls's global default can only be set once per process, so only the *first* call
    /// actually installs anything — later calls (even with a different policy) are silently
    /// ignored. Call this before bootstrapping a [`TorClient`](arti_client::TorClient) if you
    /// want arti's relay/channel TLS connections to use this policy's provider too — see the
    /// [type docs](Self) for why that's a separate concern from HTTPS termination.
    pub fn install_as_process_default(&self) {
        let _ = (*self.provider).clone().install_default();
    }

    /// Builds a `rustls::ServerConfig` from a PEM cert chain + key, using this policy's
    /// provider and protocol versions.
    ///
    /// Only used by the onion/i2p self-signed-cert paths today (see `server/tor.rs` and
    /// `server/i2p.rs`, both of which require `cert-gen` — not just `tls` — to reach the
    /// self-signed-cert branch) — gated the same way so a plain `tls`-only build doesn't trip
    /// `-D dead-code`.
    #[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
    pub(crate) fn server_config_from_pem(
        &self,
        cert: &[u8],
        key: &[u8],
    ) -> Result<rustls::ServerConfig, std::io::Error> {
        let cert_chain: Vec<CertificateDer<'static>> = crate::tls::pem::certs(cert);

        let key_der: PrivateKeyDer<'static> =
            crate::tls::pem::private_key(key).map_err(|e| crate::tls::pem::key_io_error(&e))?;

        let mut server_config = rustls::ServerConfig::builder_with_provider(self.provider())
            .with_protocol_versions(&self.versions)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("TLS version configuration failed: {e}"),
                )
            })?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid certificate or key: {e}"),
                )
            })?;

        server_config.alpn_protocols = crate::server::alpn_protocols(false);
        Ok(server_config)
    }
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self::hardened()
    }
}

/// Tachyon's curated default `CryptoProvider`: hybrid post-quantum key-exchange groups
/// preferred, AES-256-GCM/ChaCha20-Poly1305 preferred over AES-128, computed once and shared.
fn hardened_provider() -> Arc<CryptoProvider> {
    static DEFAULT_PROVIDER: std::sync::OnceLock<Arc<CryptoProvider>> = std::sync::OnceLock::new();
    DEFAULT_PROVIDER
        .get_or_init(|| {
            let kx_groups = vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768,
                rustls::crypto::aws_lc_rs::kx_group::MLKEM1024,
                rustls::crypto::aws_lc_rs::kx_group::MLKEM768,
                rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
                rustls::crypto::aws_lc_rs::kx_group::X25519,
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            ];

            // Both TLS 1.3 and 1.2 suites are always offered — call `TlsPolicy::tls13_only()`
            // or pass a fully custom provider (`TlsPolicy::with_provider`) for a narrower set.
            let cipher_suites = vec![
                // TLS 1.3
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
                // TLS 1.2
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ];

            Arc::new(CryptoProvider {
                cipher_suites,
                kx_groups,
                ..rustls::crypto::aws_lc_rs::default_provider()
            })
        })
        .clone()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::TlsPolicy;

    #[test]
    fn hardened_offers_both_tls_versions_by_default() {
        let policy = TlsPolicy::hardened();
        assert_eq!(policy.versions().len(), 2);
    }

    #[test]
    fn tls13_only_restricts_to_a_single_version() {
        let policy = TlsPolicy::hardened().tls13_only();
        assert_eq!(policy.versions(), &[&rustls::version::TLS13]);
    }

    #[test]
    fn default_matches_hardened() {
        let default_versions = TlsPolicy::default().versions().len();
        let hardened_versions = TlsPolicy::hardened().versions().len();
        assert_eq!(default_versions, hardened_versions);
    }

    #[test]
    fn debug_format_reports_negotiated_versions() {
        let both = format!("{:?}", TlsPolicy::hardened());
        assert!(both.contains("tls13: true"));
        assert!(both.contains("tls12: true"));

        let tls13_only = format!("{:?}", TlsPolicy::hardened().tls13_only());
        assert!(tls13_only.contains("tls13: true"));
        assert!(tls13_only.contains("tls12: false"));
    }

    /// Idempotent by design (rustls's process-wide default can only be installed once) — this
    /// just proves calling it repeatedly, including after another policy already raced to
    /// install first, never panics.
    #[test]
    fn install_as_process_default_is_idempotent() {
        TlsPolicy::hardened().install_as_process_default();
        TlsPolicy::hardened()
            .tls13_only()
            .install_as_process_default();
    }

    #[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
    #[test]
    fn server_config_from_pem_builds_a_working_config_from_a_self_signed_cert() {
        let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
            .expect("generate self-signed cert");

        let config = TlsPolicy::hardened()
            .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .expect("build server config from valid PEM");

        assert_eq!(config.alpn_protocols, crate::server::alpn_protocols(false));
    }

    #[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
    #[test]
    fn server_config_from_pem_rejects_garbage_input() {
        let err = TlsPolicy::hardened()
            .server_config_from_pem(b"not a certificate", b"not a key")
            .expect_err("garbage PEM must not build a config");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
    #[test]
    fn server_config_from_pem_rejects_a_key_that_does_not_match_the_cert() {
        let cert_a = crate::tls::generate_self_signed_cert(vec!["a.example".to_string()])
            .expect("generate cert a");
        let cert_b = crate::tls::generate_self_signed_cert(vec!["b.example".to_string()])
            .expect("generate cert b");

        let err = TlsPolicy::hardened()
            .server_config_from_pem(cert_a.cert_pem.as_bytes(), cert_b.key_pem.as_bytes())
            .expect_err("mismatched cert/key pair must not build a config");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
