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
/// # `tls12-legacy`
///
/// **TLS 1.3 is the only protocol version this crate offers unless the `tls12-legacy`
/// feature is enabled.** Every policy this type can build — default, `fips`, `cnsa`, or one
/// wrapped around a caller's own [`CryptoProvider`] — negotiates 1.3 and nothing else, and
/// carries no TLS 1.2 cipher suite for a peer to downgrade onto. Enable `tls12-legacy` only
/// for a deployment that genuinely has to serve clients with no TLS 1.3.
///
/// The feature also switches on `rustls/tls12`, so in a build without it TLS 1.2 is usually
/// absent outright rather than merely unselected. That second, stronger property depends on
/// the rest of your dependency graph and is **not** something this crate can promise: Cargo
/// unifies features, and `tor` pulls in `tor-rtcompat`, which enables `rustls/tls12` for
/// arti's own relay/channel link layer. In such a build `rustls::version::TLS12` exists
/// again — but this policy still never offers it, which is the guarantee that actually
/// governs what a client can negotiate with your listeners.
///
/// Note that `tls12-legacy` is also what gives the FIPS profile's extended-master-secret
/// requirement (FIPS 140-3 IG D.Q) anything to act on: EMS is a TLS 1.2 extension, so in a
/// 1.3-only build it is vacuous.
///
/// # `fips`
///
/// With the `fips` feature enabled, [`new`](Self::new)/[`Default::default`] always build a
/// FIPS 140-3 Level 1 validated software provider in approved mode — AES-256-GCM only; NIST SECP
/// curves and ML-KEM only, no X25519. There is no fallback and no override: under `fips`,
/// `TlsPolicy::with_provider` and `Server::crypto_provider` don't compile, so a
/// non-compliant provider can't be plugged in even by mistake — the only `CryptoProvider` a
/// `TlsPolicy` can ever hold under that feature is the FIPS one.
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
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Clone)]
pub struct TlsPolicy {
    provider: Arc<CryptoProvider>,
    versions: Vec<&'static SupportedProtocolVersion>,
    disable_resumption: bool,
}

impl std::fmt::Debug for TlsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("TlsPolicy");
        let _ = out.field("tls13", &self.versions.contains(&&rustls::version::TLS13));
        #[cfg(feature = "tls12-legacy")]
        let _ = out.field("tls12", &self.versions.contains(&&rustls::version::TLS12));
        #[cfg(not(feature = "tls12-legacy"))]
        let _ = out.field("tls12", &"unavailable (no `tls12-legacy` feature)");
        out.field("disable_resumption", &self.disable_resumption)
            .finish_non_exhaustive()
    }
}

/// The version list every constructor below starts from.
///
/// TLS 1.3 alone unless `tls12-legacy` is enabled, in which case TLS 1.2 follows it as a
/// fallback. The gate is deliberately on *this crate's* feature rather than on
/// `cfg(feature = "tls12")` reaching rustls: a dependency that enables `rustls/tls12` for
/// its own purposes (`tor` does, via `tor-rtcompat`) must not thereby put TLS 1.2 back into
/// what these listeners offer.
#[cfg(not(feature = "cnsa"))]
fn default_versions() -> Vec<&'static SupportedProtocolVersion> {
    vec![
        &rustls::version::TLS13,
        #[cfg(feature = "tls12-legacy")]
        &rustls::version::TLS12,
    ]
}

impl TlsPolicy {
    /// Tachyon's default TLS policy.
    ///
    /// Without the `fips` feature: hybrid post-quantum key-exchange groups preferred
    /// (`X25519MLKEM768`, `SECP256R1MLKEM768`, `MLKEM1024`, `MLKEM768`), falling back to
    /// classical ECDHE groups (`SECP384R1`, `X25519`, `SECP256R1`) for interoperability;
    /// AES-256-GCM and ChaCha20-Poly1305 preferred over AES-128.
    ///
    /// With `fips`, this is the restricted FIPS policy. With `cnsa`, the stricter CNSA policy
    /// takes precedence.
    ///
    /// **TLS 1.3 only**, unless the `tls12-legacy` feature is enabled — see the
    /// [type docs](Self#tls12-legacy).
    #[must_use]
    pub fn new() -> Self {
        #[cfg(feature = "cnsa")]
        {
            Self::cnsa()
        }
        #[cfg(all(feature = "fips", not(feature = "cnsa")))]
        {
            Self::fips()
        }
        #[cfg(not(feature = "fips"))]
        {
            Self {
                provider: default_provider(),
                versions: default_versions(),
                disable_resumption: false,
            }
        }
    }

    /// Builds a policy from a fully custom [`CryptoProvider`] — for example one pinned to
    /// `TLS13_AES_256_GCM_SHA384` only.
    ///
    /// Negotiates TLS 1.3 only unless `tls12-legacy` is enabled. A TLS 1.2 suite in
    /// `provider` is inert without that feature — the version is never offered, so there is
    /// no handshake it can apply to.
    ///
    /// Not available with the `fips` feature enabled — see the [type docs](Self#fips).
    #[cfg(not(feature = "fips"))]
    #[must_use]
    pub fn with_provider(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            versions: default_versions(),
            disable_resumption: false,
        }
    }

    /// The FIPS 140-3 Level 1 approved-mode software policy: AES-256-GCM cipher suites only (no ChaCha20-Poly1305
    /// or AES-128), and only NIST SECP curves / the hybrid `SECP256R1MLKEM768` key-exchange
    /// group — no X25519 in any form, since RFC 7748 Curve25519 isn't FIPS-140-3-approved for
    /// key agreement (NIST SP 800-186 vs SP 800-56Arev3), and no standalone ML-KEM group,
    /// since SP 800-56C rev2 only sanctions a *hybrid* Z' = Z || T built from an approved SP
    /// 800-56A/B scheme — bare ML-KEM doesn't qualify on its own. This is stricter than
    /// rustls's own `fips()` predicate, which accepts bare ML-KEM once the module is in FIPS
    /// mode; [`cnsa`](Self::cnsa) takes rustls's reading instead, and the two profiles are
    /// mutually exclusive for that reason — see [`cnsa`](Self::cnsa)'s docs.
    ///
    /// Requires the `fips` feature, under which this is also what [`new`](Self::new) and
    /// [`Default::default`] build — see the [type docs](Self#fips) for why it's the only
    /// provider a `TlsPolicy` can hold in that build.
    #[cfg(all(feature = "fips", not(feature = "cnsa")))]
    #[must_use]
    pub fn fips() -> Self {
        Self {
            provider: fips_provider(),
            versions: default_versions(),
            disable_resumption: false,
        }
    }

    /// Strict CNSA 2.0 TLS profile for controlled, non-browser clients.
    ///
    /// This is TLS 1.3 with `TLS_AES_256_GCM_SHA384`, ML-KEM-1024 as the sole key-exchange
    /// group, and all session resumption disabled. Certificate constructors in a `cnsa` build
    /// generate ML-DSA-87 keys. The feature implies `fips`, so AWS-LC also runs in its FIPS
    /// 140-3 Level 1 approved software mode.
    ///
    /// # This is deliberately *not* the [`fips`](Self::fips) profile
    ///
    /// The two profiles disagree, and CNSA wins here by design. `fips` excludes standalone
    /// ML-KEM because SP 800-56C rev2 only sanctions a hybrid `Z' = Z || T`; CNSA 2.0
    /// (CNSSP-15) requires bare ML-KEM-1024 and treats a classical hybrid as optional at
    /// most. A `cnsa` build therefore runs the FIPS-validated *module* while negotiating a
    /// key-exchange the `fips` profile's own reading of SP 800-56C would reject. If the
    /// compliance regime you answer to is FIPS 140-3 rather than CNSA 2.0, build with `fips`
    /// alone and do not enable `cnsa`.
    ///
    /// rustls itself reports bare ML-KEM as FIPS-approved whenever the backing module is in
    /// FIPS mode — see its `MlKem::fips` auditor note, which reads AWS-LC-FIPS's FIPS-pending
    /// ML-KEM as usable under regimes such as `FedRAMP` rev 5 SC-13. That is why
    /// `assert_fips_server_config` accepts this profile rather than rejecting it.
    #[cfg(feature = "cnsa")]
    #[must_use]
    pub fn cnsa() -> Self {
        Self {
            provider: cnsa_provider(),
            versions: vec![&rustls::version::TLS13],
            disable_resumption: true,
        }
    }

    /// Restricts this policy to TLS 1.3 only.
    ///
    /// This is already the default. TLS 1.2 is offered only when the `tls12-legacy` feature
    /// is enabled, and in a build without it this method is a no-op kept for source
    /// compatibility — there is no TLS 1.2 in the binary for it to remove.
    #[must_use]
    pub fn tls13_only(mut self) -> Self {
        self.versions = vec![&rustls::version::TLS13];
        self
    }

    /// Enables or disables the strict replay lockdown.
    ///
    /// When enabled, server configurations built from this policy reject TLS 0-RTT data and
    /// disable both stateful session caching and TLS 1.3 session tickets. The default is
    /// `false` so callers can choose the interoperability/performance tradeoff explicitly.
    #[must_use]
    pub const fn disable_resumption(mut self, disable: bool) -> Self {
        #[cfg(feature = "cnsa")]
        {
            let _ = disable;
            self.disable_resumption = true;
            self
        }
        #[cfg(not(feature = "cnsa"))]
        {
            self.disable_resumption = disable;
            self
        }
    }

    pub(crate) fn apply_to_server_config(&self, config: &mut rustls::ServerConfig) {
        if self.disable_resumption {
            config.max_early_data_size = 0;
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            config.max_tls13_tickets = 0;
        }
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

        #[cfg(feature = "cnsa")]
        crate::server::tls_config::assert_cnsa_identity(&cert_chain, &key_der)?;

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
        self.apply_to_server_config(&mut server_config);
        Ok(server_config)
    }
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Tachyon's default `CryptoProvider` (non-`fips` builds only): hybrid post-quantum
/// key-exchange groups preferred, AES-256-GCM/ChaCha20-Poly1305 preferred over AES-128,
/// computed once and shared.
#[cfg(not(feature = "fips"))]
fn default_provider() -> Arc<CryptoProvider> {
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

            // The TLS 1.2 suites are listed only under `tls12-legacy`. Gating on this crate's
            // own feature, not on rustls's, is what keeps a dependency that enables
            // `rustls/tls12` for itself (`tor` does) from widening what we offer.
            let cipher_suites = vec![
                // TLS 1.3
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
                // TLS 1.2
                #[cfg(feature = "tls12-legacy")]
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                #[cfg(feature = "tls12-legacy")]
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                #[cfg(feature = "tls12-legacy")]
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                #[cfg(feature = "tls12-legacy")]
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                #[cfg(feature = "tls12-legacy")]
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                #[cfg(feature = "tls12-legacy")]
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

/// Tachyon's FIPS 140-3 Level 1 approved-mode software `CryptoProvider`: AES-256-GCM cipher suites only, and only
/// NIST SECP curves / ML-KEM key-exchange groups — computed once and shared. See
/// [`TlsPolicy::fips`] for why each algorithm was chosen.
#[cfg(all(feature = "fips", not(feature = "cnsa")))]
fn fips_provider() -> Arc<CryptoProvider> {
    static FIPS_PROVIDER: std::sync::OnceLock<Arc<CryptoProvider>> = std::sync::OnceLock::new();
    FIPS_PROVIDER
        .get_or_init(|| {
            // Deliberately excludes standalone `MLKEM768`/`MLKEM1024`: SP 800-56C rev2 only
            // sanctions a hybrid shared secret Z' = Z || T built from an SP 800-56A/B scheme,
            // which `SECP256R1MLKEM768` satisfies (classical-first, so its FIPS status tracks
            // the approved NIST curve) but bare ML-KEM as the sole key-establishment scheme
            // does not — see `TlsPolicy::fips`'s docs.
            let kx_groups = vec![
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768,
                rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            ];

            let cipher_suites = vec![
                // TLS 1.3
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                // TLS 1.2 — only under `tls12-legacy`, see `default_versions`.
                #[cfg(feature = "tls12-legacy")]
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                #[cfg(feature = "tls12-legacy")]
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ];

            Arc::new(CryptoProvider {
                cipher_suites,
                kx_groups,
                ..rustls::crypto::aws_lc_rs::default_provider()
            })
        })
        .clone()
}

#[cfg(feature = "cnsa")]
fn cnsa_provider() -> Arc<CryptoProvider> {
    static CNSA_PROVIDER: std::sync::OnceLock<Arc<CryptoProvider>> = std::sync::OnceLock::new();
    CNSA_PROVIDER
        .get_or_init(|| {
            Arc::new(CryptoProvider {
                cipher_suites: vec![
                    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                ],
                kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM1024],
                ..rustls::crypto::aws_lc_rs::default_provider()
            })
        })
        .clone()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::TlsPolicy;

    /// Without `tls12-legacy`, no policy this type can build may offer TLS 1.2 — not the
    /// version, and not a 1.2 cipher suite to downgrade onto.
    ///
    /// Deliberately asserted on the *values*, not on `cfg(feature = "tls12")`: Cargo unifies
    /// features, and `tor` enables `rustls/tls12` for arti's relay link layer. This test is
    /// what proves that unification does not leak back into what the listeners offer, so it
    /// must keep passing in a build where `rustls::version::TLS12` exists.
    #[cfg(all(not(feature = "cnsa"), not(feature = "tls12-legacy")))]
    #[test]
    fn no_policy_offers_tls12_without_the_tls12_legacy_feature() {
        let policies = [TlsPolicy::new(), TlsPolicy::new().tls13_only()];
        for policy in policies {
            assert_eq!(policy.versions(), &[&rustls::version::TLS13]);
            for suite in &policy.provider().cipher_suites {
                assert_eq!(
                    suite.version().version,
                    rustls::ProtocolVersion::TLSv1_3,
                    "a non-TLS-1.3 cipher suite survived into a build without \
                     `tls12-legacy`: {suite:?}"
                );
            }
        }
    }

    #[cfg(all(not(feature = "cnsa"), feature = "tls12-legacy"))]
    #[test]
    fn new_offers_both_tls_versions_under_tls12_legacy() {
        let policy = TlsPolicy::new();
        assert_eq!(
            policy.versions(),
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        );
    }

    #[test]
    fn tls13_only_restricts_to_a_single_version() {
        let policy = TlsPolicy::new().tls13_only();
        assert_eq!(policy.versions(), &[&rustls::version::TLS13]);
    }

    #[cfg(all(feature = "fips", not(feature = "cnsa")))]
    #[test]
    fn new_is_fips_by_default_under_the_fips_feature() {
        assert_eq!(
            TlsPolicy::new().provider().cipher_suites,
            TlsPolicy::fips().provider().cipher_suites
        );
    }

    #[cfg(all(feature = "fips", not(feature = "cnsa")))]
    #[test]
    fn fips_offers_only_aes_256_cipher_suites() {
        let provider = TlsPolicy::fips().provider();
        for suite in &provider.cipher_suites {
            let name = format!("{suite:?}");
            assert!(
                name.contains("AES_256"),
                "non-AES-256 cipher suite offered under fips: {name}"
            );
            assert!(
                !name.contains("CHACHA20") && !name.contains("AES_128"),
                "non-compliant cipher suite offered under fips: {name}"
            );
        }
    }

    #[cfg(all(feature = "fips", not(feature = "cnsa")))]
    #[test]
    fn fips_offers_only_secp_and_hybrid_mlkem_kx_groups() {
        let provider = TlsPolicy::fips().provider();
        for group in &provider.kx_groups {
            let name = format!("{:?}", group.name()).to_ascii_uppercase();
            assert!(
                !name.contains("X25519"),
                "X25519 is not FIPS-140-3-approved for key agreement, but was offered: {name}"
            );
            assert!(
                name == "SECP256R1MLKEM768" || !name.contains("MLKEM"),
                "standalone ML-KEM isn't a sanctioned SP 800-56C hybrid, but was offered: {name}"
            );
        }
    }

    #[cfg(all(not(feature = "cnsa"), feature = "tls12-legacy"))]
    #[test]
    fn debug_format_reports_negotiated_versions() {
        let both = format!("{:?}", TlsPolicy::new());
        assert!(both.contains("tls13: true"));
        assert!(both.contains("tls12: true"));

        let tls13_only = format!("{:?}", TlsPolicy::new().tls13_only());
        assert!(tls13_only.contains("tls13: true"));
        assert!(tls13_only.contains("tls12: false"));
    }

    #[cfg(not(feature = "tls12-legacy"))]
    #[test]
    fn debug_format_says_tls12_is_unavailable() {
        let rendered = format!("{:?}", TlsPolicy::new());
        assert!(rendered.contains("tls13: true"));
        assert!(rendered.contains("tls12-legacy"), "got {rendered}");
    }

    /// Idempotent by design (rustls's process-wide default can only be installed once) — this
    /// just proves calling it repeatedly, including after another policy already raced to
    /// install first, never panics.
    #[test]
    fn install_as_process_default_is_idempotent() {
        TlsPolicy::new().install_as_process_default();
        TlsPolicy::new().tls13_only().install_as_process_default();
    }

    #[cfg(feature = "cnsa")]
    #[test]
    fn cnsa_is_narrow_and_disables_resumption() {
        let policy = TlsPolicy::new().disable_resumption(false);
        assert_eq!(policy.versions(), &[&rustls::version::TLS13]);
        assert_eq!(policy.provider().cipher_suites.len(), 1);
        assert_eq!(
            policy
                .provider()
                .cipher_suites
                .first()
                .map(rustls::SupportedCipherSuite::suite),
            Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
        );
        assert_eq!(policy.provider().kx_groups.len(), 1);
        assert_eq!(
            policy
                .provider()
                .kx_groups
                .first()
                .map(|group| group.name()),
            Some(rustls::NamedGroup::MLKEM1024)
        );
        assert!(policy.disable_resumption);
    }

    #[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
    #[test]
    fn server_config_from_pem_builds_a_working_config_from_a_self_signed_cert() {
        let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
            .expect("generate self-signed cert");

        let config = TlsPolicy::new()
            .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .expect("build server config from valid PEM");

        assert_eq!(config.alpn_protocols, crate::server::alpn_protocols(false));
    }

    #[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
    #[test]
    fn resumption_lockdown_disables_every_resumption_path() {
        let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let config = TlsPolicy::new()
            .disable_resumption(true)
            .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .expect("build server config");

        assert_eq!(config.max_early_data_size, 0);
        assert_eq!(config.send_tls13_tickets, 0);
        assert_eq!(config.max_tls13_tickets, 0);
        assert!(!config.session_storage.can_cache());
    }

    #[cfg(all(feature = "cert-gen", any(feature = "tor", feature = "i2p")))]
    #[test]
    fn server_config_from_pem_rejects_garbage_input() {
        let err = TlsPolicy::new()
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

        let err = TlsPolicy::new()
            .server_config_from_pem(cert_a.cert_pem.as_bytes(), cert_b.key_pem.as_bytes())
            .expect_err("mismatched cert/key pair must not build a config");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
