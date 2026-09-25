//! A crypto/TLS policy shared across every listener a [`Server`](crate::Server) runs.

use rustls::SupportedProtocolVersion;
use rustls::crypto::CryptoProvider;
use std::sync::Arc;

/// A crypto provider + protocol-version policy shared across every listener a
/// [`Server`](crate::Server) runs.
///
/// Set it once via [`Server::tls_policy`](crate::Server::tls_policy) and it covers every TLS
/// endpoint the server runs — clearnet HTTPS and HTTP/3, `.onion` and `.b32.i2p` — and the keys
/// their certificates are loaded with.
///
/// # `tls12-legacy`
///
/// **TLS 1.3 is the only protocol version this crate offers unless the `tls12-legacy`
/// feature is enabled.** Every policy this type can build — default, `fips`, `cnsa`, or one
/// wrapped around a caller's own [`CryptoProvider`] — negotiates 1.3 only and carries no TLS
/// 1.2 cipher suite to downgrade onto.
///
/// That holds even when another dependency enables `rustls/tls12` (`tor` does, via
/// `tor-rtcompat`, for arti's relay links): TLS 1.2 then exists in the binary, but this policy
/// never offers it. `tls12-legacy` is also what gives the FIPS profile's extended-master-secret
/// requirement (FIPS 140-3 IG D.Q) anything to act on, since EMS is a TLS 1.2 extension.
///
/// # `fips`
///
/// With the `fips` feature, [`new`](Self::new)/[`Default::default`] always build a FIPS 140-3
/// Level 1 validated software provider in approved mode — AES-256-GCM only; NIST P-curves
/// plus the `SECP256R1MLKEM768` hybrid, no X25519 and no standalone ML-KEM. `with_provider`
/// doesn't compile under `fips`, so no other provider can be plugged in.
///
/// # The Tor relay/channel layer is a separate concern
///
/// This policy governs TLS *termination*. arti's outbound TLS to Tor relays instead uses
/// rustls's *process-wide* default provider; [`install_as_process_default`] sets it, and a
/// server with an onion endpoint calls it before bootstrapping its own Tor client.
///
/// A PQ-only or single-suite policy is fine for termination but can break Tor bootstrap when
/// installed process-wide, since many relays don't support hybrid PQ groups yet. Prefer PQ;
/// don't require it there.
///
/// [`install_as_process_default`]: Self::install_as_process_default
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

/// TLS 1.3, plus TLS 1.2 under `tls12-legacy`. Gated on this crate's feature, not rustls's,
/// so a dependency enabling `rustls/tls12` can't widen what these listeners offer.
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

    /// The FIPS 140-3 Level 1 approved-mode software policy: AES-256-GCM suites only, and NIST
    /// P-curves plus the `SECP256R1MLKEM768` hybrid.
    ///
    /// No X25519, which isn't approved for key agreement (SP 800-56A rev3), and no standalone
    /// ML-KEM, since SP 800-56C rev2 only sanctions a hybrid `Z' = Z || T`. That is stricter
    /// than rustls's own `fips()` predicate; the `cnsa` profile takes rustls's reading.
    ///
    /// Under `fips` this is also what [`new`](Self::new) builds.
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
    /// group, and all session resumption disabled. A `cnsa` build accepts only ML-DSA-87
    /// certificates, generated or provided. The feature implies `fips`, so AWS-LC also runs in its FIPS
    /// 140-3 Level 1 approved software mode.
    ///
    /// # This is deliberately *not* the `fips` profile
    ///
    /// CNSA 2.0 (CNSSP-15) requires bare ML-KEM-1024, which the `fips` profile's reading of SP
    /// 800-56C rejects. A `cnsa` build runs the FIPS-validated *module* but negotiates a key
    /// exchange that profile would refuse; rustls itself counts bare ML-KEM as approved in FIPS
    /// mode, which is why `assert_fips_server_config` accepts it. If you answer to FIPS 140-3
    /// rather than CNSA 2.0, build with `fips` alone.
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
    /// Only has an effect under `tls12-legacy`; otherwise this is already the case.
    #[must_use]
    pub fn tls13_only(mut self) -> Self {
        self.versions = vec![&rustls::version::TLS13];
        self
    }

    /// Enables or disables the strict replay lockdown.
    ///
    /// When enabled, server configurations built from this policy reject TLS 0-RTT data and
    /// disable both stateful session caching and TLS 1.3 session tickets: every reconnect pays a
    /// full handshake, but there is no replay surface and no cross-connection linkability
    /// signal — worth it for anonymity endpoints. The default is `false`; `cnsa` forces `true`.
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

    fn apply_to_server_config(&self, config: &mut rustls::ServerConfig) {
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
    /// Only the first call in a process installs anything; later ones, even with a different
    /// policy, are ignored. Call it before bootstrapping an arti `TorClient` so its relay TLS
    /// uses this provider too — see the [type docs](Self).
    pub fn install_as_process_default(&self) {
        let _ = (*self.provider).clone().install_default();
    }

    /// The shared prefix of every `rustls::ServerConfig` built from this policy: its provider
    /// and protocol versions, and no client auth.
    pub(crate) fn config_builder(
        &self,
    ) -> Result<
        rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>,
        crate::Error,
    > {
        rustls::ServerConfig::builder_with_provider(self.provider())
            .with_protocol_versions(&self.versions)
            .map(rustls::ConfigBuilder::<rustls::ServerConfig, _>::with_no_client_auth)
            .map_err(|e| crate::Error::config(format!("TLS version configuration failed: {e}")))
    }

    /// Applies this policy's resumption setting to a finished config and freezes it. Every
    /// config any listener serves goes through here.
    pub(crate) fn finalize(&self, mut config: rustls::ServerConfig) -> Arc<rustls::ServerConfig> {
        self.apply_to_server_config(&mut config);
        Arc::new(config)
    }
}

/// Rejects a config that does not itself negotiate FIPS-approved algorithms. `fips()` is
/// rustls's own predicate: an approved provider *and* `require_ems` (FIPS 140-3 IG D.Q, which
/// only bites under `tls12-legacy`).
#[cfg(feature = "fips")]
pub(crate) fn assert_fips_server_config(config: &rustls::ServerConfig) -> Result<(), crate::Error> {
    if !config.fips() {
        return Err(crate::Error::config(
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
            return Err(crate::Error::config(
                "TLS config violates the compile-time CNSA profile: require TLS 1.3 \
                 AES-256-GCM-SHA384, ML-KEM-1024, and disabled session resumption",
            ));
        }
    }

    Ok(())
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Tachyon's default `CryptoProvider`, computed once and shared — see [`TlsPolicy::new`].
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

            // TLS 1.2 suites only under `tls12-legacy` — see `default_versions`.
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

/// Tachyon's FIPS approved-mode `CryptoProvider`, computed once and shared — see
/// [`TlsPolicy::fips`].
#[cfg(all(feature = "fips", not(feature = "cnsa")))]
fn fips_provider() -> Arc<CryptoProvider> {
    static FIPS_PROVIDER: std::sync::OnceLock<Arc<CryptoProvider>> = std::sync::OnceLock::new();
    FIPS_PROVIDER
        .get_or_init(|| {
            // No standalone ML-KEM: see `TlsPolicy::fips`.
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

    #[test]
    fn resumption_lockdown_disables_every_resumption_path() {
        let config = TlsPolicy::new()
            .disable_resumption(true)
            .config_builder()
            .expect("builder")
            .with_cert_resolver(std::sync::Arc::new(
                rustls::server::ResolvesServerCertUsingSni::new(),
            ));
        let config = TlsPolicy::new().disable_resumption(true).finalize(config);

        assert_eq!(config.max_early_data_size, 0);
        assert_eq!(config.send_tls13_tickets, 0);
        assert_eq!(config.max_tls13_tickets, 0);
        assert!(!config.session_storage.can_cache());
    }
}
