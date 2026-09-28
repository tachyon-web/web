//! The crypto policy every TLS endpoint of a [`Server`](crate::Server) shares.

use rustls::SupportedProtocolVersion;
use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs};
use std::sync::Arc;

/// A TLS key-exchange group.
///
/// The variants a build has *are* its compliance profile: under `fips` only the groups FIPS
/// 140-3 approves exist (NIST P-curves and the `SECP256R1MLKEM768` hybrid; no X25519, and no
/// standalone ML-KEM, which SP 800-56C rev2 only sanctions as part of a hybrid), and under
/// `cnsa` only ML-KEM-1024 (CNSSP-15). Naming anything else there is a compile error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum KeyExchange {
    /// X25519 + ML-KEM-768 hybrid: what browsers offer for post-quantum key exchange.
    #[cfg(not(feature = "fips"))]
    X25519MlKem768,
    /// NIST P-256 + ML-KEM-768 hybrid.
    #[cfg(not(feature = "cnsa"))]
    Secp256r1MlKem768,
    /// ML-KEM-768 alone (FIPS 203).
    #[cfg(not(feature = "fips"))]
    MlKem768,
    /// ML-KEM-1024 alone (FIPS 203); the only group CNSA 2.0 permits.
    #[cfg(any(not(feature = "fips"), feature = "cnsa"))]
    MlKem1024,
    /// ECDHE over NIST P-384.
    #[cfg(not(feature = "cnsa"))]
    Secp384r1,
    /// ECDHE over X25519.
    #[cfg(not(feature = "fips"))]
    X25519,
    /// ECDHE over NIST P-256.
    #[cfg(not(feature = "cnsa"))]
    Secp256r1,
}

impl KeyExchange {
    /// Every group this build permits.
    #[cfg(test)]
    pub(crate) const ALL: &[Self] = &[
        #[cfg(not(feature = "fips"))]
        Self::X25519MlKem768,
        #[cfg(not(feature = "cnsa"))]
        Self::Secp256r1MlKem768,
        #[cfg(not(feature = "fips"))]
        Self::MlKem768,
        #[cfg(any(not(feature = "fips"), feature = "cnsa"))]
        Self::MlKem1024,
        #[cfg(not(feature = "cnsa"))]
        Self::Secp384r1,
        #[cfg(not(feature = "fips"))]
        Self::X25519,
        #[cfg(not(feature = "cnsa"))]
        Self::Secp256r1,
    ];

    /// This build's default, most preferred first.
    const DEFAULT: &[Self] = &[
        #[cfg(not(feature = "fips"))]
        Self::X25519MlKem768,
        #[cfg(not(feature = "cnsa"))]
        Self::Secp256r1MlKem768,
        #[cfg(any(not(feature = "fips"), feature = "cnsa"))]
        Self::MlKem1024,
        #[cfg(not(feature = "fips"))]
        Self::MlKem768,
        #[cfg(not(feature = "cnsa"))]
        Self::Secp384r1,
        #[cfg(not(feature = "fips"))]
        Self::X25519,
        #[cfg(not(feature = "cnsa"))]
        Self::Secp256r1,
    ];

    fn group(self) -> &'static dyn SupportedKxGroup {
        match self {
            #[cfg(not(feature = "fips"))]
            Self::X25519MlKem768 => aws_lc_rs::kx_group::X25519MLKEM768,
            #[cfg(not(feature = "cnsa"))]
            Self::Secp256r1MlKem768 => aws_lc_rs::kx_group::SECP256R1MLKEM768,
            #[cfg(not(feature = "fips"))]
            Self::MlKem768 => aws_lc_rs::kx_group::MLKEM768,
            #[cfg(any(not(feature = "fips"), feature = "cnsa"))]
            Self::MlKem1024 => aws_lc_rs::kx_group::MLKEM1024,
            #[cfg(not(feature = "cnsa"))]
            Self::Secp384r1 => aws_lc_rs::kx_group::SECP384R1,
            #[cfg(not(feature = "fips"))]
            Self::X25519 => aws_lc_rs::kx_group::X25519,
            #[cfg(not(feature = "cnsa"))]
            Self::Secp256r1 => aws_lc_rs::kx_group::SECP256R1,
        }
    }
}

/// A TLS AEAD cipher.
///
/// As with [`KeyExchange`], only the ciphers the build's profile permits exist: `fips` drops
/// ChaCha20-Poly1305 (not FIPS-approved), `cnsa` keeps AES-256-GCM alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Cipher {
    /// AES-256-GCM: `TLS_AES_256_GCM_SHA384`.
    Aes256Gcm,
    /// ChaCha20-Poly1305: `TLS_CHACHA20_POLY1305_SHA256`.
    #[cfg(not(feature = "fips"))]
    ChaCha20Poly1305,
    /// AES-128-GCM: `TLS_AES_128_GCM_SHA256`.
    #[cfg(not(feature = "cnsa"))]
    Aes128Gcm,
}

impl Cipher {
    /// Every cipher this build permits.
    #[cfg(test)]
    pub(crate) const ALL: &[Self] = &[
        Self::Aes256Gcm,
        #[cfg(not(feature = "fips"))]
        Self::ChaCha20Poly1305,
        #[cfg(not(feature = "cnsa"))]
        Self::Aes128Gcm,
    ];

    /// This build's default, most preferred first. `fips` keeps its historical AES-256 only.
    const DEFAULT: &[Self] = &[
        Self::Aes256Gcm,
        #[cfg(not(feature = "fips"))]
        Self::ChaCha20Poly1305,
        #[cfg(not(feature = "fips"))]
        Self::Aes128Gcm,
    ];

    const fn tls13(self) -> rustls::SupportedCipherSuite {
        match self {
            Self::Aes256Gcm => aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            #[cfg(not(feature = "fips"))]
            Self::ChaCha20Poly1305 => aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            #[cfg(not(feature = "cnsa"))]
            Self::Aes128Gcm => aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        }
    }

    #[cfg(feature = "tls12-legacy")]
    const fn tls12(self) -> [rustls::SupportedCipherSuite; 2] {
        use aws_lc_rs::cipher_suite as cs;
        match self {
            Self::Aes256Gcm => [
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            #[cfg(not(feature = "fips"))]
            Self::ChaCha20Poly1305 => [
                cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            #[cfg(not(feature = "cnsa"))]
            Self::Aes128Gcm => [
                cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
        }
    }
}

/// The crypto policy every TLS endpoint of a [`Server`](crate::Server) shares — clearnet HTTPS
/// and HTTP/3, `.onion` and `.b32.i2p` — set with
/// [`Server::tls_policy`](crate::Server::tls_policy).
///
/// ```rust
/// use tachyon_web::tls::{Cipher, KeyExchange, TlsPolicy};
///
/// # #[cfg(not(feature = "fips"))]
/// let policy = TlsPolicy::new()
///     .key_exchange([KeyExchange::X25519MlKem768, KeyExchange::X25519])
///     .ciphers([Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305]);
/// ```
///
/// # Compliance is a property of the build
///
/// Only what the build's profile permits can be named: see [`KeyExchange`] and [`Cipher`]. So
/// a `fips` or `cnsa` server cannot be configured out of compliance, and there is no way to
/// hand it a raw `rustls` config or provider. Under `cnsa` the profile is fixed: TLS 1.3,
/// `TLS_AES_256_GCM_SHA384`, ML-KEM-1024, and session resumption off.
///
/// # Preference order
///
/// Ciphers are chosen in **this server's** order, the first one the client also offers.
/// Key-exchange groups are a set: rustls's server picks the first group, in the *client's*
/// order, that is in it. To prefer post-quantum, leave the classical groups out rather than
/// listing them last.
///
/// # TLS 1.2
///
/// TLS 1.3 only, unless the `tls12-legacy` feature is enabled. That holds even when another
/// dependency enables `rustls/tls12` (`tor` does): the version exists in the binary but is
/// never offered here. `cnsa` and `tls12-legacy` cannot be combined.
#[derive(Clone, Debug)]
pub struct TlsPolicy {
    key_exchange: Vec<KeyExchange>,
    ciphers: Vec<Cipher>,
    versions: Vec<&'static SupportedProtocolVersion>,
    disable_resumption: bool,
}

impl TlsPolicy {
    /// This build's default policy.
    ///
    /// Without `fips`: hybrid post-quantum groups first (`X25519MLKEM768`, `SECP256R1MLKEM768`),
    /// then ML-KEM alone and the classical ECDHE groups for interoperability; AES-256-GCM, then
    /// ChaCha20-Poly1305, then AES-128-GCM. With `fips`: `SECP256R1MLKEM768`, P-384, P-256 and
    /// AES-256-GCM. With `cnsa`: the fixed CNSA 2.0 profile.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key_exchange: KeyExchange::DEFAULT.to_vec(),
            ciphers: Cipher::DEFAULT.to_vec(),
            versions: vec![
                &rustls::version::TLS13,
                #[cfg(feature = "tls12-legacy")]
                &rustls::version::TLS12,
            ],
            disable_resumption: cfg!(feature = "cnsa"),
        }
    }

    /// The key-exchange groups to accept. An empty list does not compile; a repeated group
    /// counts once.
    #[must_use]
    pub fn key_exchange<const N: usize>(mut self, groups: [KeyExchange; N]) -> Self {
        const { assert!(N > 0, "TlsPolicy::key_exchange needs at least one group") };
        self.key_exchange = unique(&groups);
        self
    }

    /// The ciphers to offer, most preferred first. An empty list does not compile; a repeated
    /// cipher counts once.
    ///
    /// ```rust,compile_fail
    /// let policy = tachyon_web::tls::TlsPolicy::new().ciphers([]);
    /// ```
    #[must_use]
    pub fn ciphers<const N: usize>(mut self, ciphers: [Cipher; N]) -> Self {
        const { assert!(N > 0, "TlsPolicy::ciphers needs at least one cipher") };
        self.ciphers = unique(&ciphers);
        self
    }

    /// Disables every session-resumption path: 0-RTT data, the stateful session cache, and
    /// TLS 1.3 session tickets. Every reconnect pays a full handshake, but there is no replay
    /// surface and no cross-connection linkability signal — worth it for anonymity endpoints.
    /// Default `false`; not available under `cnsa`, which always disables resumption.
    #[cfg(not(feature = "cnsa"))]
    #[must_use]
    pub const fn disable_resumption(mut self, disable: bool) -> Self {
        self.disable_resumption = disable;
        self
    }

    /// Stops offering TLS 1.2.
    #[cfg(feature = "tls12-legacy")]
    #[must_use]
    pub fn tls13_only(mut self) -> Self {
        self.versions = vec![&rustls::version::TLS13];
        self
    }

    /// Installs this policy's crypto provider as rustls's process-wide default, via
    /// [`CryptoProvider::install_default`].
    ///
    /// Only the first call in a process installs anything. Call it before bootstrapping your
    /// own arti `TorClient` for [`OnionConfig::client`](crate::tor::OnionConfig), so
    /// its relay TLS uses the build's validated module too. Keep that policy broad: many
    /// relays don't support post-quantum groups yet.
    pub fn install_as_process_default(&self) {
        let _ = self.build_provider().install_default();
    }

    fn build_provider(&self) -> CryptoProvider {
        let tls13 = self.ciphers.iter().map(|cipher| cipher.tls13());
        #[cfg(feature = "tls12-legacy")]
        let tls13 = tls13.chain(
            self.ciphers
                .iter()
                .filter(|_| self.versions.contains(&&rustls::version::TLS12))
                .flat_map(|cipher| cipher.tls12()),
        );
        CryptoProvider {
            cipher_suites: tls13.collect(),
            kx_groups: self.key_exchange.iter().map(|kx| kx.group()).collect(),
            ..aws_lc_rs::default_provider()
        }
    }

    /// The provider certificates' keys load through — under `fips` the validated module.
    pub(crate) fn provider(&self) -> Arc<CryptoProvider> {
        Arc::new(self.build_provider())
    }

    /// The shared prefix of every `rustls::ServerConfig` built from this policy.
    pub(crate) fn config_builder(
        &self,
    ) -> Result<
        rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>,
        crate::Error,
    > {
        rustls::ServerConfig::builder_with_provider(self.provider())
            .with_protocol_versions(&self.versions)
            .map(rustls::ConfigBuilder::<rustls::ServerConfig, _>::with_no_client_auth)
            .map_err(|e| crate::Error::config(format!("TLS configuration failed: {e}")))
    }

    /// Applies the server-side preference order and resumption setting, and freezes the
    /// config. Every config any listener serves goes through here.
    pub(crate) fn finalize(&self, mut config: rustls::ServerConfig) -> Arc<rustls::ServerConfig> {
        config.ignore_client_order = true;
        if self.disable_resumption {
            config.max_early_data_size = 0;
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            config.max_tls13_tickets = 0;
        }
        Arc::new(config)
    }
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// `items` in order, each first occurrence only.
fn unique<T: Copy + PartialEq>(items: &[T]) -> Vec<T> {
    let mut out = Vec::with_capacity(items.len());
    for &item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Cipher, KeyExchange, TlsPolicy};

    fn config(policy: &TlsPolicy) -> std::sync::Arc<rustls::ServerConfig> {
        let config = policy
            .config_builder()
            .expect("every policy builds")
            .with_cert_resolver(std::sync::Arc::new(
                rustls::server::ResolvesServerCertUsingSni::new(),
            ));
        policy.finalize(config)
    }

    fn shuffled<T: Copy>(items: &[T]) -> Vec<T> {
        let mut items = items.to_vec();
        rand::seq::SliceRandom::shuffle(items.as_mut_slice(), &mut rand::rng());
        items
    }

    /// The config carries exactly the chosen groups and ciphers, in the chosen order, and
    /// ciphers are picked in the server's order.
    #[test]
    fn a_policy_keeps_its_order_and_drops_repeats() {
        let groups = shuffled(KeyExchange::ALL);
        let ciphers = shuffled(Cipher::ALL);
        let policy = TlsPolicy {
            key_exchange: super::unique(&[groups.as_slice(), &groups].concat()),
            ciphers: super::unique(&[ciphers.as_slice(), &ciphers].concat()),
            ..TlsPolicy::new()
        };

        let config = config(&policy);
        let provider = config.crypto_provider();
        let names: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        let expected: Vec<_> = groups.iter().map(|g| g.group().name()).collect();
        assert_eq!(names, expected);
        let suites: Vec<_> = provider
            .cipher_suites
            .iter()
            .filter(|s| s.version() == &rustls::version::TLS13)
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        let expected: Vec<_> = ciphers.iter().map(|c| c.tls13().suite()).collect();
        assert_eq!(suites, expected);
        assert!(config.ignore_client_order);
    }

    /// Without `tls12-legacy` no policy offers TLS 1.2 — not the version, and not a suite to
    /// downgrade onto. Asserted on values: `tor` enables `rustls/tls12` through Cargo feature
    /// unification, and this proves that doesn't leak into what listeners offer.
    #[cfg(not(feature = "tls12-legacy"))]
    #[test]
    fn no_policy_offers_tls12_without_the_tls12_legacy_feature() {
        let policy = TlsPolicy::new();
        assert_eq!(policy.versions, [&rustls::version::TLS13]);
        for suite in &policy.provider().cipher_suites {
            assert_eq!(suite.version().version, rustls::ProtocolVersion::TLSv1_3);
        }
    }

    #[cfg(feature = "tls12-legacy")]
    #[test]
    fn tls13_only_drops_the_tls12_version_and_suites() {
        assert_eq!(TlsPolicy::new().versions.len(), 2);
        let policy = TlsPolicy::new().tls13_only();
        assert_eq!(policy.versions, [&rustls::version::TLS13]);
        for suite in &policy.provider().cipher_suites {
            assert_eq!(suite.version().version, rustls::ProtocolVersion::TLSv1_3);
        }
    }

    /// Every policy a `fips` build can express is approved by rustls's own predicate — the
    /// check that used to run at start-up, now proven for the whole type.
    #[cfg(feature = "fips")]
    #[test]
    fn every_expressible_policy_is_fips_approved() {
        let mut policy = TlsPolicy::new();
        assert!(config(&policy).fips());
        policy.key_exchange = shuffled(KeyExchange::ALL);
        policy.ciphers = shuffled(Cipher::ALL);
        assert!(config(&policy).fips());
        for &group in KeyExchange::ALL {
            for &cipher in Cipher::ALL {
                assert!(config(&TlsPolicy::new().key_exchange([group]).ciphers([cipher])).fips());
            }
        }
    }

    #[cfg(feature = "cnsa")]
    #[test]
    fn cnsa_is_one_fixed_profile() {
        let config = config(&TlsPolicy::new());
        let provider = config.crypto_provider();
        assert_eq!(
            provider
                .cipher_suites
                .iter()
                .map(rustls::SupportedCipherSuite::suite)
                .collect::<Vec<_>>(),
            [rustls::CipherSuite::TLS13_AES_256_GCM_SHA384]
        );
        assert_eq!(
            provider
                .kx_groups
                .iter()
                .map(|g| g.name())
                .collect::<Vec<_>>(),
            [rustls::NamedGroup::MLKEM1024]
        );
        assert_eq!(config.max_early_data_size, 0);
        assert!(!config.session_storage.can_cache());
    }

    #[cfg(not(feature = "cnsa"))]
    #[test]
    fn resumption_lockdown_disables_every_resumption_path() {
        let config = config(&TlsPolicy::new().disable_resumption(true));
        assert_eq!(config.max_early_data_size, 0);
        assert_eq!(config.send_tls13_tickets, 0);
        assert_eq!(config.max_tls13_tickets, 0);
        assert!(!config.session_storage.can_cache());
    }
}
