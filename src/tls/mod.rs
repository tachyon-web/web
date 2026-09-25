//! TLS termination: where certificates come from ([`Tls`]), which key algorithms they use
//! ([`KeyAlgorithm`]), how one is picked per handshake, and the crypto policy
//! ([`TlsPolicy`]).
//!
//! # Several certificates on one endpoint
//!
//! A [`Tls`] set may hold any mix of Let's Encrypt, self-signed and caller-provided
//! certificates. On each handshake the first one, **in the order they were added**, that the
//! client can verify is served: its name must match the client's SNI (when any certificate
//! does), and its signature algorithm must be among those the client offered
//! (RFC 8446 §4.2.3).
//!
//! That is the only signal TLS gives a server, and it has one consequence worth planning
//! around: a client cannot say *which trust anchor* it wants, only which algorithms it
//! verifies. A browser that verifies both P-256 and P-521 gets whichever comes first. So put
//! the CA-issued certificate browsers must see first, and let special clients reach the others
//! by what they offer:
//!
//! ```rust,no_run
//! # #[cfg(feature = "acme")] {
//! use tachyon_web::tls::{Acme, KeyAlgorithm, Tls};
//!
//! let tls = Tls::new()
//!     .domains(["example.com"])
//!     .store("/var/lib/tachyon/tls")
//!     // Browsers: CA-trusted ECDSA P-256.
//!     .acme(Acme::lets_encrypt().contact("admin@example.com"))
//!     // Post-quantum clients: they offer ML-DSA, which no browser does yet.
//!     .self_signed(KeyAlgorithm::MlDsa87)
//!     // Pinning clients: offer only `ecdsa_secp521r1_sha512` and get the pinned key.
//!     .self_signed(KeyAlgorithm::EcdsaP521);
//! # }
//! ```
//!
//! With a [`store`](Tls::store), self-signed keys persist across restarts, so a pin (or a
//! TEE attestation binding its SHA-256) stays valid. Every certificate served, with its
//! fingerprints and where it is used, is readable from [`ServerInfo`](crate::ServerInfo).

#[cfg(feature = "acme")]
pub(crate) mod acme;
pub(crate) mod certs;
mod der;
mod policy;
mod store;

#[cfg(feature = "acme")]
pub use acme::{Acme, AcmeKey};
pub use certs::{CertificateInfo, Issuer};
pub use policy::{Cipher, KeyExchange, TlsPolicy};

use std::path::PathBuf;

/// The key and signature algorithm of a generated certificate.
///
/// Browser support differs: every browser verifies P-256 and P-384; Chrome does not verify
/// P-521 at all; no browser verifies ML-DSA yet (`draft-ietf-tls-mldsa`). The ML-DSA
/// parameter sets are FIPS 204's.
///
/// A `cnsa` build has only [`MlDsa87`](Self::MlDsa87), so no other certificate can be
/// generated there.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// ECDSA over NIST P-256 with SHA-256.
    #[cfg(not(feature = "cnsa"))]
    EcdsaP256,
    /// ECDSA over NIST P-384 with SHA-384.
    #[cfg(not(feature = "cnsa"))]
    EcdsaP384,
    /// ECDSA over NIST P-521 with SHA-512.
    #[cfg(not(feature = "cnsa"))]
    EcdsaP521,
    /// ML-DSA-44 (NIST security category 2).
    #[cfg(not(feature = "cnsa"))]
    MlDsa44,
    /// ML-DSA-65 (NIST security category 3).
    #[cfg(not(feature = "cnsa"))]
    MlDsa65,
    /// ML-DSA-87 (NIST security category 5; the only one CNSA 2.0 permits).
    MlDsa87,
}

impl KeyAlgorithm {
    pub(crate) const ALL: &[Self] = &[
        #[cfg(not(feature = "cnsa"))]
        Self::EcdsaP256,
        #[cfg(not(feature = "cnsa"))]
        Self::EcdsaP384,
        #[cfg(not(feature = "cnsa"))]
        Self::EcdsaP521,
        #[cfg(not(feature = "cnsa"))]
        Self::MlDsa44,
        #[cfg(not(feature = "cnsa"))]
        Self::MlDsa65,
        Self::MlDsa87,
    ];

    pub(crate) fn rcgen(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP521 => &rcgen::PKCS_ECDSA_P521_SHA512,
            #[cfg(not(feature = "cnsa"))]
            Self::MlDsa44 => &rcgen::PKCS_ML_DSA_44,
            #[cfg(not(feature = "cnsa"))]
            Self::MlDsa65 => &rcgen::PKCS_ML_DSA_65,
            Self::MlDsa87 => &rcgen::PKCS_ML_DSA_87,
        }
    }

    pub(crate) const fn scheme(self) -> rustls::SignatureScheme {
        match self {
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP256 => rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP384 => rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP521 => rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            #[cfg(not(feature = "cnsa"))]
            Self::MlDsa44 => rustls::SignatureScheme::ML_DSA_44,
            #[cfg(not(feature = "cnsa"))]
            Self::MlDsa65 => rustls::SignatureScheme::ML_DSA_65,
            Self::MlDsa87 => rustls::SignatureScheme::ML_DSA_87,
        }
    }

    /// The algorithm behind `scheme`, or `None` for one this build cannot generate — which a
    /// `cnsa` build then refuses to serve.
    pub(crate) fn from_scheme(scheme: rustls::SignatureScheme) -> Option<Self> {
        Self::ALL.iter().copied().find(|alg| alg.scheme() == scheme)
    }

    /// A short stable name, used in certificate store file names.
    pub(crate) const fn tag(self) -> &'static str {
        match self {
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP256 => "p256",
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP384 => "p384",
            #[cfg(not(feature = "cnsa"))]
            Self::EcdsaP521 => "p521",
            #[cfg(not(feature = "cnsa"))]
            Self::MlDsa44 => "mldsa44",
            #[cfg(not(feature = "cnsa"))]
            Self::MlDsa65 => "mldsa65",
            Self::MlDsa87 => "mldsa87",
        }
    }
}

/// Where an endpoint's certificates come from, in preference order.
///
/// Used by [`Server::https`](crate::Server::https) and by the Tor and I2P configs. See the
/// [module docs](self) for how one certificate is chosen per handshake.
///
/// On an `.onion` or `.b32.i2p` endpoint the service address is always among the names, so
/// [`domains`](Self::domains) is only needed there for extra ones.
#[derive(Clone, Default)]
pub struct Tls {
    pub(crate) domains: Vec<String>,
    pub(crate) store: Option<PathBuf>,
    pub(crate) sources: Vec<Source>,
}

#[derive(Clone)]
pub(crate) enum Source {
    SelfSigned(KeyAlgorithm),
    Pem {
        cert: Vec<u8>,
        key: Vec<u8>,
    },
    PemFiles {
        cert: PathBuf,
        key: PathBuf,
    },
    #[cfg(feature = "acme")]
    Acme(Acme),
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sources: Vec<String> = self
            .sources
            .iter()
            .map(|source| match source {
                Source::SelfSigned(alg) => format!("SelfSigned({alg:?})"),
                Source::Pem { .. } => "Pem".to_string(),
                Source::PemFiles { cert, .. } => format!("PemFiles({})", cert.display()),
                #[cfg(feature = "acme")]
                Source::Acme(acme) => format!("{acme:?}"),
            })
            .collect();
        f.debug_struct("Tls")
            .field("domains", &self.domains)
            .field("store", &self.store)
            .field("sources", &sources)
            .finish()
    }
}

impl Tls {
    /// An empty set. Add at least one certificate source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The DNS names (or IP literals) this endpoint serves. They become the SANs of generated
    /// certificates, the identifiers of ACME orders, and the default host allow-list. A leading
    /// `*.` is a wildcard for self-signed certificates only.
    #[must_use]
    pub fn domains(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.domains = names.into_iter().map(Into::into).collect();
        self
    }

    /// Persists generated keys, issued certificates and ACME account credentials in `dir`.
    ///
    /// Required for [`acme`](Self::acme). Without it self-signed certificates are regenerated on
    /// every start, so nothing can pin them. The directory is created `0700` if missing and
    /// refused if it is a symlink, grants group or other access, or belongs to another user.
    #[must_use]
    pub fn store(mut self, dir: impl Into<PathBuf>) -> Self {
        self.store = Some(dir.into());
        self
    }

    /// Adds a self-signed certificate for this endpoint's names, generated with `algorithm`.
    #[must_use]
    pub fn self_signed(mut self, algorithm: KeyAlgorithm) -> Self {
        self.sources.push(Source::SelfSigned(algorithm));
        self
    }

    /// Adds a certificate chain and private key, both PEM. The key may be PKCS#8, PKCS#1 or
    /// SEC1. Under `cnsa` it must be ML-DSA-87, checked when the server starts.
    #[must_use]
    pub fn pem(mut self, cert_chain: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Self {
        self.sources.push(Source::Pem {
            cert: cert_chain.into(),
            key: key.into(),
        });
        self
    }

    /// As [`pem`](Self::pem), read from files when the server starts.
    #[must_use]
    pub fn pem_files(mut self, cert_chain: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.sources.push(Source::PemFiles {
            cert: cert_chain.into(),
            key: key.into(),
        });
        self
    }

    /// Adds a certificate issued and renewed in-process by an ACME CA. Needs a
    /// [`store`](Self::store), [`domains`](Self::domains), and a
    /// [`Server::redirect`](crate::Server::redirect) listener on port 80 to answer HTTP-01.
    #[cfg(feature = "acme")]
    #[must_use]
    pub fn acme(mut self, acme: Acme) -> Self {
        self.sources.push(Source::Acme(acme));
        self
    }
}

/// PEM parsing, on `rustls-pki-types`' own `PemObject` implementation.
pub(crate) mod pem {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    /// Parses a PEM certificate chain. A malformed entry is an error rather than skipped: a
    /// silently shortened chain fails only later, on clients.
    pub(crate) fn certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, crate::Error> {
        let chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| crate::Error::certificate(format!("invalid certificate PEM: {e}")))?;
        if chain.is_empty() {
            return Err(crate::Error::certificate("no certificate found in PEM"));
        }
        Ok(chain)
    }

    /// Parses the first private key in a PEM blob.
    pub(crate) fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, crate::Error> {
        PrivateKeyDer::from_pem_slice(pem)
            .map_err(|e| crate::Error::certificate(format!("invalid private key PEM: {e}")))
    }
}
