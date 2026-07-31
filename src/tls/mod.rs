//! TLS helper utilities.

#[cfg(feature = "cert-gen")]
mod cert_gen {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// A self-signed TLS certificate with both PEM and DER representations.
    #[derive(Debug)]
    pub struct SelfSignedCert {
        /// Certificate in PEM format.
        pub cert_pem: String,
        /// Private key in PEM format.
        pub key_pem: String,
        /// Certificate in DER format.
        pub cert_der: CertificateDer<'static>,
        /// Private key in DER format.
        pub key_der: PrivateKeyDer<'static>,
    }

    /// Generates an ephemeral self-signed ECDSA P-384 certificate for the given domains.
    /// Useful for bootstrapping development servers or testing TLS connections without a real CA.
    ///
    /// # Errors
    ///
    /// Returns an error if generating the key pair or signing the certificate fails.
    pub fn generate_self_signed_cert(domains: Vec<String>) -> Result<SelfSignedCert, rcgen::Error> {
        let params = CertificateParams::new(domains)?;
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        let cert = params.self_signed(&key_pair)?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        Ok(SelfSignedCert {
            cert_pem,
            key_pem,
            cert_der,
            key_der,
        })
    }
}

#[cfg(feature = "cert-gen")]
pub use cert_gen::{SelfSignedCert, generate_self_signed_cert};

/// PEM parsing, on `rustls-pki-types`' own [`PemObject`] implementation.
///
/// This replaces the `rustls-pemfile` crate, which was archived in August 2025 and flagged
/// unmaintained by RUSTSEC-2025-0134. That crate's final release was already a thin wrapper
/// around exactly this code — `rustls-pki-types` has carried the PEM parser since 1.9.0 — so
/// dropping it removes a dependency without changing which parser actually runs.
///
/// [`PemObject`]: rustls::pki_types::pem::PemObject
// `unreachable_pub` (rustc) requires these items be `pub(crate)` rather than `pub`, while
// `clippy::redundant_pub_crate` calls `pub(crate)` redundant inside a `pub(crate)` module.
// The two lints directly contradict each other here; rustc's wins, and clippy's is silenced.
#[cfg(feature = "tls")]
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod pem {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    /// Parses a PEM certificate chain, skipping entries that fail to parse.
    ///
    /// Skipping rather than failing is the behavior the `rustls_pemfile::certs(..)`
    /// `.filter_map(Result::ok)` call this replaces already had at every call site, kept
    /// deliberately: a chain whose *leaf* parses is servable even if a later entry is
    /// malformed, and `with_single_cert` rejects an empty chain anyway.
    pub(crate) fn certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem)
            .filter_map(std::result::Result::ok)
            .collect()
    }

    /// Parses the first private key in a PEM blob, in any of the PKCS#1/PKCS#8/SEC1 encodings
    /// `PrivateKeyDer` understands.
    ///
    /// # Errors
    ///
    /// Returns [`rustls::pki_types::pem::Error`] if no key is present or it cannot be parsed.
    /// Note the shape change from `rustls_pemfile::private_key`, which returned
    /// `io::Result<Option<_>>` and so made "absent" a distinct, easily-ignored case: here a
    /// missing key is simply `Err(NoItemsFound)`.
    pub(crate) fn private_key(
        pem: &[u8],
    ) -> Result<PrivateKeyDer<'static>, rustls::pki_types::pem::Error> {
        PrivateKeyDer::from_pem_slice(pem)
    }

    /// Maps a key-parsing failure onto the `io::Error` the TLS-config constructors have always
    /// returned, preserving the *kind*: a PEM blob containing no key at all stays
    /// [`NotFound`](std::io::ErrorKind::NotFound), anything malformed is
    /// [`InvalidData`](std::io::ErrorKind::InvalidData).
    ///
    /// Kept distinct deliberately — `RustlsConfig::from_pem`'s error kind is observable public
    /// behavior that callers match on, and collapsing both cases into one kind while swapping
    /// out the PEM parser would have been a silent breaking change.
    pub(crate) fn key_io_error(e: &rustls::pki_types::pem::Error) -> std::io::Error {
        let kind = if matches!(e, rustls::pki_types::pem::Error::NoItemsFound) {
            std::io::ErrorKind::NotFound
        } else {
            std::io::ErrorKind::InvalidData
        };
        std::io::Error::new(kind, format!("Failed to read private key: {e}"))
    }
}

#[cfg(feature = "lets-encrypt")]
pub mod acme;

#[cfg(feature = "tls")]
mod policy;

#[cfg(feature = "tls")]
pub use policy::TlsPolicy;
