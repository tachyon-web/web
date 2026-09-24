//! TLS helper utilities.

#[cfg(feature = "cert-gen")]
mod cert_gen {
    #[cfg(not(feature = "cnsa"))]
    use rcgen::PKCS_ECDSA_P384_SHA384;
    #[cfg(feature = "cnsa")]
    use rcgen::PKCS_ML_DSA_87;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// A self-signed TLS certificate with both PEM and DER representations.
    ///
    /// *Tachyon extension: no `axum` equivalent.*
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

    /// Generates an ephemeral self-signed certificate for the given domains.
    ///
    /// Ordinary builds use ECDSA P-384. A `cnsa` build instead unconditionally uses ML-DSA-87;
    /// there is no algorithm parameter through which a caller can downgrade it.
    /// Useful for bootstrapping development servers or testing TLS connections without a real CA.
    ///
    /// # Errors
    ///
    /// Returns an error if generating the key pair or signing the certificate fails.
    ///
    /// *Tachyon extension: no `axum` equivalent.*
    pub fn generate_self_signed_cert(domains: Vec<String>) -> Result<SelfSignedCert, rcgen::Error> {
        let params = CertificateParams::new(domains)?;
        #[cfg(not(feature = "cnsa"))]
        let algorithm = &PKCS_ECDSA_P384_SHA384;
        #[cfg(feature = "cnsa")]
        let algorithm = &PKCS_ML_DSA_87;
        let key_pair = KeyPair::generate_for(algorithm)?;
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

#[cfg(all(test, feature = "cert-gen", feature = "cnsa"))]
mod cnsa_tests {
    #[test]
    fn generated_certificate_uses_ml_dsa_87() {
        let cert = super::generate_self_signed_cert(vec!["localhost".to_string()])
            .expect("generate CNSA certificate");
        let marker = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
        ];
        assert!(
            cert.cert_der
                .as_ref()
                .windows(marker.len())
                .any(|window| window == marker),
            "certificate does not contain the ML-DSA-87 algorithm identifier"
        );
    }
}

#[cfg(feature = "cert-gen")]
pub(crate) fn certificate_dns_names(
    cert: &rustls::pki_types::CertificateDer<'static>,
) -> Vec<String> {
    webpki::EndEntityCert::try_from(cert)
        .map(|cert| cert.valid_dns_names().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// PEM parsing, on `rustls-pki-types`' own [`PemObject`] implementation.
///
/// [`PemObject`]: rustls::pki_types::pem::PemObject
#[cfg(feature = "tls")]
pub(crate) mod pem {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    /// Parses a PEM certificate chain, skipping entries that fail to parse: a chain whose leaf
    /// parses is servable even if a later entry is malformed, and `with_single_cert` rejects an
    /// empty chain anyway.
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
    /// The distinction is observable public behavior: `RustlsConfig::from_pem` callers match on
    /// the error kind.
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
