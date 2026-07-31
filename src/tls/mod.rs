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

#[cfg(feature = "lets-encrypt")]
pub mod acme;

#[cfg(feature = "tls")]
mod policy;

#[cfg(feature = "tls")]
pub use policy::TlsPolicy;
