//! Loading, generating and persisting an endpoint's certificates, picking one per handshake,
//! and the [`CertificateInfo`] published about each.

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use rustls::SignatureScheme;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use super::store::Store;
use super::{KeyAlgorithm, Source, Tls, TlsPolicy, der, pem};
use crate::Error;

/// Who vouches for a certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Issuer {
    /// Generated and signed by this server with its own key; trusted only where pinned.
    SelfSigned,
    /// Issued by an ACME CA.
    Acme {
        /// The CA's ACME directory URL.
        directory: String,
    },
    /// Supplied by the caller as PEM; issued by whoever signed it.
    Provided,
}

/// Public facts about one certificate a server is serving — everything a client or an
/// attestation needs to pin or verify it, and nothing secret.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CertificateInfo {
    /// The chain as served, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// [`chain`](Self::chain) as PEM.
    pub pem: String,
    /// SHA-256 of the leaf certificate's DER: its conventional fingerprint.
    pub sha256: [u8; 32],
    /// SHA-256 of the leaf's DER `SubjectPublicKeyInfo`: the RFC 7469 `pin-sha256` value,
    /// which survives re-issuance under the same key.
    pub spki_sha256: [u8; 32],
    /// The key algorithm, or `None` for a provided certificate with a key this crate cannot
    /// generate (RSA, Ed25519).
    pub algorithm: Option<KeyAlgorithm>,
    /// Who issued it.
    pub issuer: Issuer,
    /// The names it covers: its DNS SANs, or for a generated certificate the names it was
    /// generated for (which may include IP literals and `.onion`/`.b32.i2p` addresses).
    pub names: Vec<String>,
    /// When it expires.
    pub not_after: SystemTime,
    /// The origins of the endpoints serving it, e.g. `https://example.com`.
    pub endpoints: Vec<String>,
}

impl CertificateInfo {
    /// [`sha256`](Self::sha256) as lowercase hex.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex(&self.sha256)
    }

    fn covers(&self, server_name: &str) -> bool {
        self.names
            .iter()
            .any(|name| crate::server::security::host_allowed(name, server_name))
    }
}

/// Every scheme a loaded key is probed for, so a handshake can test support without
/// allocating a signer per candidate.
const SCHEMES: [SignatureScheme; 13] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
];

struct Loaded {
    key: Arc<CertifiedKey>,
    info: Arc<CertificateInfo>,
    schemes: Vec<SignatureScheme>,
}

/// One certificate source's current certificate. ACME replaces its contents on renewal.
#[derive(Default)]
pub(crate) struct Slot(RwLock<Option<Loaded>>);

impl Slot {
    pub(crate) fn set(&self, key: CertifiedKey, info: CertificateInfo) {
        let schemes = SCHEMES
            .into_iter()
            .filter(|scheme| key.key.choose_scheme(&[*scheme]).is_some())
            .collect();
        let loaded = Loaded {
            key: Arc::new(key),
            info: Arc::new(info),
            schemes,
        };
        if let Ok(mut slot) = self.0.write() {
            *slot = Some(loaded);
        }
    }

    #[cfg(all(test, feature = "acme"))]
    pub(crate) fn is_loaded(&self) -> bool {
        self.0.read().is_ok_and(|slot| slot.is_some())
    }
}

/// An endpoint's certificates, in preference order, resolved per handshake.
pub(crate) struct CertStore {
    slots: Vec<Arc<Slot>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("certificates", &self.slots.len())
            .finish()
    }
}

impl CertStore {
    pub(crate) fn infos(&self) -> Vec<Arc<CertificateInfo>> {
        self.slots
            .iter()
            .filter_map(|slot| Some(slot.0.read().ok()?.as_ref()?.info.clone()))
            .collect()
    }

    /// The first loaded certificate, in preference order, that `accept` takes.
    fn first(&self, accept: impl Fn(&Loaded) -> bool) -> Option<Arc<CertifiedKey>> {
        self.slots.iter().find_map(|slot| {
            let slot = slot.0.read().ok()?;
            let key = slot
                .as_ref()
                .filter(|loaded| accept(loaded))
                .map(|loaded| loaded.key.clone());
            drop(slot);
            key
        })
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let offered = hello.signature_schemes();
        let verifiable = |loaded: &Loaded| loaded.schemes.iter().any(|s| offered.contains(s));
        // A certificate for the requested name wins; otherwise any verifiable one, as every
        // server with a default certificate does.
        hello
            .server_name()
            .and_then(|name| self.first(|loaded| loaded.info.covers(name) && verifiable(loaded)))
            .or_else(|| self.first(verifiable))
    }
}

/// Rejects a [`Tls`] that cannot work, before anything is bound.
pub(crate) fn validate(tls: &Tls, anonymous: bool) -> Result<(), Error> {
    if let Some(name) = tls
        .domains
        .iter()
        .find(|name| !crate::server::security::valid_host_entry(name))
    {
        return Err(Error::config(format!(
            "Tls::domains: {name:?} is not a DNS name, `*.` wildcard or IP literal"
        )));
    }
    if tls.sources.is_empty() {
        return Err(Error::config("a Tls set needs at least one certificate"));
    }
    let needs_domains = !anonymous
        && tls
            .sources
            .iter()
            .any(|source| !matches!(source, Source::Pem { .. } | Source::PemFiles { .. }));
    if needs_domains && tls.domains.is_empty() {
        return Err(Error::config(
            "self-signed and ACME certificates need names: call Tls::domains",
        ));
    }
    #[cfg(feature = "acme")]
    if tls
        .sources
        .iter()
        .any(|source| matches!(source, Source::Acme(_)))
    {
        if anonymous {
            return Err(Error::config(
                "ACME cannot issue for .onion or .b32.i2p addresses",
            ));
        }
        if tls.store.is_none() {
            return Err(Error::config(
                "ACME needs a certificate store: call Tls::store",
            ));
        }
        if let Some(name) = tls
            .domains
            .iter()
            .find(|name| name.starts_with("*.") || name.parse::<std::net::IpAddr>().is_ok())
        {
            return Err(Error::config(format!(
                "ACME orders DNS names over HTTP-01, which cannot validate {name:?}"
            )));
        }
    }
    Ok(())
}

/// The TLS side of one endpoint, ready to serve.
pub(crate) struct Built {
    pub(crate) config: Arc<rustls::ServerConfig>,
    pub(crate) store: Arc<CertStore>,
    #[cfg(feature = "acme")]
    pub(crate) acme: Vec<super::acme::Manager>,
}

/// Loads or generates every certificate in `tls` for an endpoint answering to `names` at
/// `url`, and builds its rustls config.
pub(crate) fn build(
    tls: &Tls,
    policy: &TlsPolicy,
    names: &[String],
    url: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<Built, Error> {
    let store = tls.store.as_deref().map(Store::open).transpose()?;
    let endpoints = vec![url.to_string()];
    let mut slots = Vec::with_capacity(tls.sources.len());
    #[cfg(feature = "acme")]
    let mut acme = Vec::new();
    for source in &tls.sources {
        let slot = Arc::new(Slot::default());
        match source {
            Source::SelfSigned(alg) => {
                let (key, info) = self_signed(*alg, names, store.as_ref(), policy, &endpoints)?;
                slot.set(key, info);
            }
            Source::Pem { cert, key } => {
                let (key, info) = provided(cert, key, policy, &endpoints)?;
                slot.set(key, info);
            }
            Source::PemFiles { cert, key } => {
                let (key, info) = provided(
                    &std::fs::read(cert)?,
                    &std::fs::read(key)?,
                    policy,
                    &endpoints,
                )?;
                slot.set(key, info);
            }
            #[cfg(feature = "acme")]
            Source::Acme(config) => {
                let Some(store) = &store else {
                    return Err(Error::config(
                        "ACME needs a certificate store: call Tls::store",
                    ));
                };
                let manager = super::acme::Manager::new(
                    config,
                    store.clone(),
                    names.to_vec(),
                    policy,
                    slot.clone(),
                    endpoints.clone(),
                );
                manager.load_cached();
                acme.push(manager);
            }
        }
        slots.push(slot);
    }

    let store = Arc::new(CertStore { slots });
    let mut config = policy.config_builder()?.with_cert_resolver(store.clone());
    config.alpn_protocols = alpn;
    Ok(Built {
        config: policy.finalize(config),
        store,
        #[cfg(feature = "acme")]
        acme,
    })
}

/// A certified key and its published facts, from a chain and key loaded through `policy`'s
/// provider — under `fips` a stock provider would be a different, unvalidated module.
pub(crate) fn certify(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    issuer: Issuer,
    names: Option<Vec<String>>,
    policy: &TlsPolicy,
    endpoints: &[String],
) -> Result<(CertifiedKey, CertificateInfo), Error> {
    let signing_key = policy
        .provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| Error::certificate(format!("unusable private key: {e}")))?;
    let certified = CertifiedKey::new(chain.clone(), signing_key);
    certified
        .keys_match()
        .map_err(|e| Error::certificate(format!("certificate and key do not match: {e}")))?;

    let leaf = chain
        .first()
        .ok_or_else(|| Error::certificate("empty certificate chain"))?;
    let parsed = webpki::EndEntityCert::try_from(leaf)
        .map_err(|e| Error::certificate(format!("unparsable certificate: {e}")))?;
    let names = names.unwrap_or_else(|| parsed.valid_dns_names().map(str::to_owned).collect());
    let not_after = der::parse_not_after(leaf.as_ref())
        .map_err(|e| Error::certificate(format!("unparsable certificate validity: {e}")))?;
    let algorithm = SCHEMES
        .into_iter()
        .find(|scheme| certified.key.choose_scheme(&[*scheme]).is_some())
        .and_then(KeyAlgorithm::from_scheme);
    if cfg!(feature = "cnsa") && algorithm != Some(KeyAlgorithm::MlDsa87) {
        return Err(Error::certificate(
            "CNSA mode requires an ML-DSA-87 certificate and key",
        ));
    }

    let info = CertificateInfo {
        pem: chain
            .iter()
            .map(|cert| der::pem_encode("CERTIFICATE", cert))
            .collect(),
        sha256: sha256(leaf),
        spki_sha256: sha256(&parsed.subject_public_key_info()),
        algorithm,
        issuer,
        names,
        not_after,
        endpoints: endpoints.to_vec(),
        chain,
    };
    Ok((certified, info))
}

fn provided(
    cert: &[u8],
    key: &[u8],
    policy: &TlsPolicy,
    endpoints: &[String],
) -> Result<(CertifiedKey, CertificateInfo), Error> {
    certify(
        pem::certs(cert)?,
        pem::private_key(key)?,
        Issuer::Provided,
        None,
        policy,
        endpoints,
    )
}

/// A self-signed certificate for `names`, reused from `store` when one was generated there
/// before for the same algorithm and names.
fn self_signed(
    alg: KeyAlgorithm,
    names: &[String],
    store: Option<&Store>,
    policy: &TlsPolicy,
    endpoints: &[String],
) -> Result<(CertifiedKey, CertificateInfo), Error> {
    let stem = format!("self-signed-{}-{}", alg.tag(), names_id(names));
    let (cert_file, key_file) = (format!("{stem}.crt"), format!("{stem}.key"));
    let certify_pem = |cert: &[u8], key: &[u8]| {
        certify(
            pem::certs(cert)?,
            pem::private_key(key)?,
            Issuer::SelfSigned,
            Some(names.to_vec()),
            policy,
            endpoints,
        )
    };

    if let Some(store) = store
        && let (Some(cert), Some(key)) = (store.read(&cert_file)?, store.read(&key_file)?)
    {
        match certify_pem(&cert, &key) {
            Ok(loaded) if loaded.1.not_after > SystemTime::now() => return Ok(loaded),
            Ok(_) => crate::telemetry_warn!("[tls] stored {stem} has expired; regenerating"),
            Err(e) => crate::telemetry_warn!("[tls] stored {stem} is unusable ({e}); regenerating"),
        }
    }

    let key_pair = rcgen::KeyPair::generate_for(alg.rcgen())
        .map_err(|e| Error::certificate(format!("{alg:?} key generation failed: {e}")))?;
    let cert = rcgen::CertificateParams::new(names.to_vec())
        .and_then(|params| params.self_signed(&key_pair))
        .map_err(|e| Error::certificate(format!("self-signing failed: {e}")))?;
    let (cert_pem, key_pem) = (cert.pem(), key_pair.serialize_pem());
    if let Some(store) = store {
        store.write(&key_file, key_pem.as_bytes())?;
        store.write(&cert_file, cert_pem.as_bytes())?;
    }
    certify_pem(cert_pem.as_bytes(), key_pem.as_bytes())
}

/// A short stable identifier for a set of names, so each set gets its own store files.
pub(crate) fn names_id(names: &[String]) -> String {
    let mut sorted: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    sorted.sort_unstable();
    let digest = sha256(sorted.join("\n").as_bytes());
    hex(digest.get(..8).unwrap_or_default())
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    digest.as_ref().try_into().unwrap_or([0; 32])
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_names() -> Vec<String> {
        vec![format!("{:x}.example", rand::random::<u64>())]
    }

    fn endpoint() -> Vec<String> {
        vec!["https://example".to_string()]
    }

    /// Every algorithm generates, loads through the policy's provider, and reports itself —
    /// with fingerprints that match the certificate actually served.
    #[test]
    fn every_key_algorithm_generates_a_servable_certificate() {
        let policy = TlsPolicy::new();
        for &alg in KeyAlgorithm::ALL {
            let names = random_names();
            let (key, info) = self_signed(alg, &names, None, &policy, &endpoint())
                .unwrap_or_else(|e| panic!("{alg:?}: {e}"));
            let leaf = key.cert.first().expect("leaf");
            assert_eq!(info.algorithm, Some(alg));
            assert_eq!(info.sha256, sha256(leaf));
            assert_eq!(info.names, names);
            assert_eq!(info.issuer, Issuer::SelfSigned);
            assert_eq!(pem::certs(info.pem.as_bytes()).expect("pem"), key.cert);
        }
    }

    #[test]
    fn a_stored_self_signed_certificate_is_reused_only_for_the_same_names() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&dir.path().join("tls")).expect("store");
        let policy = TlsPolicy::new();
        let alg = KeyAlgorithm::MlDsa87;
        let names = random_names();

        let generate = |names: &[String]| {
            self_signed(alg, names, Some(&store), &policy, &endpoint())
                .expect("self-signed")
                .1
                .sha256
        };
        let first = generate(&names);
        assert_eq!(
            generate(&names),
            first,
            "same names must reuse the stored key"
        );
        assert_ne!(generate(&random_names()), first);
    }

    #[test]
    fn a_mismatched_certificate_and_key_are_refused() {
        let policy = TlsPolicy::new();
        let generate = || {
            let key = rcgen::KeyPair::generate_for(KeyAlgorithm::MlDsa87.rcgen()).expect("key");
            let cert = rcgen::CertificateParams::new(random_names())
                .and_then(|params| params.self_signed(&key))
                .expect("cert");
            (cert.pem(), key.serialize_pem())
        };
        let ((cert, _), (_, other_key)) = (generate(), generate());
        assert!(matches!(
            provided(cert.as_bytes(), other_key.as_bytes(), &policy, &endpoint()),
            Err(Error::Certificate(_))
        ));
    }

    /// A domain that could never match a request or name a certificate is refused.
    #[test]
    fn malformed_domains_are_refused() {
        let tls = |name: String| {
            Tls::new()
                .domains([name])
                .self_signed(KeyAlgorithm::MlDsa87)
        };
        let host = random_names().remove(0);
        for good in [host.clone(), format!("*.{host}"), "::1".to_string()] {
            assert!(validate(&tls(good.clone()), false).is_ok(), "{good}");
        }
        for bad in [
            format!("https://{host}"),
            format!("{host}:443"),
            format!("{host}/"),
        ] {
            assert!(validate(&tls(bad.clone()), false).is_err(), "{bad}");
        }
    }

    /// A provided certificate is the one place CNSA can't be settled at compile time: its
    /// algorithm is data, so anything but ML-DSA-87 is refused when it loads.
    #[cfg(feature = "cnsa")]
    #[test]
    fn cnsa_refuses_a_provided_certificate_that_is_not_ml_dsa_87() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("key");
        let cert = rcgen::CertificateParams::new(random_names())
            .and_then(|params| params.self_signed(&key))
            .expect("cert");
        let loaded = provided(
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            &TlsPolicy::new(),
            &endpoint(),
        );
        assert!(matches!(loaded, Err(Error::Certificate(_))));
    }

    /// Provided certificates load from memory or files and report their own SANs and issuer.
    #[cfg(not(feature = "cnsa"))]
    #[test]
    fn provided_certificates_report_their_own_names() {
        let names = random_names();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("key");
        let cert = rcgen::CertificateParams::new(names.clone())
            .and_then(|params| params.self_signed(&key))
            .expect("cert");
        let dir = tempfile::tempdir().expect("temp dir");
        let (cert_file, key_file) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        std::fs::write(&cert_file, cert.pem()).expect("write cert");
        std::fs::write(&key_file, key.serialize_pem()).expect("write key");

        let tls = Tls::new()
            .pem(cert.pem(), key.serialize_pem())
            .pem_files(&cert_file, &key_file);
        validate(&tls, false).expect("provided certificates need no domains");
        let built = build(&tls, &TlsPolicy::new(), &[], "https://x", Vec::new()).expect("build");
        let infos = built.store.infos();
        assert_eq!(infos.len(), 2);
        for info in infos {
            assert_eq!(info.issuer, Issuer::Provided);
            assert_eq!(info.names, names);
            assert_eq!(info.algorithm, Some(KeyAlgorithm::EcdsaP384));
        }
        assert!(format!("{tls:?}").contains("PemFiles"));
    }
}
