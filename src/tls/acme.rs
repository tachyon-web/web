//! In-process ACME (RFC 8555) issuance and renewal over HTTP-01.
//!
//! Challenge tokens are answered by the [`Server::redirect`](crate::Server::redirect) listener;
//! no external client is involved. Accounts and certificates are cached in the endpoint's
//! [`Tls::store`](super::Tls::store), so restarts reuse them. A background task checks daily,
//! renews inside the 30-day window, and swaps the new certificate into the running listener,
//! backing off exponentially on failure to stay clear of CA rate limits.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, BodyWrapper, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus,
};

use super::certs::{Issuer, Slot, certify, names_id};
use super::store::Store;
use super::{KeyAlgorithm, TlsPolicy, pem};
use crate::{Error, telemetry_error as error, telemetry_info as info, telemetry_warn as warn};

const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// A certificate issued and renewed by an ACME CA — Let's Encrypt by default. Added to an
/// endpoint with [`Tls::acme`](super::Tls::acme).
///
/// ```rust,no_run
/// use tachyon_web::tls::{Acme, AcmeKey};
///
/// // Start on staging: its rate limits forgive a misconfiguration; production's lock you out
/// // for a week.
/// let acme = Acme::lets_encrypt_staging()
///     .contact("admin@example.com")
///     .key(AcmeKey::EcdsaP384);
/// ```
#[derive(Clone, Debug)]
pub struct Acme {
    directory: String,
    contact: Option<String>,
    key: AcmeKey,
}

/// The key algorithm of an ACME certificate: the ones public ACME CAs, Let's Encrypt among
/// them, issue.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum AcmeKey {
    /// ECDSA over NIST P-256: what every browser verifies. The default.
    #[default]
    EcdsaP256,
    /// ECDSA over NIST P-384.
    EcdsaP384,
}

impl AcmeKey {
    const fn algorithm(self) -> KeyAlgorithm {
        match self {
            Self::EcdsaP256 => KeyAlgorithm::EcdsaP256,
            Self::EcdsaP384 => KeyAlgorithm::EcdsaP384,
        }
    }
}

impl Acme {
    /// Let's Encrypt production: browser-trusted, strict rate limits.
    #[must_use]
    pub fn lets_encrypt() -> Self {
        Self::directory(LETS_ENCRYPT)
    }

    /// Let's Encrypt staging: untrusted certificates, generous rate limits. Use it until an
    /// issuance succeeds.
    #[must_use]
    pub fn lets_encrypt_staging() -> Self {
        Self::directory(LETS_ENCRYPT_STAGING)
    }

    /// Any RFC 8555 CA, by its directory URL.
    #[must_use]
    pub fn directory(url: impl Into<String>) -> Self {
        Self {
            directory: url.into(),
            contact: None,
            key: AcmeKey::EcdsaP256,
        }
    }

    /// An email address the CA may contact about this account.
    #[must_use]
    pub fn contact(mut self, email: impl Into<String>) -> Self {
        self.contact = Some(email.into());
        self
    }

    /// The certificate key's algorithm. Default [`AcmeKey::EcdsaP256`].
    #[must_use]
    pub const fn key(mut self, key: AcmeKey) -> Self {
        self.key = key;
        self
    }
}

/// Active HTTP-01 challenges, `token → key_authorization`. Read-mostly: contended only
/// during the brief provisioning window.
static ACTIVE_CHALLENGES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn challenges() -> &'static RwLock<HashMap<String, String>> {
    ACTIVE_CHALLENGES.get_or_init(|| RwLock::new(HashMap::new()))
}

// Crate-private: anything that can write here publishes arbitrary bytes on every port-80
// listener in the process, so only the ACME flow itself may.
fn register_challenge(token: String, key_authorization: String) {
    if let Ok(mut map) = challenges().write() {
        let _ = map.insert(token, key_authorization);
    } else {
        error!("[acme] failed to acquire write lock for challenge registration");
    }
}

fn unregister_challenge(token: &str) {
    if let Ok(mut map) = challenges().write() {
        let _ = map.remove(token);
    }
}

/// The key authorization for an active HTTP-01 `token`, for the port-80 listener to answer.
pub(crate) fn get_challenge(token: &str) -> Option<String> {
    challenges()
        .read()
        .ok()
        .and_then(|map| map.get(token).cloned())
}

/// Minimum time remaining before renewal is triggered.
const RENEW_THRESHOLD: Duration = Duration::from_hours(30 * 24);
/// How often the background loop wakes up to check cert validity.
const CHECK_INTERVAL: Duration = Duration::from_hours(24);
/// Initial backoff delay on provisioning failure.
const BACKOFF_INITIAL: Duration = Duration::from_mins(5);
/// Maximum backoff delay on repeated provisioning failures.
const BACKOFF_MAX: Duration = Duration::from_hours(6);

/// Whether a certificate expiring at `expiry` is inside the renewal window (or expired).
fn renewal_due(expiry: SystemTime) -> bool {
    expiry
        .duration_since(SystemTime::now())
        .map_or(true, |remaining| remaining <= RENEW_THRESHOLD)
}

fn acme_error(e: impl std::fmt::Display) -> Error {
    Error::certificate(format!("ACME: {e}"))
}

/// Keeps one ACME certificate issued, cached, renewed, and loaded into its [`Slot`].
pub(crate) struct Manager {
    acme: Acme,
    domains: Vec<String>,
    store: Store,
    policy: TlsPolicy,
    slot: Arc<Slot>,
    endpoints: Vec<String>,
}

impl Manager {
    pub(crate) fn new(
        acme: &Acme,
        store: Store,
        domains: Vec<String>,
        policy: &TlsPolicy,
        slot: Arc<Slot>,
        endpoints: Vec<String>,
    ) -> Self {
        Self {
            acme: acme.clone(),
            domains,
            store,
            policy: policy.clone(),
            slot,
            endpoints,
        }
    }

    /// `acme-<CA>-<alg>-<domains>`: one cache entry per CA, algorithm and domain set, so no
    /// two configurations can ever read each other's certificate.
    fn cert_stem(&self) -> String {
        format!(
            "acme-{}-{}-{}",
            names_id(std::slice::from_ref(&self.acme.directory)),
            self.acme.key.algorithm().tag(),
            names_id(&self.domains)
        )
    }

    /// Activates the cached certificate if it is still valid, returning its expiry. A
    /// certificate inside the renewal window is still activated, so a failing renewal doesn't
    /// take the listener down with it.
    pub(crate) fn load_cached(&self) -> Option<SystemTime> {
        let stem = self.cert_stem();
        let loaded = (|| {
            let cert = self.store.read(&format!("{stem}.crt"))?;
            let key = self.store.read(&format!("{stem}.key"))?;
            let (Some(cert), Some(key)) = (cert, key) else {
                return Ok(None);
            };
            self.certify(&cert, &key).map(Some)
        })();
        match loaded {
            Ok(Some((key, info))) if info.not_after > SystemTime::now() => {
                if !same_names(&info.names, &self.domains) {
                    warn!("[acme] cached {stem} does not cover {:?}", self.domains);
                    return None;
                }
                let expiry = info.not_after;
                self.slot.set(key, info);
                info!("[acme] loaded cached certificate {stem}");
                Some(expiry)
            }
            Ok(Some(_)) => {
                warn!("[acme] cached {stem} has expired");
                None
            }
            Ok(None) => None,
            Err(e) => {
                warn!("[acme] cached {stem} is unusable: {e}");
                None
            }
        }
    }

    fn certify(
        &self,
        cert: &[u8],
        key: &[u8],
    ) -> Result<(rustls::sign::CertifiedKey, super::CertificateInfo), Error> {
        certify(
            pem::certs(cert)?,
            pem::private_key(key)?,
            Issuer::Acme {
                directory: self.acme.directory.clone(),
            },
            None,
            &self.policy,
            &self.endpoints,
        )
    }

    /// The renewal loop; runs until the server stops. The active certificate's expiry is
    /// tracked in memory, so a cache write that failed neither triggers a daily re-order nor
    /// lets an older cached certificate replace the one being served.
    pub(crate) async fn run(self) {
        let mut backoff = BACKOFF_INITIAL;
        let mut active_expiry = None;
        loop {
            if active_expiry.is_none_or(renewal_due) {
                active_expiry = self.load_cached().or(active_expiry);
            }
            if active_expiry.is_none_or(renewal_due) {
                match self.provision().await {
                    Ok(expiry) => active_expiry = Some(expiry),
                    Err(e) => {
                        error!("[acme] provisioning failed: {e}. Retrying in {backoff:?}");
                        tokio::time::sleep(backoff).await;
                        backoff = backoff
                            .checked_mul(2)
                            .unwrap_or(BACKOFF_MAX)
                            .min(BACKOFF_MAX);
                        continue;
                    }
                }
            }
            backoff = BACKOFF_INITIAL;
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    }

    /// Runs the full HTTP-01 flow, caches the result, activates it, and returns its expiry.
    async fn provision(&self) -> Result<SystemTime, Error> {
        info!("[acme] ordering a certificate for {:?}", self.domains);
        let account = self.account().await?;
        let identifiers: Vec<Identifier> = self
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(acme_error)?;

        let mut tokens = Vec::new();
        let outcome = run_http01_challenges(&mut order, &mut tokens).await;
        for token in &tokens {
            unregister_challenge(token);
        }
        if outcome? == OrderStatus::Invalid {
            return Err(acme_error("the CA rejected the order"));
        }

        let key_pair =
            rcgen::KeyPair::generate_for(self.acme.key.algorithm().rcgen()).map_err(acme_error)?;
        let csr = rcgen::CertificateParams::new(self.domains.clone())
            .and_then(|params| params.serialize_request(&key_pair))
            .map_err(acme_error)?;
        order
            .finalize_csr(csr.der().as_ref())
            .await
            .map_err(acme_error)?;
        let chain_pem = order
            .poll_certificate(&instant_acme::RetryPolicy::default())
            .await
            .map_err(acme_error)?;
        let key_pem = key_pair.serialize_pem();

        let (key, info) = self.certify(chain_pem.as_bytes(), key_pem.as_bytes())?;
        let stem = self.cert_stem();
        // Key first: a failed cert write then leaves the old cert beside a new key, which
        // `certify` rejects on the next load instead of serving a mismatched pair.
        if let Err(e) = self
            .store
            .write(&format!("{stem}.key"), key_pem.as_bytes())
            .and_then(|()| {
                self.store
                    .write(&format!("{stem}.crt"), chain_pem.as_bytes())
            })
        {
            error!("[acme] failed to cache {stem}: {e}");
        }
        let expiry = info.not_after;
        self.slot.set(key, info);
        info!("[acme] issued and activated {stem}");
        Ok(expiry)
    }

    /// An [`AccountBuilder`] whose client talks to the CA with the build's default policy — the
    /// validated module under `fips`, and never a server policy narrowed past what the CA
    /// speaks — and the pinned `webpki-roots` set.
    fn account_builder() -> Result<AccountBuilder, Error> {
        let connector = HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(TlsPolicy::new().provider())
            .map_err(acme_error)?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client: HyperClient<_, BodyWrapper<bytes::Bytes>> =
            HyperClient::builder(TokioExecutor::new()).build(connector);
        Ok(Account::builder_with_http(Box::new(AcmeHttpClient(client))))
    }

    /// Loads the cached account for this CA, or registers and caches a new one.
    async fn account(&self) -> Result<Account, Error> {
        let file = format!(
            "acme-account-{}.json",
            names_id(std::slice::from_ref(&self.acme.directory))
        );
        match self.store.read(&file) {
            Ok(Some(json)) => match serde_json::from_slice::<AccountCredentials>(&json) {
                Ok(credentials) => {
                    match Self::account_builder()?.from_credentials(credentials).await {
                        Ok(account) => return Ok(account),
                        Err(e) => warn!("[acme] cached account rejected, registering anew: {e}"),
                    }
                }
                Err(e) => warn!("[acme] cached account unparsable, registering anew: {e}"),
            },
            Ok(None) => {}
            Err(e) => warn!("[acme] cached account unreadable, registering anew: {e}"),
        }

        info!("[acme] registering a new account");
        let contact: Vec<String> = self
            .acme
            .contact
            .iter()
            .map(|email| format!("mailto:{email}"))
            .collect();
        let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, credentials) = Self::account_builder()?
            .create(
                &NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.acme.directory.clone(),
                None,
            )
            .await
            .map_err(acme_error)?;
        // A failed write only costs a re-registration on the next start.
        match serde_json::to_vec(&credentials) {
            Ok(json) => {
                if let Err(e) = self.store.write(&file, &json) {
                    warn!("[acme] failed to cache account: {e}");
                }
            }
            Err(e) => warn!("[acme] failed to serialize account: {e}"),
        }
        Ok(account)
    }
}

/// Whether a certificate's SANs are exactly `domains`. Expiry alone isn't enough: a
/// still-valid certificate for a different domain set must not be activated.
fn same_names(names: &[String], domains: &[String]) -> bool {
    let normalize = |list: &[String]| {
        let mut list: Vec<String> = list.iter().map(|n| n.to_ascii_lowercase()).collect();
        list.sort_unstable();
        list.dedup();
        list
    };
    !names.is_empty() && normalize(names) == normalize(domains)
}

/// Registers an HTTP-01 response per authorization, marks each ready, then waits for the
/// order to leave the pending state.
///
/// Every token lands in `tokens` before the fallible work that follows it, so the caller can
/// unregister them all however this returns.
async fn run_http01_challenges(
    order: &mut instant_acme::Order,
    tokens: &mut Vec<String>,
) -> Result<OrderStatus, Error> {
    {
        let mut auths = order.authorizations();
        while let Some(auth) = auths.next().await {
            let mut auth = auth.map_err(acme_error)?;
            let mut challenge = auth
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| acme_error("the CA offered no HTTP-01 challenge"))?;
            let key_auth = challenge.key_authorization().as_str().to_string();
            let token = challenge.token.clone();
            register_challenge(token.clone(), key_auth);
            tokens.push(token);
            challenge.set_ready().await.map_err(acme_error)?;
        }
    }
    order
        .poll_ready(&instant_acme::RetryPolicy::default())
        .await
        .map_err(acme_error)
}

/// Adapts a `hyper_util` client to [`instant_acme::HttpClient`].
///
/// `instant-acme` ships this impl behind its `hyper-rustls` feature, but that would unify
/// `native-tokio` + `tls12` onto this crate's `hyper-rustls`.
struct AcmeHttpClient<C>(HyperClient<C, BodyWrapper<bytes::Bytes>>);

impl<C> instant_acme::HttpClient for AcmeHttpClient<C>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    fn request(
        &self,
        req: hyper::Request<BodyWrapper<bytes::Bytes>>,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let response = self.0.request(req);
        Box::pin(async move {
            response
                .await
                .map(instant_acme::BytesResponse::from)
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(dir: &std::path::Path, domains: Vec<String>) -> Manager {
        Manager::new(
            &Acme::lets_encrypt_staging(),
            Store::open(&dir.join("tls")).expect("store"),
            domains,
            &TlsPolicy::new(),
            Arc::new(Slot::default()),
            Vec::new(),
        )
    }

    fn write_cached(manager: &Manager, cert: &str, key: &str) {
        let stem = manager.cert_stem();
        for (ext, pem) in [("crt", cert), ("key", key)] {
            manager
                .store
                .write(&format!("{stem}.{ext}"), pem.as_bytes())
                .expect("write cache entry");
        }
    }

    fn cert_for(domains: &[String], valid_for: Duration) -> (String, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let mut params = rcgen::CertificateParams::new(domains.to_vec()).expect("params");
        params.not_after = SystemTime::now()
            .checked_add(valid_for)
            .expect("expiry fits")
            .into();
        let cert = params.self_signed(&key).expect("self-sign");
        (cert.pem(), key.serialize_pem())
    }

    fn random_domains() -> Vec<String> {
        vec![format!("{:x}.example", rand::random::<u64>())]
    }

    /// A cert inside the renewal window is still valid, so it must keep serving while renewal
    /// runs — otherwise a restart during a CA outage leaves every handshake failing for days.
    #[test]
    fn a_cert_due_for_renewal_is_served_until_replaced() {
        let dir = tempfile::tempdir().expect("temp dir");
        let domains = random_domains();
        let manager = manager(dir.path(), domains.clone());
        let (cert, key) = cert_for(&domains, Duration::from_hours(10 * 24));
        write_cached(&manager, &cert, &key);

        let expiry = manager
            .load_cached()
            .expect("a still-valid cert is activated");
        assert!(manager.slot.is_loaded());
        assert!(renewal_due(expiry));
    }

    /// A failed write can strand a cert beside a stale key, or leave a cert for other names;
    /// neither may be served.
    #[test]
    fn a_cached_cert_needs_its_own_key_and_exact_domains() {
        let dir = tempfile::tempdir().expect("temp dir");
        let domains = random_domains();
        let manager = manager(dir.path(), domains.clone());
        let (cert, _) = cert_for(&domains, Duration::from_hours(90 * 24));
        let (_, stale_key) = cert_for(&domains, Duration::from_hours(90 * 24));
        write_cached(&manager, &cert, &stale_key);
        assert!(manager.load_cached().is_none());

        let mut wider = domains;
        wider.extend(random_domains());
        let (cert, key) = cert_for(&wider, Duration::from_hours(90 * 24));
        write_cached(&manager, &cert, &key);
        assert!(manager.load_cached().is_none());
        assert!(!manager.slot.is_loaded());
    }

    /// HTTP-01 cannot prove a wildcard, and IP literals would be ordered as DNS names and never
    /// match their cache, re-ordering on every start.
    #[test]
    fn acme_refuses_names_http01_cannot_validate() {
        let tls = |name: String| {
            crate::tls::Tls::new()
                .domains([name])
                .store("unused")
                .acme(Acme::lets_encrypt())
        };
        let validate = |name| crate::tls::certs::validate(&tls(name), false);
        assert!(validate(random_domains().remove(0)).is_ok());
        assert!(validate(format!("*.{}", random_domains().remove(0))).is_err());
        let ip = std::net::Ipv4Addr::from(rand::random::<u32>());
        assert!(validate(ip.to_string()).is_err());
    }
}
