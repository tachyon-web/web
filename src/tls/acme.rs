//! ACME (Automatic Certificate Management Environment) native manager for Let's Encrypt.
//!
//! This module orchestrates the full TLS certificate lifecycle automatically:
//!
//! - **Account management**: Creates or reuses a cached Let's Encrypt account per environment
//!   (staging vs production). Account credentials are serialized to disk so that re-running
//!   the server never creates duplicate accounts and avoids hitting ACME registration limits.
//!
//! - **Certificate provisioning**: Performs the HTTP-01 challenge flow entirely in-process —
//!   no external CLI tools required. Challenge tokens are served via the built-in HTTP redirect
//!   listener used by [`crate::server::Server::serve_all_acme`].
//!
//! - **Hot-reload**: The [`AcmeResolver`] implements [`rustls::server::ResolvesServerCert`],
//!   meaning the TLS stack picks up renewed certificates without any downtime or restart.
//!
//! - **Automatic renewal**: A background task wakes up every 24 hours and renews certificates
//!   that expire within 30 days. Renewal uses exponential backoff on failure to avoid
//!   hammering the Let's Encrypt rate-limit window.
//!
//! - **Rate-limit safety**: Certificates and account credentials are cached to disk. On startup
//!   the cached cert is loaded and validated before ever contacting Let's Encrypt.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{error, info, warn};
use webpki::EndEntityCert;

/// Writes `contents` to `path` with owner-only read/write access (`0600` on Unix)
/// from the moment the file is created — never leaving a window where the file
/// briefly exists with the process's default (often world/group-readable) umask
/// permissions, unlike a `write()` followed by a separate `chmod()`.
///
/// Used for private keys and ACME account credentials, both of which are
/// sensitive enough that even a brief on-disk exposure to other local users is
/// worth closing.
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = fs::File::create(path)?;
    file.write_all(contents)
}

// ─── Global challenge store ──────────────────────────────────────────────────

/// Global map of active HTTP-01 challenges: `token → key_authorization`.
///
/// Uses an `RwLock`-protected `HashMap` so that many concurrent HTTPS requests
/// can read challenge responses lock-free during the brief provisioning window.
static ACTIVE_CHALLENGES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

#[inline]
fn challenges() -> &'static RwLock<HashMap<String, String>> {
    ACTIVE_CHALLENGES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Registers a temporary ACME HTTP-01 challenge response in the global store.
///
/// The challenge will be served by the HTTP listener until [`unregister_challenge`] is called.
pub fn register_challenge(token: String, key_authorization: String) {
    if let Ok(mut map) = challenges().write() {
        let _ = map.insert(token, key_authorization);
    } else {
        error!("[acme] Failed to acquire write lock for challenge registration");
    }
}

/// Removes a challenge token from the global store once the ACME server has validated it.
pub fn unregister_challenge(token: &str) {
    if let Ok(mut map) = challenges().write() {
        let _ = map.remove(token);
    }
}

/// Looks up the key authorization for a given challenge token.
///
/// Returns `Some(key_authorization)` if the token is active, or `None` otherwise.
/// Callers on the hot HTTP path acquire only a read lock.
#[inline]
#[must_use]
pub fn get_challenge(token: &str) -> Option<String> {
    challenges()
        .read()
        .ok()
        .and_then(|map| map.get(token).cloned())
}

// ─── AcmeResolver ────────────────────────────────────────────────────────────

/// Dynamic `rustls` certificate resolver that serves the most recently provisioned
/// certificate during every TLS handshake.
///
/// This allows zero-downtime certificate hot-swap: simply call [`AcmeResolver::update_cert`]
/// with the new [`CertifiedKey`] and all subsequent connections will use it immediately,
/// without restarting the listener.
///
/// # Thread safety
/// All accesses are protected by an inner [`RwLock`]; reads (handshakes) never block
/// each other, and writes (certificate renewals) happen at most once every 24 hours.
#[derive(Debug)]
pub struct AcmeResolver {
    current_key: RwLock<Option<Arc<CertifiedKey>>>,
}

impl AcmeResolver {
    /// Creates a new resolver with no initial certificate loaded.
    ///
    /// The resolver will return `None` from [`ResolvesServerCert::resolve`] until
    /// [`update_cert`][Self::update_cert] is called with a valid certificate.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current_key: RwLock::new(None),
        }
    }

    /// Atomically swaps in a new certificate for all future TLS handshakes.
    ///
    /// Old connections keep using whatever certificate was negotiated at handshake
    /// time; only new connections will see the updated certificate.
    pub fn update_cert(&self, certified_key: CertifiedKey) {
        match self.current_key.write() {
            Ok(mut lock) => {
                *lock = Some(Arc::new(certified_key));
                info!("[acme] Certificate hot-swapped into TLS resolver");
            }
            Err(e) => error!("[acme] Failed to update certificate in resolver: {e}"),
        }
    }

    /// Returns `true` if a certificate has been loaded into this resolver.
    pub fn has_certificate(&self) -> bool {
        self.current_key
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|_| ()))
            .is_some()
    }
}

impl Default for AcmeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for AcmeResolver {
    /// Called by `rustls` on every TLS handshake. Acquires a read-lock and clones
    /// the `Arc` — this is a very cheap operation (two atomic increments).
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current_key.read().ok()?.clone()
    }
}

// ─── AcmeError ───────────────────────────────────────────────────────────────

/// Errors that can occur during ACME certificate management.
#[derive(Debug)]
pub enum AcmeError {
    /// An I/O error reading or writing the certificate/key cache.
    Io(std::io::Error),
    /// An ACME protocol error returned by the CA.
    Acme(instant_acme::Error),
    /// A certificate generation error from `rcgen`.
    CertGen(rcgen::Error),
    /// JSON serialization / deserialization error for stored credentials.
    Json(serde_json::Error),
    /// The ACME order was rejected by the CA (challenge failed).
    OrderInvalid,
    /// No private key was found in the PEM data on disk.
    MissingPrivateKey,
    /// Certificate parsing failed (x509-parser error).
    CertParse(String),
    /// TLS signing key could not be loaded from the private key.
    TlsKeyLoad(String),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Acme(e) => write!(f, "ACME protocol error: {e}"),
            Self::CertGen(e) => write!(f, "Certificate generation error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::OrderInvalid => write!(f, "ACME order was rejected by CA"),
            Self::MissingPrivateKey => write!(f, "No private key found in PEM data"),
            Self::CertParse(s) => write!(f, "Certificate parse error: {s}"),
            Self::TlsKeyLoad(s) => write!(f, "TLS signing key load failed: {s}"),
        }
    }
}

impl std::error::Error for AcmeError {}

impl From<std::io::Error> for AcmeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<instant_acme::Error> for AcmeError {
    fn from(e: instant_acme::Error) -> Self {
        Self::Acme(e)
    }
}
impl From<rcgen::Error> for AcmeError {
    fn from(e: rcgen::Error) -> Self {
        Self::CertGen(e)
    }
}
impl From<serde_json::Error> for AcmeError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

// ─── AcmeManager ─────────────────────────────────────────────────────────────

/// The central orchestrator for automatic Let's Encrypt TLS certificate management.
///
/// # Usage
///
/// ```rust,no_run
/// use tachyon_web::tls::acme::AcmeManager;
///
/// # async fn example() {
/// // 1. Create the manager for your domains.
/// let acme = AcmeManager::new(
///     "/var/cache/tachyon/certs",         // persistent cache dir (survives restarts)
///     vec!["example.com".to_string(), "www.example.com".to_string()],
///     "admin@example.com".to_string(),
///     false,                              // false = production Let's Encrypt
/// );
///
/// // 2. Get the TLS resolver to wire into the server.
/// let resolver = acme.resolver();
///
/// // 3. Launch the background renewal loop.
/// acme.start();
/// # }
/// ```
///
/// # Rate-limit safety
///
/// On every restart the manager first tries to load a valid certificate from
/// `<cache_dir>/domain.crt` and `<cache_dir>/domain.key`. A new ACME order is
/// only placed if:
/// - No cached certificate exists, or
/// - The cached certificate expires within 30 days.
///
/// Account credentials are cached in `<cache_dir>/account-{staging|prod}.json`
/// and reused across runs, so only one account registration per environment
/// ever happens.
///
/// On provisioning failure the background loop retries with exponential backoff
/// (starting at 5 minutes, capped at 6 hours) to stay well within the
/// [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/).
#[derive(Debug)]
pub struct AcmeManager {
    domains: Vec<String>,
    email: String,
    cache_dir: PathBuf,
    is_staging: bool,
    resolver: Arc<AcmeResolver>,
    /// Guard to prevent concurrent provisioning runs.
    /// Uses `tokio::sync::Mutex` so the guard is `Send` across async await points.
    provisioning: tokio::sync::Mutex<()>,
}

/// Minimum time remaining before renewal is triggered.
const RENEW_THRESHOLD: Duration = Duration::from_hours(30 * 24); // 30 days
/// How often the background loop wakes up to check cert validity.
const CHECK_INTERVAL: Duration = Duration::from_hours(24);
/// Initial backoff delay on provisioning failure.
const BACKOFF_INITIAL: Duration = Duration::from_mins(5);
/// Maximum backoff delay on repeated provisioning failures.
const BACKOFF_MAX: Duration = Duration::from_hours(6);

impl AcmeManager {
    /// Creates a new `AcmeManager` and ensures the cache directory exists.
    ///
    /// # Arguments
    /// - `cache_dir`: Directory used for storing account credentials and the certificate/key pair.
    ///   Must be writable by the process. Survives across server restarts.
    /// - `domains`: The domain names to include in the certificate as Subject Alternative
    ///   Names. The issued certificate has no Subject/CN set — TLS clients validate against
    ///   the SAN list, not the (legacy, deprecated) CN field.
    /// - `email`: Contact address sent to Let's Encrypt. Used for expiry warnings.
    /// - `is_staging`: If `true`, targets `acme-staging-v02.api.letsencrypt.org` instead of
    ///   production. Staging issues untrusted certificates but has much more lenient rate limits.
    ///
    /// # Returns
    /// An `Arc<AcmeManager>` so it can be cheaply shared between the background renewal
    /// task and the calling code that needs the [`resolver`][Self::resolver].
    pub fn new(
        cache_dir: impl Into<PathBuf>,
        domains: Vec<String>,
        email: String,
        is_staging: bool,
    ) -> Arc<Self> {
        let cache_dir = cache_dir.into();
        if let Err(e) = fs::create_dir_all(&cache_dir) {
            error!(
                "[acme] Failed to create cache directory {:?}: {e}",
                cache_dir
            );
        }
        Arc::new(Self {
            domains,
            email,
            cache_dir,
            is_staging,
            resolver: Arc::new(AcmeResolver::new()),
            provisioning: tokio::sync::Mutex::new(()),
        })
    }

    /// Returns the [`AcmeResolver`] that should be passed to [`rustls::ServerConfig`].
    ///
    /// Wire this into your TLS configuration:
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use tachyon_web::tls::acme::AcmeManager;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let acme = AcmeManager::new("/tmp/certs", vec!["example.com".into()], "admin@example.com".into(), true);
    /// let resolver = acme.resolver();
    ///
    /// let tls_config = rustls::ServerConfig::builder()
    ///     .with_no_client_auth()
    ///     .with_cert_resolver(resolver);
    /// # Ok(())
    /// # }
    /// ```
    pub fn resolver(&self) -> Arc<AcmeResolver> {
        self.resolver.clone()
    }

    /// Spawns the background certificate management loop as a Tokio task.
    ///
    /// The loop runs indefinitely:
    /// 1. Checks whether a valid cached certificate exists and loads it.
    /// 2. If the certificate is missing or expiring soon, provisions a new one from ACME.
    /// 3. Sleeps for 24 hours, then repeats.
    ///
    /// Provisioning failures use exponential backoff instead of immediately retrying
    /// to respect Let's Encrypt rate limits.
    ///
    /// # Panics
    /// Never panics. All errors are logged via [`tracing`].
    pub fn start(self: Arc<Self>) {
        drop(tokio::spawn(async move {
            self.run_loop().await;
        }));
    }

    /// Internal background loop. Runs forever with controlled sleep intervals.
    async fn run_loop(&self) {
        let mut backoff = BACKOFF_INITIAL;

        loop {
            let needs_provisioning = match self.load_and_activate_cached_cert() {
                Ok(true) => {
                    // Valid cert loaded and activated — reset backoff for next cycle.
                    backoff = BACKOFF_INITIAL;
                    false
                }
                Ok(false) => {
                    info!("[acme] No valid cached certificate — provisioning new one");
                    true
                }
                Err(e) => {
                    warn!("[acme] Error loading cached certificate: {e}");
                    true
                }
            };

            if needs_provisioning {
                match self.provision_cert().await {
                    Ok((certs, key)) => {
                        info!("[acme] Successfully provisioned new certificate from Let's Encrypt");
                        match Self::build_certified_key(certs, key) {
                            Ok(certified_key) => {
                                self.resolver.update_cert(certified_key);
                                backoff = BACKOFF_INITIAL; // success — reset backoff
                            }
                            Err(e) => {
                                error!(
                                    "[acme] Failed to build TLS signing key: {e}. Retrying in {:?}",
                                    backoff
                                );
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(BACKOFF_MAX);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "[acme] Certificate provisioning failed: {e}. Retrying in {:?}",
                            backoff
                        );
                        tokio::time::sleep(backoff).await;
                        // Exponential backoff, capped at BACKOFF_MAX.
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        continue; // Skip the CHECK_INTERVAL sleep on failure.
                    }
                }
            }

            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    }

    /// Loads the cached certificate from disk and activates it in the resolver.
    ///
    /// Returns `Ok(true)` if a valid (non-expiring) certificate was loaded,
    /// `Ok(false)` if the certificate is missing or about to expire,
    /// or `Err` if reading/parsing failed with an unexpected error.
    fn load_and_activate_cached_cert(&self) -> Result<bool, AcmeError> {
        let Ok((certs, key)) = self.load_cached_certs_and_key() else {
            return Ok(false); // Cache miss — silently request provisioning.
        };

        let Some(expiry) = Self::check_cert_expiry(&certs) else {
            return Ok(false);
        };

        if !Self::cert_matches_domains(&certs, &self.domains) {
            warn!(
                "[acme] Cached certificate in {:?} does not cover the configured domain set {:?} \
                 — discarding stale cache and re-provisioning",
                self.cache_dir, self.domains
            );
            return Ok(false);
        }

        let now = SystemTime::now();
        let time_remaining = expiry.duration_since(now).unwrap_or(Duration::ZERO);

        if expiry <= now || time_remaining <= RENEW_THRESHOLD {
            warn!(
                "[acme] Cached certificate expires in {:.1} days — triggering renewal",
                time_remaining.as_secs_f64() / 86400.0
            );
            return Ok(false);
        }

        info!(
            "[acme] Loaded cached certificate (expires in {:.1} days)",
            time_remaining.as_secs_f64() / 86400.0
        );

        let certified_key = Self::build_certified_key(certs, key)?;
        self.resolver.update_cert(certified_key);
        Ok(true)
    }

    /// Parses the `notAfter` field from the first DER certificate in the chain.
    ///
    /// Uses the small hand-rolled DER walker in [`min_der`] rather than a general-purpose
    /// X.509 parsing crate — see that module's docs for why.
    fn check_cert_expiry(certs: &[CertificateDer<'static>]) -> Option<SystemTime> {
        let first = certs.first()?;
        min_der::parse_not_after(first.as_ref())
            .inspect_err(|e| warn!("[acme] Failed to parse cached certificate: {e}"))
            .ok()
    }

    /// Verifies that every domain this manager is configured for is covered by the
    /// certificate's Subject Alternative Names.
    ///
    /// A cached certificate is only safe to reuse if it was actually issued for the
    /// domain set this instance is managing — an expiry check alone isn't enough: a
    /// still-valid cert left behind by a previous configuration (different domains
    /// pointed at the same `cache_dir`) would otherwise be silently activated for the
    /// wrong hostname.
    fn cert_matches_domains(certs: &[CertificateDer<'static>], domains: &[String]) -> bool {
        let Some(first) = certs.first() else {
            return false;
        };
        let Ok(cert) = EndEntityCert::try_from(first) else {
            return false;
        };
        let san_names: Vec<String> = cert
            .valid_dns_names()
            .map(str::to_ascii_lowercase)
            .collect();
        !san_names.is_empty()
            && domains
                .iter()
                .all(|d| san_names.contains(&d.to_ascii_lowercase()))
    }

    /// Reads PEM-encoded cert and key from `<cache_dir>/domain.crt` and `domain.key`.
    fn load_cached_certs_and_key(
        &self,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), AcmeError> {
        let cert_path = self.cache_dir.join("domain.crt");
        let key_path = self.cache_dir.join("domain.key");

        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;

        let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(std::result::Result::ok)
            .collect();

        let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
        let key =
            rustls_pemfile::private_key(&mut key_reader)?.ok_or(AcmeError::MissingPrivateKey)?;

        Ok((certs, key))
    }

    /// Atomically writes the PEM cert chain and private key to the cache directory.
    ///
    /// Both files are written independently; if the key write fails the cert file is
    /// still present. On next startup the loader will fail to parse the key and
    /// re-provision — no data corruption risk.
    ///
    /// The private key is written with owner-only permissions (`0600` on Unix) so it
    /// is never left world- or group-readable on disk.
    fn save_certs_and_key(&self, cert_pem: &str, key_pem: &str) -> Result<(), AcmeError> {
        fs::write(self.cache_dir.join("domain.crt"), cert_pem)?;
        let key_path = self.cache_dir.join("domain.key");
        write_private_file(&key_path, key_pem.as_bytes())?;
        Ok(())
    }

    /// Constructs a `rustls` [`CertifiedKey`] from DER-encoded certificates and a private key.
    fn build_certified_key(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<CertifiedKey, AcmeError> {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| AcmeError::TlsKeyLoad(e.to_string()))?;
        Ok(CertifiedKey::new(certs, signing_key))
    }

    /// Runs the full ACME HTTP-01 challenge flow and returns the new certificate chain + key.
    ///
    /// A mutex guard prevents two concurrent `provision_cert` calls (both driven by
    /// [`run_loop`][Self::run_loop] today) from racing each other — e.g. two overlapping
    /// HTTP-01 challenge flows stomping on each other's [`ACTIVE_CHALLENGES`] entries.
    async fn provision_cert(
        &self,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), AcmeError> {
        // Prevent concurrent provisioning attempts. tokio::sync::Mutex is used here
        // because std::sync::MutexGuard is not Send across .await points.
        let _guard = self.provisioning.lock().await;

        let directory_url = if self.is_staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        };

        // 1. Load or create an ACME account (scoped to staging vs production).
        let account = self.get_or_create_account(directory_url).await?;

        // 2. Create a new order for all configured domains.
        let identifiers: Vec<Identifier> = self
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let new_order = NewOrder::new(&identifiers);
        let mut order = account.new_order(&new_order).await?;

        // 3. Complete all HTTP-01 authorizations.
        let mut tokens_to_unregister: Vec<String> = Vec::new();
        {
            let mut auths = order.authorizations();
            while let Some(auth_res) = auths.next().await {
                let mut auth = auth_res?;
                let mut challenge = auth.challenge(ChallengeType::Http01).ok_or_else(|| {
                    AcmeError::Io(std::io::Error::other(
                        "No HTTP-01 challenge offered by CA — ensure port 80 is reachable",
                    ))
                })?;

                let key_auth = challenge.key_authorization().as_str().to_string();
                let token = challenge.token.clone();

                register_challenge(token.clone(), key_auth);
                tokens_to_unregister.push(token);

                // Signal ACME server that it may now probe the challenge endpoint.
                challenge.set_ready().await?;
            }
        }

        // 4. Poll until the order is valid (or failed).
        let status = order
            .poll_ready(&instant_acme::RetryPolicy::default())
            .await?;

        // Unregister all challenge tokens regardless of outcome.
        for token in &tokens_to_unregister {
            unregister_challenge(token);
        }

        if status == OrderStatus::Invalid {
            return Err(AcmeError::OrderInvalid);
        }

        // 5. Generate a new ECDSA P-256 key pair and CSR for the certificate.
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert_params = CertificateParams::new(self.domains.clone())?;
        let csr = cert_params.serialize_request(&key_pair)?;

        // 6. Finalize the order by submitting the CSR.
        order.finalize_csr(csr.der().as_ref()).await?;

        // 7. Download the signed certificate chain from the CA.
        let cert_chain_pem = order
            .poll_certificate(&instant_acme::RetryPolicy::default())
            .await?;
        let private_key_pem = key_pair.serialize_pem();

        // 8. Persist to disk for future restarts.
        if let Err(e) = self.save_certs_and_key(&cert_chain_pem, &private_key_pem) {
            error!("[acme] Failed to persist certificate to cache directory: {e}");
        }

        // 9. Parse PEM → DER for immediate use in rustls.
        let mut cert_reader = std::io::BufReader::new(cert_chain_pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(std::result::Result::ok)
            .collect();

        let mut key_reader = std::io::BufReader::new(private_key_pem.as_bytes());
        let key =
            rustls_pemfile::private_key(&mut key_reader)?.ok_or(AcmeError::MissingPrivateKey)?;

        Ok((certs, key))
    }

    /// Loads existing ACME account credentials from `<cache_dir>/account-{staging|prod}.json`
    /// or creates a new account and caches the credentials.
    ///
    /// The file name is scoped by environment so that staging and production accounts
    /// can coexist in the same cache directory without interfering.
    async fn get_or_create_account(&self, directory_url: &str) -> Result<Account, AcmeError> {
        // Use separate credential files per environment to avoid mixing staging/prod accounts.
        let env_suffix = if self.is_staging { "staging" } else { "prod" };
        let account_path = self.cache_dir.join(format!("account-{env_suffix}.json"));

        if account_path.exists() {
            match fs::read(&account_path) {
                Ok(creds_bytes) => {
                    match serde_json::from_slice::<AccountCredentials>(&creds_bytes) {
                        Ok(creds) => {
                            let builder = Account::builder()?;
                            match builder.from_credentials(creds).await {
                                Ok(account) => {
                                    info!("[acme] Reusing cached ACME account ({env_suffix})");
                                    return Ok(account);
                                }
                                Err(e) => {
                                    warn!(
                                        "[acme] Cached account credentials invalid, creating new: {e}"
                                    );
                                }
                            }
                        }
                        Err(e) => warn!("[acme] Failed to parse cached account credentials: {e}"),
                    }
                }
                Err(e) => warn!("[acme] Failed to read account credentials file: {e}"),
            }
        }

        // Create a new ACME account.
        info!("[acme] Registering new ACME account with Let's Encrypt ({env_suffix})");
        let contact = [format!("mailto:{}", self.email)];
        let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
        let builder = Account::builder()?;
        let (account, creds) = builder
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url.to_string(),
                None,
            )
            .await?;

        // Persist credentials. If this fails, warn but don't fail the overall flow —
        // provisioning can still succeed; we'll just re-register next restart.
        let creds_bytes = serde_json::to_vec(&creds)?;
        if let Err(e) = write_private_file(&account_path, &creds_bytes) {
            warn!("[acme] Failed to cache account credentials: {e}");
        }

        Ok(account)
    }
}

/// Minimal, purpose-built DER reader for extracting a certificate's `notAfter`
/// timestamp — nothing else.
///
/// # Why this exists instead of a general X.509-parsing crate
///
/// The only certificate this module ever parses is one this process itself wrote to
/// `<cache_dir>/domain.crt` after a successful ACME order (see
/// [`AcmeManager::provision_cert`]) — never arbitrary, unauthenticated network input.
/// Pulling in a full X.509/ASN.1 parsing stack (`x509-parser`, plus its own
/// `der-parser`/`asn1-rs`/`nom`/`oid-registry`/`num-bigint` dependency tree — over a
/// dozen extra crates) just to read one timestamp field out of our own
/// previously-issued certificate was disproportionate. This walks the handful of DER
/// TLVs needed to reach `TBSCertificate.validity.notAfter` and nothing else; SAN
/// parsing (a genuinely more involved structure) is instead delegated to
/// [`cert_matches_domains`] via `rustls-webpki`'s public, already-linked-through-`rustls`
/// `EndEntityCert::valid_dns_names()`.
///
/// X.509 certificates are always definite-length DER (never indefinite-length BER),
/// so this only needs to handle short- and long-form DER lengths — no indefinite
/// length, no BER quirks.
mod min_der {
    use std::time::{Duration, SystemTime};

    /// Reads one DER TLV starting at `pos`, returning `(tag, content, end)` where
    /// `end` is the offset in `buf` just past the whole TLV (header + content).
    fn read_tlv(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize), &'static str> {
        let tag = *buf.get(pos).ok_or("truncated DER: missing tag")?;
        let len_byte = *buf.get(pos + 1).ok_or("truncated DER: missing length")?;
        let (len, header_len) = if len_byte & 0x80 == 0 {
            (usize::from(len_byte), 2usize)
        } else {
            // Long form: low 7 bits count the number of following length bytes.
            // Real certificates never need more than a couple of these (a cert
            // would have to be >16 MiB to need a 3rd byte); cap at 4 bytes (up
            // to a 4 GiB length) purely as a sanity bound against malformed input.
            let n = usize::from(len_byte & 0x7f);
            if n == 0 || n > 4 {
                return Err("unsupported DER length encoding");
            }
            let start = pos + 2;
            let bytes = buf
                .get(start..start + n)
                .ok_or("truncated DER: missing length bytes")?;
            let mut len = 0usize;
            for &b in bytes {
                len = len
                    .checked_shl(8)
                    .and_then(|v| v.checked_add(usize::from(b)))
                    .ok_or("DER length overflow")?;
            }
            (len, 2 + n)
        };
        let content_start = pos + header_len;
        let content_end = content_start
            .checked_add(len)
            .ok_or("DER length overflow")?;
        let content = buf
            .get(content_start..content_end)
            .ok_or("truncated DER: content shorter than declared length")?;
        Ok((tag, content, content_end))
    }

    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_CONTEXT_0: u8 = 0xA0;
    const TAG_UTC_TIME: u8 = 0x17;
    const TAG_GENERALIZED_TIME: u8 = 0x18;

    /// Extracts `TBSCertificate.validity.notAfter` from a DER-encoded X.509 certificate.
    pub(super) fn parse_not_after(cert_der: &[u8]) -> Result<SystemTime, &'static str> {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        let (tag, cert_content, _) = read_tlv(cert_der, 0)?;
        if tag != TAG_SEQUENCE {
            return Err("not a DER SEQUENCE (Certificate)");
        }
        // TBSCertificate ::= SEQUENCE { version?, serialNumber, signature, issuer, validity, ... }
        let (tag, tbs, _) = read_tlv(cert_content, 0)?;
        if tag != TAG_SEQUENCE {
            return Err("not a DER SEQUENCE (TBSCertificate)");
        }

        // Optional `[0] EXPLICIT Version` — present on v3 certs, absent on v1.
        let (tag, _, next) = read_tlv(tbs, 0)?;
        let pos = if tag == TAG_CONTEXT_0 { next } else { 0 };

        // serialNumber INTEGER
        let (tag, _, pos) = read_tlv(tbs, pos)?;
        if tag != TAG_INTEGER {
            return Err("expected serialNumber INTEGER");
        }
        // signature AlgorithmIdentifier ::= SEQUENCE
        let (tag, _, pos) = read_tlv(tbs, pos)?;
        if tag != TAG_SEQUENCE {
            return Err("expected signature AlgorithmIdentifier SEQUENCE");
        }
        // issuer Name ::= SEQUENCE
        let (tag, _, pos) = read_tlv(tbs, pos)?;
        if tag != TAG_SEQUENCE {
            return Err("expected issuer Name SEQUENCE");
        }
        // validity Validity ::= SEQUENCE { notBefore, notAfter }
        let (tag, validity, _) = read_tlv(tbs, pos)?;
        if tag != TAG_SEQUENCE {
            return Err("expected validity SEQUENCE");
        }

        // notBefore Time — skip.
        let (_, _, pos) = read_tlv(validity, 0)?;
        // notAfter Time — decode.
        let (tag, time, _) = read_tlv(validity, pos)?;
        match tag {
            TAG_UTC_TIME => parse_utc_time(time),
            TAG_GENERALIZED_TIME => parse_generalized_time(time),
            _ => Err("notAfter is neither UTCTime nor GeneralizedTime"),
        }
    }

    fn parse_utc_time(b: &[u8]) -> Result<SystemTime, &'static str> {
        // UTCTime, RFC 5280 profile: `YYMMDDHHMMSSZ` — always UTC, always seconds, always `Z`.
        if b.len() != 13 || b[12] != b'Z' {
            return Err("malformed UTCTime");
        }
        // RFC 5280's Y2K pivot rule: YY >= 50 means 19YY, otherwise 20YY.
        let yy = two_digits(&b[0..2])?;
        let year = i64::from(if yy >= 50 { 1900 + yy } else { 2000 + yy });
        ymdhms_to_system_time(
            year,
            two_digits(&b[2..4])?,
            two_digits(&b[4..6])?,
            two_digits(&b[6..8])?,
            two_digits(&b[8..10])?,
            two_digits(&b[10..12])?,
        )
    }

    fn parse_generalized_time(b: &[u8]) -> Result<SystemTime, &'static str> {
        // GeneralizedTime, RFC 5280 profile: `YYYYMMDDHHMMSSZ` — no fractional seconds.
        if b.len() != 15 || b[14] != b'Z' {
            return Err("malformed GeneralizedTime");
        }
        let year = i64::from(two_digits(&b[0..2])?) * 100 + i64::from(two_digits(&b[2..4])?);
        ymdhms_to_system_time(
            year,
            two_digits(&b[4..6])?,
            two_digits(&b[6..8])?,
            two_digits(&b[8..10])?,
            two_digits(&b[10..12])?,
            two_digits(&b[12..14])?,
        )
    }

    fn two_digits(b: &[u8]) -> Result<u32, &'static str> {
        let [hi, lo] = *b else {
            return Err("expected two ASCII digits");
        };
        if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
            return Err("expected two ASCII digits");
        }
        Ok(u32::from(hi - b'0') * 10 + u32::from(lo - b'0'))
    }

    /// Converts a UTC calendar date/time (as decoded from DER) into a `SystemTime`,
    /// using the standard proleptic-Gregorian civil-calendar-to-days-since-epoch
    /// formula (Howard Hinnant's `days_from_civil`, a widely published public-domain
    /// algorithm — not copied from any particular implementation).
    fn ymdhms_to_system_time(
        year: i64,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Result<SystemTime, &'static str> {
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err("month/day out of range");
        }
        if hour > 23 || minute > 59 || second > 60 {
            return Err("time-of-day out of range");
        }
        let days = days_from_civil(year, i64::from(month), i64::from(day));
        let secs_of_day = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
        let total_secs = days
            .checked_mul(86_400)
            .and_then(|d| d.checked_add(secs_of_day))
            .ok_or("date arithmetic overflow")?;
        // Certificates with a notAfter before 1970 aren't something we can (or need
        // to) support: we only ever compare this against `SystemTime::now()`.
        let total_secs = u64::try_from(total_secs).map_err(|_| "date before the Unix epoch")?;
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(total_secs))
    }

    /// Days since 1970-01-01 for a given proleptic-Gregorian civil date.
    const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = (if y >= 0 { y } else { y - 399 }) / 400;
        let yoe = y - era * 400; // [0, 399]
        let mp = (m + 9) % 12; // [0, 11], Mar=0 .. Feb=11
        let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146_097 + doe - 719_468
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used)]
        use super::*;

        #[test]
        fn epoch_day_zero() {
            assert_eq!(days_from_civil(1970, 1, 1), 0);
        }

        #[test]
        fn known_dates() {
            // 2024-01-01 is 19723 days after the epoch.
            assert_eq!(days_from_civil(2024, 1, 1), 19723);
            // Leap-day handling: 2024 is a leap year, so 2024-02-29 exists.
            assert_eq!(
                days_from_civil(2024, 3, 1) - days_from_civil(2024, 2, 29),
                1
            );
        }

        #[test]
        fn utc_time_roundtrip() {
            let t = parse_utc_time(b"991231235959Z").unwrap();
            let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            // 1999-12-31 23:59:59 UTC
            assert_eq!(secs, 946_684_799);
        }

        #[test]
        fn utc_time_y2k_pivot() {
            // "49" -> 2049 (post-epoch, decodable); "50" -> 1950 (pre-epoch, rejected
            // by design — see `ymdhms_to_system_time`).
            assert!(parse_utc_time(b"490101000000Z").is_ok());
            assert!(parse_utc_time(b"500101000000Z").is_err());
        }

        #[test]
        fn generalized_time_roundtrip() {
            let t = parse_generalized_time(b"20991231235959Z").unwrap();
            let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            assert_eq!(secs, 4_102_444_799);
        }

        #[test]
        fn rejects_malformed_input() {
            assert!(parse_utc_time(b"not-a-time!!!").is_err());
            assert!(parse_generalized_time(b"short").is_err());
            assert!(parse_not_after(b"").is_err());
            assert!(parse_not_after(&[0x30, 0x00]).is_err());
        }

        /// End-to-end: generate a real cert with `rcgen` (already a dependency of
        /// the `cert-gen` feature that `lets-encrypt` requires) and confirm the
        /// full DER walk (`SEQUENCE` -> `TBSCertificate` -> ... -> `Validity` ->
        /// `notAfter`) lands on a sane result.
        #[test]
        #[cfg(feature = "cert-gen")]
        fn parses_notafter_from_a_real_certificate() {
            use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

            let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
            let cert = params.self_signed(&key_pair).unwrap();

            // rcgen's default `not_after` is far in the future (year 4096) — check
            // we land somewhere plausible rather than pinning the exact instant, so
            // this test isn't fragile to rcgen ever changing its default.
            let parsed = parse_not_after(cert.der().as_ref()).unwrap();
            let year_2170 = SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 365 * 200);
            assert!(
                parsed > year_2170,
                "expected a far-future notAfter, got {parsed:?}"
            );
        }
    }
}
