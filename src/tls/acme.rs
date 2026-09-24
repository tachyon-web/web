//! In-process ACME client for Let's Encrypt: account setup, HTTP-01 issuance, and renewal.
//!
//! Accounts are cached to disk per environment (staging vs production) so restarts reuse the
//! same registration. Challenge tokens are answered by the HTTP listener
//! [`crate::server::Server::serve_all_acme`] binds; no external CLI is involved. [`AcmeResolver`]
//! implements [`rustls::server::ResolvesServerCert`], so a renewed certificate swaps in without
//! a restart. A background task checks every 24 hours and renews inside the 30-day window,
//! backing off exponentially on failure to stay clear of the rate limits.

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use crate::{telemetry_error as error, telemetry_info as info, telemetry_warn as warn};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, BodyWrapper, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use webpki::EndEntityCert;

/// Atomically replaces `path` with `contents`, owner-only (`0600` on Unix) from the moment
/// the temporary file is created — no window where a key or credential is readable by others,
/// and a symlink at `path` is replaced rather than followed.
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private file has no parent",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "private file has no name")
    })?;

    for _ in 0..16 {
        let suffix = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            suffix
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = options.mode(0o600);
        }

        let mut file = match options.open(&temp_path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let result = (|| {
            file.write_all(contents)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        return result;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a private temporary file",
    ))
}

const MAX_CACHE_FILE_SIZE: u64 = 1024 * 1024;

fn read_bounded_string(path: &std::path::Path) -> std::io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CACHE_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ACME cache entry is not a regular file or exceeds 1 MiB",
        ));
    }
    fs::read_to_string(path)
}

fn validate_cache_directory(path: &std::path::Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cache path must be a real directory, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cache directory must not grant group or other access",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if metadata.uid() != fs::metadata("/proc/self")?.uid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cache directory is not owned by the current process user",
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod private_file_tests {
    use super::write_private_file;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[test]
    fn private_file_replaces_links_atomically_with_owner_only_permissions() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let target = dir.path().join("target");
        let secret = dir.path().join("secret");
        std::fs::write(&target, b"untouched").expect("write target");
        std::os::unix::fs::symlink(&target, &secret).expect("create symlink");

        write_private_file(&secret, b"private").expect("write private file");

        assert_eq!(std::fs::read(&target).expect("read target"), b"untouched");
        assert_eq!(std::fs::read(&secret).expect("read secret"), b"private");
        let metadata = std::fs::symlink_metadata(&secret).expect("inspect private file");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
}

/// Active HTTP-01 challenges, `token → key_authorization`. Read-mostly: contended only
/// during the brief provisioning window.
static ACTIVE_CHALLENGES: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

#[inline]
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

/// Dynamic `rustls` certificate resolver that serves the most recently provisioned
/// certificate during every TLS handshake.
///
/// This allows zero-downtime certificate hot-swap: simply call [`AcmeResolver::update_cert`]
/// with the new [`CertifiedKey`] and all subsequent connections will use it immediately,
/// without restarting the listener.
///
/// # Thread safety
/// All accesses are protected by an inner [`RwLock`]; reads (handshakes) never block
/// each other, and writes happen only when the renewal loop (re)loads a certificate.
///
/// *Tachyon extension: no `axum` equivalent.*
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
                info!("[acme] certificate hot-swapped into TLS resolver");
            }
            Err(e) => error!("[acme] failed to update certificate in resolver: {e}"),
        }
    }

    /// Returns `true` if a certificate has been loaded into this resolver.
    pub fn has_certificate(&self) -> bool {
        self.current_key.read().is_ok_and(|g| g.is_some())
    }
}

impl Default for AcmeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for AcmeResolver {
    /// Called by `rustls` on every TLS handshake: a read-lock and an `Arc` clone.
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current_key.read().ok()?.clone()
    }
}

/// Errors that can occur during ACME certificate management.
///
/// *Tachyon extension: no `axum` equivalent.*
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
    /// Certificate parsing failed.
    CertParse(String),
    /// TLS signing key could not be loaded from the private key.
    TlsKeyLoad(String),
    /// The certificate cache directory does not meet local security requirements.
    InsecureCache(String),
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
            Self::InsecureCache(s) => write!(f, "Insecure ACME cache: {s}"),
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
///
/// *Tachyon extension: no `axum` equivalent.*
#[derive(Debug)]
pub struct AcmeManager {
    domains: Vec<String>,
    email: String,
    cache_dir: PathBuf,
    is_staging: bool,
    resolver: Arc<AcmeResolver>,
    /// The provider signing keys are loaded through — see [`AcmeManager::with_policy`].
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Serializes provisioning runs. `tokio::sync::Mutex` because the guard is held across
    /// awaits.
    provisioning: tokio::sync::Mutex<()>,
    cache_error: Option<String>,
}

/// Minimum time remaining before renewal is triggered.
const RENEW_THRESHOLD: Duration = Duration::from_hours(30 * 24); // 30 days
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

impl AcmeManager {
    /// Creates an `AcmeManager`, creating `cache_dir` if it does not exist.
    ///
    /// `cache_dir` holds the account credentials and the certificate/key pair and must be
    /// writable; keeping it across restarts is what avoids re-registering. `domains` become the
    /// certificate's SANs — no Subject/CN is set, since clients validate against SANs. Setting
    /// `is_staging` targets `acme-staging-v02.api.letsencrypt.org`: untrusted certificates,
    /// much looser rate limits.
    pub fn new(
        cache_dir: impl Into<PathBuf>,
        domains: Vec<String>,
        email: String,
        is_staging: bool,
    ) -> Arc<Self> {
        Self::with_policy(
            cache_dir,
            domains,
            email,
            is_staging,
            &crate::tls::TlsPolicy::default(),
        )
    }

    /// [`new`](Self::new), with the signing key loaded through `policy`'s crypto provider
    /// instead of [`TlsPolicy::new`](crate::tls::TlsPolicy::new)'s.
    ///
    /// [`Server::serve_all_acme`](crate::server::Server::serve_all_acme) passes its own
    /// effective policy, so a `fips`/custom provider covers the issued certificate too.
    pub fn with_policy(
        cache_dir: impl Into<PathBuf>,
        domains: Vec<String>,
        email: String,
        is_staging: bool,
        policy: &crate::tls::TlsPolicy,
    ) -> Arc<Self> {
        let cache_dir = cache_dir.into();
        let cache_existed = cache_dir.exists();
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            let _ = directory.mode(0o700);
        }
        if let Err(e) = directory.create(&cache_dir) {
            error!(
                "[acme] failed to create cache directory {:?}: {e}",
                cache_dir
            );
        }
        #[cfg(unix)]
        if !cache_existed {
            use std::os::unix::fs::PermissionsExt as _;
            if let Err(e) = fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)) {
                error!("[acme] failed to secure cache directory {cache_dir:?}: {e}");
            }
        }
        let cache_error = validate_cache_directory(&cache_dir)
            .err()
            .map(|e| e.to_string());
        if let Some(error) = &cache_error {
            error!("[acme] refusing insecure cache directory: {error}");
        }
        Arc::new(Self {
            domains,
            email,
            cache_dir,
            is_staging,
            resolver: Arc::new(AcmeResolver::new()),
            provider: policy.provider(),
            provisioning: tokio::sync::Mutex::new(()),
            cache_error,
        })
    }

    /// Returns an error when the cache directory is unsafe for credentials or private keys.
    ///
    /// # Errors
    ///
    /// Returns [`AcmeError::InsecureCache`] when validation during construction failed.
    pub fn validate_cache(&self) -> Result<(), AcmeError> {
        self.cache_error
            .as_ref()
            .map_or(Ok(()), |error| Err(AcmeError::InsecureCache(error.clone())))
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
    /// The task is detached and runs for the life of the runtime. Errors are logged only with
    /// the `telemetry` feature; without it a failing order is silent.
    pub fn start(self: Arc<Self>) {
        drop(self.spawn_task());
    }

    pub(crate) fn start_guarded(self: Arc<Self>) -> crate::server::BackgroundTask {
        crate::server::BackgroundTask::new(self.spawn_task())
    }

    fn spawn_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run_loop().await;
        })
    }

    /// The renewal loop. The active certificate's expiry is tracked in memory, so a cache
    /// write that failed neither triggers a daily re-order nor lets an older cached
    /// certificate replace the one being served.
    async fn run_loop(&self) {
        if let Err(e) = self.validate_cache() {
            error!("[acme] certificate manager stopped: {e}");
            return;
        }
        let mut backoff = BACKOFF_INITIAL;
        let mut active_expiry: Option<SystemTime> = None;

        loop {
            if active_expiry.is_none_or(renewal_due) {
                active_expiry = self.load_and_activate_cached_cert().unwrap_or_else(|e| {
                    warn!("[acme] error loading cached certificate: {e}");
                    None
                });
            }
            if active_expiry.is_none_or(renewal_due) {
                match self.provision_and_activate().await {
                    Ok(expiry) => active_expiry = expiry,
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

    /// Orders a new certificate, activates it, and returns its expiry.
    async fn provision_and_activate(&self) -> Result<Option<SystemTime>, AcmeError> {
        info!("[acme] provisioning a new certificate");
        let (certs, key) = self.provision_cert().await?;
        let expiry = Self::check_cert_expiry(&certs);
        self.resolver
            .update_cert(self.build_certified_key(certs, key)?);
        info!("[acme] provisioned new certificate");
        Ok(expiry)
    }

    /// Loads the cached certificate from disk, activates it if it is still valid, and returns
    /// its expiry.
    ///
    /// `Ok(None)` means nothing was activated: the certificate is missing, unparsable, covers
    /// the wrong domains, or has expired. A certificate inside the renewal window is still
    /// activated, so a failing renewal doesn't take the listener down with it.
    fn load_and_activate_cached_cert(&self) -> Result<Option<SystemTime>, AcmeError> {
        let Ok((certs, key)) = self.load_cached_certs_and_key() else {
            return Ok(None);
        };
        let Some(expiry) = Self::check_cert_expiry(&certs) else {
            return Ok(None);
        };
        if !Self::cert_matches_domains(&certs, &self.domains) {
            warn!(
                "[acme] Cached certificate in {:?} does not cover the configured domain set {:?} \
                 — discarding stale cache and re-provisioning",
                self.cache_dir, self.domains
            );
            return Ok(None);
        }
        let Some(time_remaining) = expiry
            .duration_since(SystemTime::now())
            .ok()
            .filter(|remaining| !remaining.is_zero())
        else {
            warn!("[acme] Cached certificate has expired");
            return Ok(None);
        };

        self.resolver
            .update_cert(self.build_certified_key(certs, key)?);
        info!(
            "[acme] Loaded cached certificate (expires in {:.1} days)",
            time_remaining.as_secs_f64() / 86400.0
        );
        Ok(Some(expiry))
    }

    /// Parses the `notAfter` field from the first DER certificate in the chain.
    ///
    /// Uses the small hand-rolled DER walker in [`min_der`] rather than a general-purpose
    /// X.509 parsing crate — see that module's docs for why.
    fn check_cert_expiry(certs: &[CertificateDer<'static>]) -> Option<SystemTime> {
        let first = certs.first()?;
        min_der::parse_not_after(first.as_ref())
            .inspect_err(|e| warn!("[acme] failed to parse cached certificate: {e}"))
            .ok()
    }

    /// Verifies that the certificate's Subject Alternative Names exactly match the domains
    /// this manager is configured for.
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
        let mut san_names: Vec<String> = cert
            .valid_dns_names()
            .map(str::to_ascii_lowercase)
            .collect();
        let mut expected: Vec<String> = domains
            .iter()
            .map(|domain| domain.to_ascii_lowercase())
            .collect();
        san_names.sort_unstable();
        san_names.dedup();
        expected.sort_unstable();
        expected.dedup();
        !san_names.is_empty() && san_names == expected
    }

    /// Reads PEM-encoded cert and key from `<cache_dir>/domain.crt` and `domain.key`.
    fn load_cached_certs_and_key(
        &self,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), AcmeError> {
        let cert_path = self.cache_dir.join("domain.crt");
        let key_path = self.cache_dir.join("domain.key");

        let cert_pem = read_bounded_string(&cert_path)?;
        let key_pem = read_bounded_string(&key_path)?;

        let certs: Vec<CertificateDer<'static>> = crate::tls::pem::certs(cert_pem.as_bytes());
        let key = crate::tls::pem::private_key(key_pem.as_bytes())
            .map_err(|_| AcmeError::MissingPrivateKey)?;

        Ok((certs, key))
    }

    /// Atomically writes the PEM cert chain and private key to the cache directory.
    ///
    /// Both files are written independently, so a failed key write leaves the new cert beside
    /// the old key. [`build_certified_key`](Self::build_certified_key) rejects that pair, which
    /// sends the loader back to provisioning.
    ///
    /// The private key is written with owner-only permissions (`0600` on Unix) so it
    /// is never left world- or group-readable on disk.
    fn save_certs_and_key(&self, cert_pem: &str, key_pem: &str) -> Result<(), AcmeError> {
        write_private_file(&self.cache_dir.join("domain.crt"), cert_pem.as_bytes())?;
        let key_path = self.cache_dir.join("domain.key");
        write_private_file(&key_path, key_pem.as_bytes())?;
        Ok(())
    }

    /// Constructs a `rustls` [`CertifiedKey`] from DER-encoded certificates and a private key.
    ///
    /// Loaded through this manager's own provider, not a stock one: under `fips` those are
    /// different modules, and using the wrong one silently voids the guarantee.
    fn build_certified_key(
        &self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<CertifiedKey, AcmeError> {
        let signing_key = self
            .provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| AcmeError::TlsKeyLoad(e.to_string()))?;
        let certified_key = CertifiedKey::new(certs, signing_key);
        certified_key
            .keys_match()
            .map_err(|e| AcmeError::TlsKeyLoad(e.to_string()))?;
        Ok(certified_key)
    }

    /// Runs the full ACME HTTP-01 challenge flow and returns the new certificate chain + key.
    ///
    /// Serialized, so two overlapping HTTP-01 flows can't stomp on each other's challenges.
    async fn provision_cert(
        &self,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), AcmeError> {
        // Guard is held across awaits, hence tokio's Mutex.
        let _guard = self.provisioning.lock().await;

        let directory_url = if self.is_staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        };

        // Account is scoped to staging vs production.
        let account = self.get_or_create_account(directory_url).await?;

        let identifiers: Vec<Identifier> = self
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let new_order = NewOrder::new(&identifiers);
        let mut order = account.new_order(&new_order).await?;

        let mut tokens_to_unregister: Vec<String> = Vec::new();
        let outcome = Self::run_http01_challenges(&mut order, &mut tokens_to_unregister).await;
        for token in &tokens_to_unregister {
            unregister_challenge(token);
        }

        if outcome? == OrderStatus::Invalid {
            return Err(AcmeError::OrderInvalid);
        }

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert_params = CertificateParams::new(self.domains.clone())?;
        let csr = cert_params.serialize_request(&key_pair)?;

        order.finalize_csr(csr.der().as_ref()).await?;

        let cert_chain_pem = order
            .poll_certificate(&instant_acme::RetryPolicy::default())
            .await?;
        let private_key_pem = key_pair.serialize_pem();

        if let Err(e) = self.save_certs_and_key(&cert_chain_pem, &private_key_pem) {
            error!("[acme] failed to persist certificate to cache directory: {e}");
        }

        let certs: Vec<CertificateDer<'static>> = crate::tls::pem::certs(cert_chain_pem.as_bytes());
        let key = crate::tls::pem::private_key(private_key_pem.as_bytes())
            .map_err(|_| AcmeError::MissingPrivateKey)?;

        Ok((certs, key))
    }

    /// Registers an HTTP-01 response per authorization, marks each ready, then waits for the
    /// order to leave the pending state.
    ///
    /// Every token lands in `tokens` before the fallible work that follows it, so
    /// [`provision_cert`][Self::provision_cert] can unregister them all however this returns.
    async fn run_http01_challenges(
        order: &mut instant_acme::Order,
        tokens: &mut Vec<String>,
    ) -> Result<OrderStatus, AcmeError> {
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
                tokens.push(token);

                // Signal ACME server that it may now probe the challenge endpoint.
                challenge.set_ready().await?;
            }
        }

        Ok(order
            .poll_ready(&instant_acme::RetryPolicy::default())
            .await?)
    }

    /// An [`AccountBuilder`] whose client talks to the CA through this manager's own provider
    /// (so `fips`/custom providers cover it) and the pinned `webpki-roots` set, since it only
    /// ever contacts Let's Encrypt.
    fn account_builder(&self) -> Result<AccountBuilder, AcmeError> {
        let connector = HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(self.provider.clone())
            .map_err(|e| AcmeError::Io(std::io::Error::other(e)))?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client: HyperClient<_, BodyWrapper<bytes::Bytes>> =
            HyperClient::builder(TokioExecutor::new()).build(connector);
        Ok(Account::builder_with_http(Box::new(AcmeHttpClient(client))))
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
            match read_bounded_string(&account_path) {
                Ok(creds_json) => match serde_json::from_str::<AccountCredentials>(&creds_json) {
                    Ok(creds) => {
                        let builder = self.account_builder()?;
                        match builder.from_credentials(creds).await {
                            Ok(account) => {
                                info!("[acme] reusing cached account ({env_suffix})");
                                return Ok(account);
                            }
                            Err(e) => {
                                warn!(
                                    "[acme] Cached account credentials invalid, creating new: {e}"
                                );
                            }
                        }
                    }
                    Err(e) => warn!("[acme] failed to parse cached account credentials: {e}"),
                },
                Err(e) => warn!("[acme] failed to read account credentials file: {e}"),
            }
        }

        // Create a new ACME account.
        info!("[acme] registering new account ({env_suffix})");
        let contact = [format!("mailto:{}", self.email)];
        let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
        let builder = self.account_builder()?;
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
            warn!("[acme] failed to cache account credentials: {e}");
        }

        Ok(account)
    }
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

/// Minimal DER reader for a certificate's `notAfter` — nothing else.
///
/// It only ever reads the certificate this process cached after an ACME order, so a full
/// X.509 stack isn't worth the dependency tree. SANs go through `rustls-webpki` instead.
/// X.509 is always definite-length DER, so only short- and long-form lengths are handled.
mod min_der {
    use std::num::Wrapping;
    use std::time::{Duration, SystemTime};

    /// Reads one DER TLV starting at `pos`, returning `(tag, content, end)` where
    /// `end` is the offset in `buf` just past the whole TLV (header + content).
    fn read_tlv(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize), &'static str> {
        let tag = *buf.get(pos).ok_or("truncated DER: missing tag")?;
        let pos_plus_1 = pos.checked_add(1).ok_or("DER offset overflow")?;
        let len_byte = *buf.get(pos_plus_1).ok_or("truncated DER: missing length")?;
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
            let start = pos.checked_add(2).ok_or("DER offset overflow")?;
            let end = start.checked_add(n).ok_or("DER offset overflow")?;
            let bytes = buf
                .get(start..end)
                .ok_or("truncated DER: missing length bytes")?;
            // `checked_mul`, not `checked_shl`: a shift only reports shifting by more bits
            // than the type has, not shifting significant bits off the top — so on 32-bit a
            // 4-byte length would wrap to something plausible.
            let mut len = 0usize;
            for &b in bytes {
                len = len
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(usize::from(b)))
                    .ok_or("DER length overflow")?;
            }
            (len, 2usize.checked_add(n).ok_or("DER offset overflow")?)
        };
        let content_start = pos.checked_add(header_len).ok_or("DER offset overflow")?;
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
        if b.len() != 13 || b.get(12) != Some(&b'Z') {
            return Err("malformed UTCTime");
        }
        // RFC 5280's Y2K pivot rule: YY >= 50 means 19YY, otherwise 20YY.
        let yy = two_digits(b.get(0..2).ok_or("malformed UTCTime")?)?;
        let year = i64::from(if yy >= 50 {
            (Wrapping(1900u32) + Wrapping(yy)).0
        } else {
            (Wrapping(2000u32) + Wrapping(yy)).0
        });
        ymdhms_to_system_time(
            year,
            two_digits(b.get(2..4).ok_or("malformed UTCTime")?)?,
            two_digits(b.get(4..6).ok_or("malformed UTCTime")?)?,
            two_digits(b.get(6..8).ok_or("malformed UTCTime")?)?,
            two_digits(b.get(8..10).ok_or("malformed UTCTime")?)?,
            two_digits(b.get(10..12).ok_or("malformed UTCTime")?)?,
        )
    }

    fn parse_generalized_time(b: &[u8]) -> Result<SystemTime, &'static str> {
        // GeneralizedTime, RFC 5280 profile: `YYYYMMDDHHMMSSZ` — no fractional seconds.
        if b.len() != 15 || b.get(14) != Some(&b'Z') {
            return Err("malformed GeneralizedTime");
        }
        let century = two_digits(b.get(0..2).ok_or("malformed GeneralizedTime")?)?;
        let year_in_century = two_digits(b.get(2..4).ok_or("malformed GeneralizedTime")?)?;
        // Bounded, range-checked two-digit groups — see the `Wrapping` note on `two_digits`.
        let year = i64::from((Wrapping(century) * Wrapping(100) + Wrapping(year_in_century)).0);
        ymdhms_to_system_time(
            year,
            two_digits(b.get(4..6).ok_or("malformed GeneralizedTime")?)?,
            two_digits(b.get(6..8).ok_or("malformed GeneralizedTime")?)?,
            two_digits(b.get(8..10).ok_or("malformed GeneralizedTime")?)?,
            two_digits(b.get(10..12).ok_or("malformed GeneralizedTime")?)?,
            two_digits(b.get(12..14).ok_or("malformed GeneralizedTime")?)?,
        )
    }

    fn two_digits(b: &[u8]) -> Result<u32, &'static str> {
        let [hi, lo] = *b else {
            return Err("expected two ASCII digits");
        };
        if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
            return Err("expected two ASCII digits");
        }
        // `Wrapping`, not raw `-`/`*`/`+`: the digits are already range-checked above so this
        // never actually wraps, but `clippy::arithmetic_side_effects` doesn't know that and
        // `Wrapping` is its documented way to say "this is deliberate, bounded arithmetic".
        let hi = Wrapping(u32::from(hi)) - Wrapping(u32::from(b'0'));
        let lo = Wrapping(u32::from(lo)) - Wrapping(u32::from(b'0'));
        Ok((hi * Wrapping(10) + lo).0)
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
        let leap_year =
            year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
        let days_in_month = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap_year => 29,
            2 => 28,
            _ => return Err("month/day out of range"),
        };
        if day == 0 || day > days_in_month {
            return Err("month/day out of range");
        }
        if hour > 23 || minute > 59 || second > 60 {
            return Err("time-of-day out of range");
        }
        let days = days_from_civil(year, i64::from(month), i64::from(day));
        // Bounded by the `hour`/`minute`/`second` checks above — see `two_digits` for why
        // `Wrapping` rather than raw arithmetic.
        let secs_of_day = (Wrapping(i64::from(hour)) * Wrapping(3600)
            + Wrapping(i64::from(minute)) * Wrapping(60)
            + Wrapping(i64::from(second)))
        .0;
        let total_secs = days
            .checked_mul(86_400)
            .and_then(|d| d.checked_add(secs_of_day))
            .ok_or("date arithmetic overflow")?;
        // Certificates with a notAfter before 1970 aren't something we can (or need
        // to) support: we only ever compare this against `SystemTime::now()`.
        let total_secs = u64::try_from(total_secs).map_err(|_| "date before the Unix epoch")?;
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(total_secs))
            .ok_or("date arithmetic overflow")
    }

    /// Days since 1970-01-01 for a given proleptic-Gregorian civil date.
    ///
    /// Uses `Wrapping` throughout — see `two_digits` for why — rather than raw arithmetic: the
    /// month/day range is validated by `ymdhms_to_system_time` before this is ever called, and
    /// the year range certificates can express (four-digit `GeneralizedTime`/two-digit
    /// `UTCTime` years) is nowhere near enough to overflow `i64`, so this never actually wraps.
    fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let (y, m, d) = (Wrapping(y), Wrapping(m), Wrapping(d));
        let y = if m.0 <= 2 { y - Wrapping(1) } else { y };
        let era = Wrapping(if y.0 >= 0 { y.0 } else { (y - Wrapping(399)).0 } / 400);
        let yoe = y - era * Wrapping(400); // [0, 399]
        let mp = Wrapping((m + Wrapping(9)).0 % 12); // [0, 11], Mar=0 .. Feb=11
        let doy = Wrapping((mp * Wrapping(153) + Wrapping(2)).0 / 5) + d - Wrapping(1); // [0, 365]
        let doe = yoe * Wrapping(365) + Wrapping(yoe.0 / 4) - Wrapping(yoe.0 / 100) + doy; // [0, 146096]
        (era * Wrapping(146_097) + doe - Wrapping(719_468)).0
    }

    #[cfg(test)]
    mod tests {
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
            assert!(parse_utc_time(b"230229000000Z").is_err());
            assert!(parse_utc_time(b"240230000000Z").is_err());
            assert!(parse_generalized_time(b"short").is_err());
            assert!(parse_generalized_time(b"21000229000000Z").is_err());
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

#[cfg(test)]
mod cache_tests {
    use super::{AcmeManager, write_private_file};

    #[test]
    fn cached_certificate_must_match_the_exact_domain_set() {
        let cert = crate::tls::generate_self_signed_cert(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
        ])
        .expect("generate cert");
        let certs = crate::tls::pem::certs(cert.cert_pem.as_bytes());

        assert!(AcmeManager::cert_matches_domains(
            &certs,
            &["WWW.EXAMPLE.COM".to_string(), "example.com".to_string()]
        ));
        assert!(!AcmeManager::cert_matches_domains(
            &certs,
            &["example.com".to_string()]
        ));
    }

    /// A failed key write strands the new cert beside the old key. That pair parses, covers the
    /// domains and is far from expiry, so only an explicit match check keeps it from being
    /// served — every handshake would fail until renewal came due months later.
    #[test]
    fn a_cached_cert_is_activated_only_with_its_own_key() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let domains = vec!["example.com".to_string()];
        let cert = crate::tls::generate_self_signed_cert(domains.clone()).expect("generate cert");
        let stale = crate::tls::generate_self_signed_cert(domains.clone()).expect("generate key");
        let write = |name: &str, pem: &str| {
            write_private_file(&dir.path().join(name), pem.as_bytes()).expect("write cache entry");
        };
        let acme = AcmeManager::new(dir.path(), domains, "admin@example.com".into(), true);

        write("domain.crt", &cert.cert_pem);
        write("domain.key", &stale.key_pem);
        assert!(acme.load_and_activate_cached_cert().is_err());
        assert!(!acme.resolver().has_certificate());

        write("domain.key", &cert.key_pem);
        assert!(
            acme.load_and_activate_cached_cert()
                .expect("matching pair loads")
                .is_some()
        );
        assert!(acme.resolver().has_certificate());
    }

    /// A cert inside the renewal window is still valid, so it must keep serving while renewal
    /// runs — otherwise a restart during a CA outage leaves every handshake failing for days.
    #[test]
    fn a_cert_due_for_renewal_is_served_until_replaced() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let domains = vec!["example.com".to_string()];
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("generate key pair");
        let mut params = rcgen::CertificateParams::new(domains.clone()).expect("cert params");
        params.not_after = std::time::SystemTime::now()
            .checked_add(std::time::Duration::from_hours(10 * 24))
            .expect("expiry fits")
            .into();
        let cert = params.self_signed(&key_pair).expect("self-sign");
        write_private_file(&dir.path().join("domain.crt"), cert.pem().as_bytes())
            .expect("write cert");
        write_private_file(
            &dir.path().join("domain.key"),
            key_pair.serialize_pem().as_bytes(),
        )
        .expect("write key");

        let acme = AcmeManager::new(dir.path(), domains, "admin@example.com".into(), true);
        let expiry = acme
            .load_and_activate_cached_cert()
            .expect("cached pair loads")
            .expect("a still-valid cert is activated");
        assert!(acme.resolver().has_certificate());
        assert!(
            super::renewal_due(expiry),
            "a cert inside the renewal window must still trigger renewal"
        );
    }
}
