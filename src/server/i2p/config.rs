//! [`I2pConfig`]: how [`Server::i2p`](crate::Server::i2p) publishes the app.

use std::path::PathBuf;
use tachyon_i2p::{CryptoType, I2pRouter, SigType};

use crate::Error;

/// An I2P eepsite publishing the app, added with [`Server::i2p`](crate::Server::i2p).
///
/// Plaintext by default — I2P already encrypts and authenticates the connection to the
/// `.b32.i2p` address. I2P streaming has no ports, so a destination serves one mode: with
/// [`tls`](Self::tls) it serves HTTPS only. The same `nickname` and
/// [`data_dir`](Self::data_dir) keep the same address across restarts.
///
/// See the [module docs](super) for the `forbid(unsafe_code)` disclosure that applies to this
/// whole feature.
pub struct I2pConfig {
    pub(super) nickname: String,
    pub(super) data_dir: Option<PathBuf>,
    pub(super) sig_type: SigType,
    pub(super) encryption_types: Vec<CryptoType>,
    pub(super) router: Option<I2pRouter>,
    #[cfg(feature = "tls")]
    pub(super) tls: Option<crate::tls::Tls>,
}

impl std::fmt::Debug for I2pConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("I2pConfig");
        let _ = out
            .field("nickname", &self.nickname)
            .field("data_dir", &self.data_dir)
            .field("sig_type", &self.sig_type)
            .field("encryption_types", &self.encryption_types)
            .field("router", &self.router.is_some());
        #[cfg(feature = "tls")]
        let _ = out.field("tls", &self.tls);
        out.finish()
    }
}

impl I2pConfig {
    /// Creates a new configuration for a service published under `nickname`. `nickname` also
    /// seeds libi2pd's own default data directory name (its router keys/netDb cache, separate
    /// from this eepsite's own persistent destination keys — see [`data_dir`](Self::data_dir)).
    ///
    /// Defaults: plaintext, keys at `./.tachyon-i2p/<nickname>.keys`,
    /// [`SigType::default`], and libi2pd's automatic encryption set (see
    /// [`crypto_type`](Self::crypto_type)).
    #[must_use]
    pub fn new(nickname: impl Into<String>) -> Self {
        Self {
            nickname: nickname.into(),
            data_dir: None,
            sig_type: SigType::default(),
            encryption_types: Vec::new(),
            router: None,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    /// Overrides the directory this eepsite's persistent destination keys file is stored under
    /// (as `<data_dir>/<nickname>.keys`). Reusing the same directory (and `nickname`) across
    /// restarts keeps the same `.b32.i2p` address. Defaults to `./.tachyon-i2p` relative to the
    /// current working directory.
    #[must_use]
    pub fn data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    /// Overrides the signature algorithm used when this destination's keys are **first**
    /// generated; an existing keys file keeps its own. Defaults to [`SigType::default`]
    /// (`Eddsa25519`).
    #[must_use]
    pub const fn signature_type(mut self, sig: SigType) -> Self {
        self.sig_type = sig;
        self
    }

    /// Advertises exactly one encryption algorithm — shorthand for
    /// [`encryption_types`](Self::encryption_types) with one entry.
    ///
    /// By default libi2pd publishes `ElGamal` + ECIES-X25519, plus ML-KEM-768+X25519 on a
    /// post-quantum-capable backend, which suits most callers.
    #[must_use]
    pub fn crypto_type(mut self, crypto: CryptoType) -> Self {
        self.encryption_types = vec![crypto];
        self
    }

    /// Overrides the encryption algorithms this destination's `LeaseSet2` advertises, on every
    /// run. The first entry is preferred; peers skip entries they don't understand, so later
    /// entries are fallbacks:
    ///
    /// ```rust,no_run
    /// use tachyon_web::server::i2p::I2pConfig;
    /// use tachyon_i2p::CryptoType;
    ///
    /// let config = I2pConfig::new("my-eepsite").encryption_types(&[
    ///     CryptoType::EciesMlkem1024X25519, // preferred: strongest post-quantum option
    ///     CryptoType::EciesX25519,          // fallback: peers that don't understand ML-KEM yet
    /// ]);
    /// ```
    ///
    /// An empty slice restores the default automatic hybrid set described on
    /// [`crypto_type`](Self::crypto_type)'s docs.
    #[must_use]
    pub fn encryption_types(mut self, types: &[CryptoType]) -> Self {
        self.encryption_types = types.to_vec();
        self
    }

    /// Publishes through an already-started router. Only one may run per process, so this is
    /// how a second eepsite shares it.
    #[must_use]
    pub fn router(mut self, router: I2pRouter) -> Self {
        self.router = Some(router);
        self
    }

    /// Serves HTTPS instead of plaintext, with these certificates. Their names always include
    /// the `.b32.i2p` address.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls(mut self, tls: crate::tls::Tls) -> Self {
        self.tls = Some(tls);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        validate_nickname(&self.nickname)?;
        #[cfg(feature = "tls")]
        if let Some(tls) = &self.tls {
            crate::tls::certs::validate(tls, true)?;
        }
        Ok(())
    }

    /// The keys-file path this configuration resolves to (`<data_dir>/<nickname>.keys`).
    pub(super) fn keys_path(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".tachyon-i2p"))
            .join(format!("{}.keys", self.nickname))
    }
}

/// Rejects nicknames that could escape [`I2pConfig::data_dir`] in `<data_dir>/<nickname>.keys`.
fn validate_nickname(nickname: &str) -> Result<(), Error> {
    // Both separators by hand on every platform; `components()` covers empty, `.`, `..`, and
    // Windows drive prefixes like `C:`, which `Path::join` treats as absolute.
    let mut components = std::path::Path::new(nickname).components();
    let is_plain_name = !nickname.contains(['/', '\\'])
        && matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !is_plain_name {
        return Err(Error::config(format!(
            "invalid I2P eepsite nickname {nickname:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{I2pConfig, validate_nickname};

    #[test]
    fn nicknames_cannot_escape_the_data_dir() {
        assert!(validate_nickname("my-eepsite").is_ok());
        for bad in ["..", ".", "", "../../etc/passwd", "a/b", "a\\b"] {
            assert!(validate_nickname(bad).is_err(), "{bad:?} accepted");
        }
        // Drive-relative on Windows, where `Path::join` would drop `data_dir` entirely.
        #[cfg(windows)]
        assert!(validate_nickname("C:keys").is_err());

        let nickname = format!("site-{:x}", rand::random::<u64>());
        assert_eq!(
            I2pConfig::new(nickname.clone())
                .data_dir("/srv/i2p")
                .keys_path(),
            std::path::Path::new(&format!("/srv/i2p/{nickname}.keys"))
        );
    }

    #[test]
    fn encryption_types_keep_preference_order_and_replace_each_other() {
        use tachyon_i2p::CryptoType;
        let config = I2pConfig::new("nick")
            .encryption_types(&[CryptoType::EciesMlkem1024X25519, CryptoType::EciesX25519]);
        assert_eq!(
            config.encryption_types,
            [CryptoType::EciesMlkem1024X25519, CryptoType::EciesX25519]
        );
        let config = config.crypto_type(CryptoType::EciesX25519);
        assert_eq!(config.encryption_types, [CryptoType::EciesX25519]);
    }
}
