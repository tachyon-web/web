//! [`OnionConfig`]: how [`Server::onion`](crate::Server::onion) publishes the app.

use std::path::PathBuf;
use std::sync::Arc;

use arti_client::TorClient;
use tor_hsservice::HsNickname;
use tor_rtcompat::PreferredRuntime;

use crate::Error;

/// A Tor v3 onion service publishing the app, added with
/// [`Server::onion`](crate::Server::onion).
///
/// Serves plaintext HTTP on virtual port 80 by default — Tor already encrypts and
/// authenticates the connection to the `.onion` address. With [`tls`](Self::tls), HTTPS is
/// also served on virtual port 443.
///
/// The same `nickname` and [`state_dir`](Self::state_dir) keep the same `.onion` address
/// across restarts.
pub struct OnionConfig {
    pub(super) nickname: String,
    pub(super) state_dir: Option<PathBuf>,
    pub(super) cache_dir: Option<PathBuf>,
    pub(super) vanguards: bool,
    pub(super) client: Option<Arc<TorClient<PreferredRuntime>>>,
    #[cfg(feature = "tls")]
    pub(super) tls: Option<crate::tls::Tls>,
    #[cfg(feature = "tls")]
    pub(super) redirect_http: bool,
}

impl std::fmt::Debug for OnionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("OnionConfig");
        let _ = out
            .field("nickname", &self.nickname)
            .field("state_dir", &self.state_dir)
            .field("cache_dir", &self.cache_dir)
            .field("vanguards", &self.vanguards)
            .field("client", &self.client.is_some());
        #[cfg(feature = "tls")]
        let _ = out
            .field("tls", &self.tls)
            .field("redirect_http", &self.redirect_http);
        out.finish()
    }
}

impl OnionConfig {
    /// A service published under `nickname`, plaintext, with vanguards on and Arti's default
    /// state and cache directories.
    #[must_use]
    pub fn new(nickname: impl Into<String>) -> Self {
        Self {
            nickname: nickname.into(),
            state_dir: None,
            cache_dir: None,
            vanguards: true,
            client: None,
            #[cfg(feature = "tls")]
            tls: None,
            #[cfg(feature = "tls")]
            redirect_http: false,
        }
    }

    /// Where Arti keeps persistent state, including this service's onion keys.
    #[must_use]
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Where Arti caches Tor network directory information.
    #[must_use]
    pub fn cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }

    /// Whether [vanguards](https://blog.torproject.org/vanguards-onion-services/) harden the
    /// service against guard discovery. Default `true` (Arti's "lite" mode).
    #[must_use]
    pub const fn vanguards(mut self, enabled: bool) -> Self {
        self.vanguards = enabled;
        self
    }

    /// Publishes through an already-bootstrapped client — to share one across services, or
    /// to configure bridges. The client's own configuration then governs, so combining this
    /// with `state_dir`, `cache_dir` or `vanguards(false)` is a configuration error.
    ///
    /// Arti's relay TLS uses the process-wide rustls provider installed when it bootstrapped;
    /// call [`TlsPolicy::install_as_process_default`](crate::tls::TlsPolicy::install_as_process_default)
    /// first if it should match the server's policy.
    #[must_use]
    pub fn client(mut self, client: Arc<TorClient<PreferredRuntime>>) -> Self {
        self.client = Some(client);
        self
    }

    /// Also serves HTTPS on virtual port 443 with these certificates. Their names always
    /// include the `.onion` address.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls(mut self, tls: crate::tls::Tls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Makes virtual port 80 `308`-redirect to HTTPS instead of serving the app. Needs
    /// [`tls`](Self::tls).
    #[cfg(feature = "tls")]
    #[must_use]
    pub const fn redirect_http(mut self, enable: bool) -> Self {
        self.redirect_http = enable;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        let _ = parse_nickname(&self.nickname)?;
        if self.client.is_some()
            && (self.state_dir.is_some() || self.cache_dir.is_some() || !self.vanguards)
        {
            return Err(Error::config(
                "OnionConfig::client already carries its configuration; drop state_dir, \
                 cache_dir and vanguards",
            ));
        }
        #[cfg(feature = "tls")]
        {
            if self.redirect_http && self.tls.is_none() {
                return Err(Error::config(
                    "OnionConfig::redirect_http needs OnionConfig::tls",
                ));
            }
            if let Some(tls) = &self.tls {
                crate::tls::certs::validate(tls, true)?;
            }
        }
        Ok(())
    }
}

/// Validates `nickname` as an [`HsNickname`], naming the offending value — its own error
/// doesn't.
pub(super) fn parse_nickname(nickname: &str) -> Result<HsNickname, Error> {
    nickname
        .parse()
        .map_err(|e| Error::config(format!("invalid onion service nickname {nickname:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::OnionConfig;

    #[test]
    fn invalid_or_contradictory_configs_are_refused() {
        assert!(OnionConfig::new("valid-nickname").validate().is_ok());
        let err = OnionConfig::new("not a nickname!!")
            .validate()
            .expect_err("spaces are not allowed");
        assert!(err.to_string().contains("not a nickname!!"));

        #[cfg(feature = "tls")]
        assert!(
            OnionConfig::new("svc")
                .redirect_http(true)
                .validate()
                .is_err(),
            "a redirect to HTTPS without HTTPS must not be silently ignored"
        );
    }
}
