//! HTTPS entry points that bind their own listeners: caller-supplied configs, [`start_all`],
//! and [`serve_all_acme`]. All of them finish in [`Server::serve_tls`].
//!
//! [`start_all`]: Server::start_all
//! [`serve_all_acme`]: Server::serve_all_acme

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::Server;
use super::bind::bind_and_serve;
#[cfg(feature = "http3")]
use super::h3::spawn_h3_beside;
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
use super::redirect::RedirectInfo;
use super::redirect::parse_addr;
#[cfg(any(feature = "cert-gen", feature = "http3"))]
use super::tls_config::alpn_protocols;

/// How long [`Server::serve_all_acme`] waits for the first certificate before starting the
/// TLS listener regardless.
#[cfg(feature = "lets-encrypt")]
const FIRST_CERT_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

impl Server {
    /// Serves HTTPS on `listener` with `config`, plus HTTP/3 on its UDP twin when `h3` is set
    /// and the `http3` feature is on (ignored otherwise).
    pub(super) async fn serve_tls(
        self,
        listener: TcpListener,
        config: Arc<rustls::ServerConfig>,
        h3: bool,
    ) -> Result<(), std::io::Error> {
        // Checked before HTTP/3 starts; `serve_https` re-checks only the TCP side.
        #[cfg(feature = "fips")]
        super::assert_fips_server_config(&config)?;
        #[cfg(feature = "http3")]
        let _h3_task = if h3 {
            Some(spawn_h3_beside(&self, config.clone(), &listener)?)
        } else {
            None
        };
        #[cfg(not(feature = "http3"))]
        let _ = h3;
        self.serve_https(listener, TlsAcceptor::from(config)).await
    }

    /// The port-80 redirect listener for an HTTPS listener on `https_port`, drawing on its
    /// share of the connection pool.
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    fn redirect_info(
        &self,
        addr: std::net::SocketAddr,
        https_port: u16,
        allowed_hosts: Arc<[String]>,
    ) -> RedirectInfo {
        RedirectInfo {
            addr,
            https_port,
            allowed_hosts,
            limit: self
                .connection_limit
                .with_share(self.redirect_connection_permits()),
            policy: self.security_policy.clone(),
        }
    }

    /// HTTPS (HTTP/1.1 + HTTP/2) on an already-parsed address, with a caller-supplied
    /// `rustls::ServerConfig`.
    ///
    /// # Errors
    /// Returns an error if binding or the server itself fails.
    pub async fn start_https_with_config_addr(
        self,
        addr: std::net::SocketAddr,
        config: rustls::ServerConfig,
    ) -> Result<(), std::io::Error> {
        let config = self.finalize_tls_config(config);
        bind_and_serve(self, addr, None, move |server, listener| {
            server.serve_tls(listener, config, false)
        })
        .await
    }

    /// HTTPS (HTTP/1.1 + HTTP/2) on `tls_addr` (e.g. `"0.0.0.0:443"`), with a caller-supplied
    /// `rustls::ServerConfig`.
    ///
    /// # Errors
    /// Returns an error if `tls_addr` does not parse or the server fails to run.
    pub async fn start_https_with_config(
        self,
        tls_addr: &str,
        config: rustls::ServerConfig,
    ) -> Result<(), std::io::Error> {
        self.start_https_with_config_addr(parse_addr(tls_addr)?, config)
            .await
    }

    /// HTTPS and HTTP/3 with a caller-supplied `rustls::ServerConfig`. Both listeners bind
    /// `tls_addr` — TCP for HTTPS, UDP for QUIC. The config's ALPN list is overwritten.
    ///
    /// # Errors
    /// Returns an error if FIPS enforcement, binding, or server initialization fails.
    #[cfg(feature = "http3")]
    pub async fn start_https_and_h3_with_config(
        self,
        tls_addr: &str,
        mut config: rustls::ServerConfig,
    ) -> Result<(), std::io::Error> {
        config.alpn_protocols = alpn_protocols(true);
        let config = self.finalize_tls_config(config);
        bind_and_serve(
            self,
            parse_addr(tls_addr)?,
            None,
            move |server, listener| server.serve_tls(listener, config, true),
        )
        .await
    }

    /// Serves every enabled protocol from a PEM certificate chain and key: HTTPS on
    /// `tls_addr`, HTTP/3 on the same address when the `http3` feature is on, and — if
    /// `cleartext_addr` is `Some` — a listener that `308`s every request to HTTPS.
    ///
    /// That listener answers ACME HTTP-01 challenges only from this crate's in-process
    /// `AcmeManager` (`lets-encrypt`); an external ACME client such as certbot has no way to
    /// publish its tokens there.
    ///
    /// Unless the security policy already sets one, the certificate's DNS names (plus
    /// `tls_addr`'s IP, if specific) become the host allow-list.
    ///
    /// Blocks on the HTTPS listener; the others run as spawned tasks.
    ///
    /// # Errors
    /// Returns an error if binding, TLS configuration, or certificate parsing fails.
    #[cfg(feature = "cert-gen")]
    pub async fn start_all(
        mut self,
        tls_addr: &str,
        cleartext_addr: Option<&str>,
        cert_pem: String,
        key_pem: String,
    ) -> Result<(), std::io::Error> {
        let addr = parse_addr(tls_addr)?;

        let cert_chain = crate::tls::pem::certs(cert_pem.as_bytes());
        let mut allowed_hosts = cert_chain
            .first()
            .map(crate::tls::certificate_dns_names)
            .unwrap_or_default();
        if !addr.ip().is_unspecified() {
            allowed_hosts.push(addr.ip().to_string());
        }
        let allowed_hosts: Arc<[String]> = allowed_hosts.into();
        self.security_policy
            .set_default_allowed_hosts(allowed_hosts.clone());

        // Verifies the CNSA identity too, under `cnsa`.
        let mut config = self
            .effective_tls_policy()
            .server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        config.alpn_protocols = alpn_protocols(cfg!(feature = "http3"));
        #[cfg(feature = "cnsa")]
        {
            self.cnsa_identity_verified = true;
        }

        let redirect = match cleartext_addr {
            Some(cleartext) => {
                Some(self.redirect_info(parse_addr(cleartext)?, addr.port(), allowed_hosts))
            }
            None => None,
        };
        let config = Arc::new(config);
        bind_and_serve(self, addr, redirect, move |server, listener| {
            server.serve_tls(listener, config, true)
        })
        .await
    }

    /// [`start_all`](Self::start_all) with an [`AcmeManager`], so certificates are issued and
    /// renewed in-process.
    ///
    /// The `cleartext_addr` listener answers HTTP-01 challenges and `308`s everything else to
    /// HTTPS, so port 80 must be publicly reachable for issuance to succeed. `domains` must all
    /// resolve to this server and become the default host allow-list. `cache_dir` holds the
    /// account credentials and certificate and must be writable; reusing it across restarts is
    /// what keeps you under Let's Encrypt's rate limits. `staging` picks the staging
    /// environment — untrusted certs, far higher rate limits — and is what you want while
    /// testing.
    ///
    /// Waits up to a minute for the first certificate, then serves regardless.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use axum::{Router, routing::get};
    /// use tachyon_web::Server;
    ///
    /// async fn hello() -> &'static str { "Hello, HTTPS World!" }
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ///     let app = Router::new().route("/", get(hello));
    ///
    ///     Server::new(app)
    ///         .serve_all_acme(
    ///             "0.0.0.0:443",
    ///             "0.0.0.0:80",
    ///             vec!["example.com".to_string(), "www.example.com".to_string()],
    ///             "admin@example.com".to_string(),
    ///             "/var/cache/tachyon/certs",
    ///             false,  // false = production Let's Encrypt
    ///         )
    ///         .await?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns an error if `domains` is empty, the cache directory is insecure, either address
    /// cannot be bound, or the server fails to run.
    ///
    /// [`AcmeManager`]: crate::tls::acme::AcmeManager
    #[cfg(feature = "lets-encrypt")]
    pub async fn serve_all_acme(
        mut self,
        tls_addr: &str,
        cleartext_addr: &str,
        domains: Vec<String>,
        email: String,
        cache_dir: impl Into<std::path::PathBuf>,
        staging: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::tls::acme::AcmeManager;
        if domains.is_empty() {
            // An ACME order needs at least one identifier (RFC 8555 §7.4).
            return Err("serve_all_acme requires at least one domain".into());
        }

        let allowed_hosts: Arc<[String]> = Arc::from(domains.clone());
        self.security_policy
            .set_default_allowed_hosts(allowed_hosts.clone());
        // Signing keys load through the same provider the `ServerConfig` negotiates with —
        // under `fips` those are distinct modules otherwise.
        let policy = self.effective_tls_policy();
        let acme = AcmeManager::with_policy(cache_dir, domains, email, staging, &policy);
        acme.validate_cache()?;

        let addr = parse_addr(tls_addr)?;
        let redirect = self.redirect_info(parse_addr(cleartext_addr)?, addr.port(), allowed_hosts);
        // The redirect listener answers HTTP-01, so `bind_and_serve` has it up before the ACME
        // loop below places its first order.
        bind_and_serve(
            self,
            addr,
            Some(redirect),
            move |server, listener| async move {
                let resolver = acme.resolver();
                let _acme_task = acme.start_guarded();

                let first_cert = async {
                    while !resolver.has_certificate() {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                };
                if tokio::time::timeout(FIRST_CERT_TIMEOUT, first_cert)
                    .await
                    .is_err()
                {
                    crate::telemetry_warn!(
                        "[acme] No certificate ready after {:?}; starting TLS listener anyway — \
                     connections will fail until provisioning completes",
                        FIRST_CERT_TIMEOUT
                    );
                }

                let mut config = policy.config_builder()?.with_cert_resolver(resolver);
                config.alpn_protocols = alpn_protocols(cfg!(feature = "http3"));
                policy.apply_to_server_config(&mut config);
                server.serve_tls(listener, Arc::new(config), true).await
            },
        )
        .await?;
        Ok(())
    }
}
