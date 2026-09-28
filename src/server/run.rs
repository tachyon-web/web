//! Starting, running and gracefully stopping a [`Server`].

use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinSet;

use super::conn::Shutdown;
use super::security::{HostRule, valid_host_entry};
use super::shared::Shared;
use super::{Server, Transport};
use crate::{Endpoint, Error, Network, Reachability};

type Signal = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A [`Server`] ready to run: await it, optionally after
/// [`with_graceful_shutdown`](Self::with_graceful_shutdown).
#[must_use = "a server does nothing until awaited"]
pub struct Serve {
    server: Server,
    signal: Option<Signal>,
}

impl std::fmt::Debug for Serve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serve")
            .field("server", &self.server)
            .field("graceful_shutdown", &self.signal.is_some())
            .finish()
    }
}

impl Serve {
    pub(super) fn new(server: Server) -> Self {
        Self {
            server,
            signal: None,
        }
    }

    /// Stops gracefully once `signal` completes: every transport stops accepting, each
    /// connection finishes its in-flight requests (HTTP/1.1 closes after the current response,
    /// HTTP/2 and HTTP/3 send `GOAWAY`), and the server future resolves `Ok` once all have
    /// closed.
    ///
    /// A handler that never finishes — an endless stream — holds that wait open; bound it with
    /// your own timeout. Dropping the server future instead stops accepting immediately: TCP
    /// connections still finish their requests in the background, while HTTP/3, onion and I2P
    /// connections close with the endpoint they run on.
    pub fn with_graceful_shutdown(
        mut self,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> Self {
        self.signal = Some(Box::pin(signal));
        self
    }
}

impl IntoFuture for Serve {
    type Output = Result<(), Error>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.server.run(self.signal))
    }
}

/// A clearnet listener, bound and ready but not yet serving.
enum Bound {
    Http(TcpListener),
    #[cfg(feature = "tls")]
    Https(Box<Https>),
}

#[cfg(feature = "tls")]
struct Https {
    listener: TcpListener,
    built: crate::tls::certs::Built,
    endpoint: Endpoint,
    /// HTTP/3 on the same port, over UDP.
    #[cfg(feature = "http3")]
    quic: tachyon_quic::s2n_quic::Server,
}

impl Server {
    fn validate(&self) -> Result<(), Error> {
        if self.transports.is_empty() {
            return Err(Error::config(
                "no transports: add at least one with .http/.https/.onion/.i2p",
            ));
        }
        if let HostRule::Only(hosts) = self.security.host_rule() {
            if hosts.is_empty() {
                return Err(Error::config(
                    "SecurityPolicy::allowed_hosts is empty, which would refuse every request",
                ));
            }
            if let Some(host) = hosts.iter().find(|host| !valid_host_entry(host)) {
                return Err(Error::config(format!(
                    "SecurityPolicy::allowed_hosts: {host:?} is not a DNS name, `*.` wildcard or \
                     IP literal, so it would match nothing"
                )));
            }
        }
        #[cfg(feature = "tls")]
        {
            let https = self
                .transports
                .iter()
                .filter_map(|t| match t {
                    Transport::Https(_, tls) => Some(tls),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let redirects = self
                .transports
                .iter()
                .filter(|t| matches!(t, Transport::Redirect(_)))
                .count();
            if redirects > 1 {
                return Err(Error::config("at most one redirect listener"));
            }
            if redirects == 1 && https.is_empty() {
                return Err(Error::config("a redirect listener needs an HTTPS endpoint"));
            }
            for tls in &https {
                crate::tls::certs::validate(tls, false)?;
            }
            #[cfg(feature = "acme")]
            if redirects == 0
                && https.iter().any(|tls| {
                    tls.sources
                        .iter()
                        .any(|s| matches!(s, crate::tls::Source::Acme(_)))
                })
            {
                return Err(Error::config(
                    "ACME answers HTTP-01 on the redirect listener: add .redirect(\"0.0.0.0:80\")",
                ));
            }
        }
        #[cfg(feature = "i2p")]
        {
            let eepsites = self
                .transports
                .iter()
                .filter_map(|t| match t {
                    Transport::I2p(config) => Some(config),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if eepsites.len() > 1 && eepsites.iter().any(|config| config.starts_router()) {
                return Err(Error::config(
                    "only one I2P router runs per process: give every eepsite the same \
                     I2pConfig::router",
                ));
            }
        }
        for transport in &self.transports {
            match transport {
                #[cfg(feature = "tor")]
                Transport::Onion(config) => config.validate()?,
                #[cfg(feature = "i2p")]
                Transport::I2p(config) => config.validate()?,
                _ => {}
            }
        }
        Ok(())
    }

    async fn run(self, signal: Option<Signal>) -> Result<(), Error> {
        self.validate()?;
        super::enforce_fips_compliance()?;
        let (trigger, shutdown) = Shutdown::new();
        let shared = Arc::new(Shared::new(
            self.router,
            self.limits,
            self.security,
            self.info,
            shutdown,
            #[cfg(feature = "tls")]
            self.tls_policy,
        ));

        let startup = Startup::bind(self.transports, &shared).await?;
        shared.set_hosts(startup.allowed_hosts(&shared.security));
        let mut tasks = JoinSet::new();
        startup.spawn(&shared, &mut tasks)?;

        let signal = signal.unwrap_or_else(|| Box::pin(std::future::pending()));
        let outcome = tokio::select! {
            () = signal => Ok(()),
            Some(stopped) = tasks.join_next() => match stopped {
                Ok(Ok(())) => Err(Error::Io(std::io::Error::other("a transport stopped"))),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(Error::Io(std::io::Error::other(e))),
            },
        };
        let _ = trigger.send(true);
        // Drain before aborting: the QUIC endpoint, onion service and I2P destination live in
        // these tasks, and dropping them cuts the connections still finishing.
        shared.connections.drain().await;
        tasks.shutdown().await;
        outcome
    }
}

/// Every transport, with clearnet listeners bound and their certificates loaded, but nothing
/// served yet — so a bad address or key fails the start rather than a later request.
struct Startup {
    bound: Vec<Bound>,
    #[cfg(feature = "tls")]
    redirect: Option<TcpListener>,
    #[cfg(any(feature = "tor", feature = "i2p"))]
    anonymous: Vec<Transport>,
    /// Every clearnet name the server is configured with: TLS domains, then certificate names,
    /// then specifically bound IPs.
    names: Vec<String>,
}

impl Startup {
    async fn bind(transports: Vec<Transport>, shared: &Shared) -> Result<Self, Error> {
        let mut startup = Self {
            bound: Vec::new(),
            #[cfg(feature = "tls")]
            redirect: None,
            #[cfg(any(feature = "tor", feature = "i2p"))]
            anonymous: Vec::new(),
            names: Vec::new(),
        };
        #[cfg(not(feature = "tls"))]
        let _ = shared;
        let mut addresses = Vec::new();
        for transport in transports {
            match transport {
                Transport::Http(bind) => {
                    let listener = bind.listen().await?;
                    addresses.push(listener.local_addr()?);
                    startup.bound.push(Bound::Http(listener));
                }
                #[cfg(feature = "tls")]
                Transport::Https(bind, tls) => {
                    let listener = bind.listen().await?;
                    let addr = listener.local_addr()?;
                    addresses.push(addr);
                    let endpoint = Endpoint {
                        network: Network::Clearnet,
                        host: tls
                            .domains
                            .iter()
                            .find(|name| !name.starts_with("*."))
                            .cloned()
                            .unwrap_or_else(|| addr.ip().to_string()),
                        port: addr.port(),
                        tls: true,
                        http3: cfg!(feature = "http3"),
                        reachability: Reachability::Reachable,
                    };
                    let built = crate::tls::certs::build(
                        &tls,
                        &shared.tls_policy,
                        &tls.domains,
                        &endpoint.url(),
                        super::alpn(endpoint.http3),
                    )?;
                    startup.names.extend(tls.domains.iter().cloned());
                    for info in built.store.infos() {
                        startup.names.extend(info.names.iter().cloned());
                    }
                    #[cfg(feature = "http3")]
                    let quic = super::h3::build_quic_server(
                        built.config.clone(),
                        addr,
                        shared.limits.max_h3_streams,
                    )
                    .map_err(|e| Error::Io(std::io::Error::other(e)))?;
                    startup.bound.push(Bound::Https(Box::new(Https {
                        listener,
                        built,
                        endpoint,
                        #[cfg(feature = "http3")]
                        quic,
                    })));
                }
                #[cfg(feature = "tls")]
                Transport::Redirect(bind) => startup.redirect = Some(bind.listen().await?),
                #[cfg(any(feature = "tor", feature = "i2p"))]
                other => startup.anonymous.push(other),
            }
        }
        // Bound IPs only join names that already exist: on their own they'd make a plain
        // `127.0.0.1` dev server refuse `localhost`.
        if !startup.names.is_empty() {
            startup.names.extend(
                addresses
                    .iter()
                    .filter(|addr| !addr.ip().is_unspecified())
                    .map(|addr| addr.ip().to_string()),
            );
        }
        let mut seen = std::collections::HashSet::new();
        startup
            .names
            .retain(|name| seen.insert(name.to_ascii_lowercase()));
        Ok(startup)
    }

    /// The host allow-list the policy resolves to; `None` answers any host.
    fn allowed_hosts(&self, security: &super::SecurityPolicy) -> Option<Vec<String>> {
        match security.host_rule() {
            HostRule::Auto if self.names.is_empty() => {
                crate::telemetry_warn!(
                    "[server] no names to allow-list: any Host header is answered"
                );
                None
            }
            HostRule::Auto => Some(self.names.clone()),
            HostRule::Any => None,
            HostRule::Only(hosts) => Some(hosts.to_vec()),
        }
    }

    fn spawn(
        self,
        shared: &Arc<Shared>,
        tasks: &mut JoinSet<Result<(), Error>>,
    ) -> Result<(), Error> {
        #[cfg(feature = "tls")]
        let mut https_port = None;
        for listener in self.bound {
            match listener {
                Bound::Http(listener) => {
                    shared.info.publish(plain_endpoint(listener.local_addr()?));
                    tasks.spawn(forever(super::http::serve_plain(shared.clone(), listener)));
                }
                #[cfg(feature = "tls")]
                Bound::Https(https) => {
                    https_port.get_or_insert(https.endpoint.port);
                    spawn_https(shared, tasks, *https);
                }
            }
        }
        #[cfg(feature = "tls")]
        if let (Some(listener), Some(port)) = (self.redirect, https_port) {
            let hosts: Arc<[String]> = match shared.security.host_rule() {
                HostRule::Only(hosts) => hosts.clone(),
                _ => self.names.into(),
            };
            let limit = shared
                .connections
                .with_share(shared.limits.redirect_connections());
            tasks.spawn(forever(super::redirect::serve_redirect(
                shared.clone(),
                listener,
                port,
                hosts,
                limit,
            )));
        }
        #[cfg(any(feature = "tor", feature = "i2p"))]
        for transport in self.anonymous {
            match transport {
                #[cfg(feature = "tor")]
                Transport::Onion(config) => {
                    tasks.spawn(super::tor::serve::serve(shared.clone(), config));
                }
                #[cfg(feature = "i2p")]
                Transport::I2p(config) => {
                    tasks.spawn(super::i2p::serve::serve(shared.clone(), config));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Starts one HTTPS endpoint: HTTP/3 beside it, ACME renewal, and the TLS accept loop.
#[cfg(feature = "tls")]
fn spawn_https(shared: &Arc<Shared>, tasks: &mut JoinSet<Result<(), Error>>, https: Https) {
    #[cfg(feature = "http3")]
    let h3_port = {
        tasks.spawn(forever(super::h3::serve_h3(shared.clone(), https.quic)));
        Some(https.endpoint.port)
    };
    #[cfg(not(feature = "http3"))]
    let h3_port = None;
    shared.info.add_certificates(https.built.store);
    #[cfg(feature = "acme")]
    for manager in https.built.acme {
        tasks.spawn(forever(manager.run()));
    }
    shared.info.publish(https.endpoint);
    tasks.spawn(forever(super::http::serve_tls(
        shared.clone(),
        https.listener,
        https.built.config,
        h3_port,
    )));
}

fn plain_endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint {
        network: Network::Clearnet,
        host: addr.ip().to_string(),
        port: addr.port(),
        tls: false,
        http3: false,
        reachability: Reachability::Reachable,
    }
}

/// An accept loop, which only ends when aborted, as a task result.
async fn forever(accept_loop: impl Future<Output = ()>) -> Result<(), Error> {
    accept_loop.await;
    Ok(())
}
