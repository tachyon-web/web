//! The state one running server shares across every transport and connection.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::body::Body;
use hyper::{Request, Response};
use tokio::sync::Semaphore;
use tower::ServiceExt as _;

use super::accept::ConnectionLimit;
use super::conn::Shutdown;
use super::security::{self, SecurityPolicy};
use super::{Limits, NO_PEER_ADDR};
use crate::ServerInfo;

/// Where a request arrived from, as far as policy and response headers care.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Origin {
    /// `None` on an anonymity transport — see [`NO_PEER_ADDR`].
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) secure: bool,
    /// The UDP port HTTP/3 is served on beside this TLS listener, advertised via `Alt-Svc`.
    pub(crate) h3_port: Option<u16>,
}

impl Origin {
    pub(crate) const fn plain(peer: Option<SocketAddr>) -> Self {
        Self {
            peer,
            secure: false,
            h3_port: None,
        }
    }

    #[cfg(all(feature = "tls", any(feature = "tor", feature = "i2p")))]
    pub(crate) const fn tls(peer: Option<SocketAddr>) -> Self {
        Self {
            peer,
            secure: true,
            h3_port: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Shared {
    router: Router,
    pub(crate) limits: Limits,
    pub(crate) connections: ConnectionLimit,
    requests: Arc<Semaphore>,
    #[cfg(feature = "tls")]
    pub(crate) tls_handshakes: Arc<Semaphore>,
    pub(crate) security: SecurityPolicy,
    /// The resolved host allow-list; `None` answers any host.
    hosts: RwLock<Option<Arc<[String]>>>,
    pub(crate) info: ServerInfo,
    pub(crate) shutdown: Shutdown,
    #[cfg(feature = "tls")]
    pub(crate) tls_policy: crate::tls::TlsPolicy,
}

impl Shared {
    pub(crate) fn new(
        router: Router,
        limits: Limits,
        security: SecurityPolicy,
        info: ServerInfo,
        shutdown: Shutdown,
        #[cfg(feature = "tls")] tls_policy: crate::tls::TlsPolicy,
    ) -> Self {
        let limits = limits.sanitized();
        Self {
            // The wire limit and the extractors' limit are one setting.
            router: router.layer(axum::extract::DefaultBodyLimit::max(limits.max_body_size)),
            connections: ConnectionLimit::new(limits.max_connections),
            requests: Arc::new(Semaphore::new(limits.max_active_requests)),
            #[cfg(feature = "tls")]
            tls_handshakes: Arc::new(Semaphore::new(limits.max_tls_handshakes)),
            limits,
            security,
            hosts: RwLock::new(None),
            info,
            shutdown,
            #[cfg(feature = "tls")]
            tls_policy,
        }
    }

    pub(crate) fn set_hosts(&self, hosts: Option<Vec<String>>) {
        if let Ok(mut slot) = self.hosts.write() {
            *slot = hosts.map(Arc::from);
        }
    }

    pub(crate) fn hosts(&self) -> Option<Arc<[String]>> {
        self.hosts.read().ok().and_then(|hosts| hosts.clone())
    }

    /// Adds a published `.onion`/`.b32.i2p` address to an enforced allow-list.
    #[cfg(any(feature = "tor", feature = "i2p"))]
    pub(crate) fn allow_host(&self, host: &str) {
        if let Ok(mut slot) = self.hosts.write()
            && let Some(hosts) = slot.as_ref()
        {
            let mut hosts = hosts.to_vec();
            hosts.push(host.to_string());
            *slot = Some(hosts.into());
        }
    }

    /// Routes a request through policy and the app. Every transport funnels through here so
    /// they can't disagree about which checks run or which extensions a handler sees.
    pub(crate) async fn dispatch(&self, mut req: Request<Body>, origin: Origin) -> Response<Body> {
        if let Some(response) = self.reject(&mut req, origin) {
            return response;
        }
        self.route(req, origin).await
    }

    /// The security policy's verdict on a request's head, finalized and ready to send.
    ///
    /// Split from [`route`](Self::route) so HTTP/3, which buffers bodies, can refuse a request
    /// before reading one.
    pub(crate) fn reject(&self, req: &mut Request<Body>, origin: Origin) -> Option<Response<Body>> {
        let hosts = self.hosts();
        let mut response =
            self.security
                .inspect(req, origin.peer, origin.secure, hosts.as_deref())?;
        self.finalize(&mut response, origin);
        Some(response)
    }

    /// Routes a request that [`reject`](Self::reject) already let through.
    pub(crate) async fn route(&self, mut req: Request<Body>, origin: Origin) -> Response<Body> {
        let Ok(_permit) = self.requests.clone().try_acquire_owned() else {
            let mut response = security::empty_response(hyper::StatusCode::SERVICE_UNAVAILABLE);
            self.finalize(&mut response, origin);
            return response;
        };
        let extensions = req.extensions_mut();
        let _ = extensions.insert(axum::extract::ConnectInfo(
            origin.peer.unwrap_or(NO_PEER_ADDR),
        ));
        let _ = extensions.insert(self.info.clone());
        match self.router.clone().oneshot(req).await {
            Ok(mut response) => {
                self.finalize(&mut response, origin);
                response
            }
            Err(never) => match never {},
        }
    }

    /// The last touch on every response: hardened headers, and `Alt-Svc` where HTTP/3 is
    /// served beside the listener — without it no browser ever tries HTTP/3.
    pub(crate) fn finalize<B>(&self, response: &mut Response<B>, origin: Origin) {
        self.security.finalize_response(response, origin.secure);
        if let Some(port) = origin.h3_port
            && let Ok(value) = format!("h3=\":{port}\"; ma=86400").parse()
        {
            response
                .headers_mut()
                .entry(hyper::header::ALT_SVC)
                .or_insert(value);
        }
    }
}
