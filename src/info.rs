//! [`ServerInfo`]: what a running [`Server`](crate::Server) has published, readable from any
//! handler.

use std::sync::{Arc, RwLock};

/// Which network an [`Endpoint`] is reachable on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Network {
    /// A TCP/UDP socket on the ordinary internet (or loopback).
    Clearnet,
    /// A Tor v3 onion service.
    Tor,
    /// An I2P eepsite.
    I2p,
}

/// Whether an [`Endpoint`]'s network confirms it can be reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Reachability {
    /// Serving: a bound clearnet listener, or an onion service Tor reports fully reachable.
    Reachable,
    /// The address is known, but Tor has not confirmed the service reachable yet — or no
    /// longer does. A first publication can take minutes.
    Pending,
    /// Serving, but the network gives no reachability signal: I2P publishes the destination's
    /// `LeaseSet` in the background.
    Unconfirmed,
}

/// One place the app is reachable, published as soon as its address is known.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Endpoint {
    /// The network it is reachable on.
    pub network: Network,
    /// The name clients connect to: the first non-wildcard TLS domain, the bound IP, or the
    /// `.onion` / `.b32.i2p` address.
    pub host: String,
    /// The port clients connect to. For Tor this is the virtual port (80 or 443); I2P has no
    /// ports and reports the scheme's default.
    pub port: u16,
    /// Whether this endpoint terminates TLS.
    pub tls: bool,
    /// Whether HTTP/3 is served beside it on the same UDP port.
    pub http3: bool,
    /// Whether its network confirms it can be reached.
    pub reachability: Reachability,
}

impl Endpoint {
    /// The endpoint's origin, e.g. `https://example.com`, `http://127.0.0.1:8080` or
    /// `http://abc…xyz.onion`. Default ports are omitted.
    #[must_use]
    pub fn url(&self) -> String {
        let (scheme, default_port) = if self.tls {
            ("https", 443)
        } else {
            ("http", 80)
        };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default_port {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{}", self.port)
        }
    }
}

/// Live metadata about a running [`Server`](crate::Server): its published endpoints — including
/// `.onion` and `.b32.i2p` addresses — and, with `tls`, every certificate it serves.
///
/// Every request carries it, so a handler or middleware takes it like any extractor. It is a
/// cheap handle onto shared state: endpoints appear as each transport comes up — a `.onion` or
/// `.b32.i2p` address as soon as it is known, with its [`Reachability`] updated as the network
/// publishes it — and certificates are replaced in place when ACME renews them.
/// [`Server::info`](crate::Server::info) returns the same handle, for code outside a handler.
///
/// ```rust,no_run
/// use tachyon_web::{Network, ServerInfo};
///
/// async fn mirrors(info: ServerInfo) -> String {
///     info.endpoints()
///         .iter()
///         .filter(|e| e.network != Network::Clearnet)
///         .map(|e| e.url())
///         .collect::<Vec<_>>()
///         .join("\n")
/// }
/// ```
#[derive(Clone)]
pub struct ServerInfo(Arc<Inner>);

struct Inner {
    endpoints: RwLock<Vec<Endpoint>>,
    #[cfg(feature = "tls")]
    certificates: RwLock<Vec<Arc<crate::tls::certs::CertStore>>>,
}

impl std::fmt::Debug for ServerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerInfo")
            .field("endpoints", &self.endpoints())
            .finish_non_exhaustive()
    }
}

impl ServerInfo {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Inner {
            endpoints: RwLock::new(Vec::new()),
            #[cfg(feature = "tls")]
            certificates: RwLock::new(Vec::new()),
        }))
    }

    /// Every endpoint published so far, in the order they came up.
    #[must_use]
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.0
            .endpoints
            .read()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default()
    }

    /// Every certificate currently served, across all TLS endpoints, in each endpoint's
    /// preference order.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn certificates(&self) -> Vec<Arc<crate::tls::CertificateInfo>> {
        self.0
            .certificates
            .read()
            .map(|stores| stores.iter().flat_map(|store| store.infos()).collect())
            .unwrap_or_default()
    }

    pub(crate) fn publish(&self, endpoint: Endpoint) {
        crate::telemetry_info!(
            "[server] serving {} ({:?})",
            endpoint.url(),
            endpoint.reachability
        );
        if let Ok(mut endpoints) = self.0.endpoints.write() {
            endpoints.push(endpoint);
        }
    }

    /// Updates every endpoint published for `host`.
    #[cfg(feature = "tor")]
    pub(crate) fn set_reachability(&self, host: &str, reachability: Reachability) {
        if let Ok(mut endpoints) = self.0.endpoints.write() {
            for endpoint in endpoints.iter_mut().filter(|e| e.host == host) {
                endpoint.reachability = reachability;
            }
        }
    }

    #[cfg(feature = "tls")]
    pub(crate) fn add_certificates(&self, store: Arc<crate::tls::certs::CertStore>) {
        if let Ok(mut stores) = self.0.certificates.write() {
            stores.push(store);
        }
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ServerInfo {
    type Rejection = (axum::http::StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(parts.extensions.get::<Self>().cloned().ok_or((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "ServerInfo is only available to apps served by tachyon_web::Server",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{Endpoint, Network};

    #[test]
    fn url_omits_default_ports_and_brackets_ipv6() {
        let endpoint = |host: &str, port, tls| Endpoint {
            network: Network::Clearnet,
            host: host.to_string(),
            port,
            tls,
            http3: false,
            reachability: super::Reachability::Reachable,
        };
        assert_eq!(
            endpoint("example.com", 443, true).url(),
            "https://example.com"
        );
        assert_eq!(
            endpoint("example.com", 80, true).url(),
            "https://example.com:80"
        );
        assert_eq!(endpoint("::1", 8080, false).url(), "http://[::1]:8080");
    }
}
