//! Request-boundary security policy.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Body;
use hyper::{Request, Response, StatusCode};

const FORWARDED_HEADERS: [&str; 9] = [
    "forwarded",
    "cf-connecting-ip",
    "client-ip",
    "true-client-ip",
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
];
const ENFORCE_AUTHORITY: u8 = 1;
const STRIP_UNTRUSTED_FORWARDING: u8 = 2;
const REJECT_CONNECT: u8 = 4;
const ALLOW_H2C: u8 = 8;
const HARDEN_RESPONSES: u8 = 16;

/// An IP network used to identify a trusted reverse proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Creates a network, rejecting a prefix that is too long for its address family.
    ///
    /// # Errors
    ///
    /// Returns an error if `prefix` exceeds 32 for IPv4 or 128 for IPv6.
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, std::io::Error> {
        let width = if address.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "network prefix exceeds address width",
            ));
        }
        Ok(Self { address, prefix })
    }

    fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let prefix = u32::from(self.prefix);
                let shift = 32u32.saturating_sub(prefix);
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let prefix = u32::from(self.prefix);
                let shift = 128u32.saturating_sub(prefix);
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for IpNetwork {
    type Err = std::io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "network must use CIDR notation",
            )
        })?;
        let address = address.parse::<IpAddr>().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid IP: {e}"))
        })?;
        let prefix = prefix.parse::<u8>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid network prefix: {e}"),
            )
        })?;
        Self::new(address, prefix)
    }
}

/// Security controls applied before a request reaches the Axum router.
#[derive(Clone, Debug)]
pub struct SecurityPolicy {
    allowed_hosts: Arc<[String]>,
    trusted_proxies: Arc<[IpNetwork]>,
    flags: u8,
}

impl SecurityPolicy {
    /// Creates the default fail-safe request policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            allowed_hosts: Arc::from([]),
            trusted_proxies: Arc::from([]),
            flags: STRIP_UNTRUSTED_FORWARDING | REJECT_CONNECT | HARDEN_RESPONSES,
        }
    }

    /// Restricts requests to these case-insensitive DNS names or IP literals.
    ///
    /// An empty explicit list rejects every authority. Authority enforcement is disabled only
    /// when this builder is never called.
    #[must_use]
    pub fn allowed_hosts(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allowed_hosts = hosts.into_iter().map(Into::into).collect::<Vec<_>>().into();
        self.flags |= ENFORCE_AUTHORITY;
        self
    }

    /// Sets the networks allowed to supply forwarding headers.
    #[must_use]
    pub fn trusted_proxies(mut self, proxies: impl IntoIterator<Item = IpNetwork>) -> Self {
        self.trusted_proxies = proxies.into_iter().collect::<Vec<_>>().into();
        self
    }

    /// Controls removal of forwarding headers received directly from untrusted peers.
    #[must_use]
    pub const fn strip_untrusted_forwarding_headers(mut self, strip: bool) -> Self {
        if strip {
            self.flags |= STRIP_UNTRUSTED_FORWARDING;
        } else {
            self.flags &= !STRIP_UNTRUSTED_FORWARDING;
        }
        self
    }

    /// Allows or rejects the HTTP `CONNECT` method. It is rejected by default.
    #[must_use]
    pub const fn allow_connect(mut self, allow: bool) -> Self {
        if allow {
            self.flags &= !REJECT_CONNECT;
        } else {
            self.flags |= REJECT_CONNECT;
        }
        self
    }

    /// Enables HTTP/2 over plaintext connections. Disabled by default; HTTP/2 over TLS is
    /// unaffected.
    #[must_use]
    pub const fn allow_h2c(mut self, allow: bool) -> Self {
        if allow {
            self.flags |= ALLOW_H2C;
        } else {
            self.flags &= !ALLOW_H2C;
        }
        self
    }

    /// Controls conservative response headers that are safe for arbitrary applications.
    /// Enabled by default. Existing application-provided values are never overwritten.
    #[must_use]
    pub const fn harden_responses(mut self, harden: bool) -> Self {
        if harden {
            self.flags |= HARDEN_RESPONSES;
        } else {
            self.flags &= !HARDEN_RESPONSES;
        }
        self
    }

    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    pub(super) fn with_default_allowed_hosts(mut self, hosts: Arc<[String]>) -> Self {
        if self.flags & ENFORCE_AUTHORITY == 0 {
            self.allowed_hosts = hosts;
            self.flags |= ENFORCE_AUTHORITY;
        }
        self
    }

    pub(super) fn inspect(
        &self,
        req: &mut Request<Body>,
        peer: std::net::SocketAddr,
        secure_transport: bool,
    ) -> Option<Response<Body>> {
        if self.flags & ALLOW_H2C == 0
            && !secure_transport
            && req.version() == hyper::Version::HTTP_2
        {
            return Some(empty_response(StatusCode::UPGRADE_REQUIRED));
        }
        if req.headers().contains_key(hyper::header::TRANSFER_ENCODING)
            && req.headers().contains_key(hyper::header::CONTENT_LENGTH)
        {
            return Some(empty_response(StatusCode::BAD_REQUEST));
        }
        let mut lengths = req.headers().get_all(hyper::header::CONTENT_LENGTH).iter();
        if let Some(first) = lengths.next()
            && lengths.any(|value| value != first)
        {
            return Some(empty_response(StatusCode::BAD_REQUEST));
        }
        if self.flags & REJECT_CONNECT != 0 && req.method() == hyper::Method::CONNECT {
            return Some(empty_response(StatusCode::METHOD_NOT_ALLOWED));
        }

        if self.flags & ENFORCE_AUTHORITY != 0 {
            // Both spellings go through `bare_host` — see its docs for why that matters.
            let authority = req
                .uri()
                .authority()
                .map(hyper::http::uri::Authority::host)
                .or_else(|| {
                    req.headers()
                        .get(hyper::header::HOST)
                        .and_then(|value| value.to_str().ok())
                })
                .and_then(bare_host);
            if !authority.is_some_and(|host| {
                self.allowed_hosts
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(host))
            }) {
                return Some(empty_response(StatusCode::MISDIRECTED_REQUEST));
            }
        }

        let trusted = self
            .trusted_proxies
            .iter()
            .any(|network| network.contains(peer.ip()));
        if self.flags & STRIP_UNTRUSTED_FORWARDING != 0 && !trusted {
            for header in FORWARDED_HEADERS {
                req.headers_mut().remove(header);
            }
        }
        None
    }

    /// Finalizes a response immediately before its transport encodes it.
    ///
    /// Application values win, but singleton security fields are collapsed to exactly one
    /// value so an accidental duplicate cannot produce ambiguous wire semantics.
    ///
    /// Only headers whose correct value is a property of the *transport* are set here.
    /// `Permissions-Policy` is deliberately not among them: which browser features a page
    /// legitimately needs is a property of the application, so a transport-layer default
    /// would either be wrong for any app that uses one of the features it denies, or so
    /// permissive it is worth nothing. The same reasoning applies to `Content-Security-Policy`.
    /// Set those in your own middleware; nothing here touches or overwrites them.
    pub(super) fn finalize_response<B>(&self, response: &mut Response<B>, secure_transport: bool) {
        if self.flags & HARDEN_RESPONSES == 0 {
            return;
        }
        let is_error = response.status().is_client_error() || response.status().is_server_error();
        let headers = response.headers_mut();
        canonicalize_singleton(
            headers,
            hyper::header::X_CONTENT_TYPE_OPTIONS,
            hyper::header::HeaderValue::from_static("nosniff"),
        );
        canonicalize_singleton(
            headers,
            hyper::header::REFERRER_POLICY,
            hyper::header::HeaderValue::from_static("no-referrer"),
        );
        if secure_transport {
            canonicalize_singleton(
                headers,
                hyper::header::STRICT_TRANSPORT_SECURITY,
                hyper::header::HeaderValue::from_static("max-age=63072000"),
            );
        }
        if is_error {
            headers
                .entry(hyper::header::CACHE_CONTROL)
                .or_insert(hyper::header::HeaderValue::from_static("no-store"));
        }
        headers.remove(hyper::header::SERVER);
    }
}

fn canonicalize_singleton(
    headers: &mut hyper::HeaderMap,
    name: hyper::header::HeaderName,
    default: hyper::header::HeaderValue,
) {
    let value = headers.get(&name).cloned().unwrap_or(default);
    headers.remove(&name);
    let _ = headers.insert(name, value);
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Splits the host out of an authority — a `Host` header value or a URI authority — dropping
/// any trailing `:port` and **preserving** an IPv6 literal's brackets, so the result is still
/// valid spliced into a URL. [`crate::server::redirect`] builds `Location` values from this.
///
/// `None` only for a bracketed literal with no closing `]`, which is malformed.
pub(super) fn authority_host(authority: &str) -> Option<&str> {
    let Some(rest) = authority.strip_prefix('[') else {
        return Some(authority.split(':').next().unwrap_or(authority));
    };
    // `bracket_end` indexes into `rest` (one past the leading `[`), so the matching `]` sits at
    // `bracket_end + 1` in `authority` and an exclusive end bound of `bracket_end + 2` keeps it.
    let bracket_end = rest.find(']')?;
    authority.get(..bracket_end.saturating_add(2))
}

/// [`authority_host`] reduced to the form a host allow-list compares against: an IPv6
/// literal's brackets removed, so `[::1]` and `::1` are one host.
///
/// The two spellings both reach [`SecurityPolicy::inspect`] — `Authority::host` keeps the
/// brackets, a `Host` header never has them — so both must come through here or one address
/// gets different answers over HTTP/1.1 and HTTP/2.
fn bare_host(authority: &str) -> Option<&str> {
    let host = authority_host(authority)?;
    Some(
        host.strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host),
    )
}

pub(super) fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_contains_only_its_network() {
        let network = "10.2.0.0/16".parse::<IpNetwork>().expect("valid CIDR");
        assert!(network.contains("10.2.4.8".parse().expect("valid IP")));
        assert!(!network.contains("10.3.4.8".parse().expect("valid IP")));
    }

    #[test]
    fn policy_rejects_unknown_authorities_and_strips_spoofed_forwarding() {
        let policy = SecurityPolicy::new().allowed_hosts(["example.com"]);
        let mut request = Request::builder()
            .uri("/")
            .header("host", "example.com:443")
            .header("x-forwarded-for", "127.0.0.1")
            .body(Body::empty())
            .expect("valid request");
        assert!(
            policy
                .inspect(
                    &mut request,
                    "203.0.113.1:1".parse().expect("valid peer"),
                    false,
                )
                .is_none()
        );
        assert!(!request.headers().contains_key("x-forwarded-for"));

        request.headers_mut().insert(
            hyper::header::HOST,
            hyper::header::HeaderValue::from_static("evil.example"),
        );
        assert_eq!(
            policy
                .inspect(
                    &mut request,
                    "203.0.113.1:1".parse().expect("valid peer"),
                    false,
                )
                .expect("request rejected")
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );

        let deny_all = SecurityPolicy::new().allowed_hosts(Vec::<String>::new());
        assert_eq!(
            deny_all
                .inspect(
                    &mut request,
                    "203.0.113.1:1".parse().expect("valid peer"),
                    true,
                )
                .expect("empty allow-list rejects every host")
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );
    }

    /// `Authority::host` keeps an IPv6 literal's brackets, a `Host` header does not. Both
    /// forms must land on the same allow-list decision, or the same deployment answers
    /// HTTP/1.1 and HTTP/2 differently for one address.
    #[test]
    fn ipv6_literal_matches_whether_it_arrives_as_authority_or_host_header() {
        let policy = SecurityPolicy::new().allowed_hosts(["::1"]);
        let peer: std::net::SocketAddr = "203.0.113.1:1".parse().expect("valid peer");

        let mut via_authority = Request::builder()
            .uri("http://[::1]:8443/")
            .body(Body::empty())
            .expect("valid request");
        assert!(policy.inspect(&mut via_authority, peer, false).is_none());

        let mut via_host = Request::builder()
            .uri("/")
            .header("host", "[::1]:8443")
            .body(Body::empty())
            .expect("valid request");
        assert!(policy.inspect(&mut via_host, peer, false).is_none());

        let mut wrong = Request::builder()
            .uri("http://[::2]:8443/")
            .body(Body::empty())
            .expect("valid request");
        assert_eq!(
            policy
                .inspect(&mut wrong, peer, false)
                .expect("rejected")
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );
    }

    /// `Permissions-Policy` is the application's call, not the transport's. Hardening must
    /// neither invent one nor touch one a handler set.
    #[test]
    fn hardening_leaves_permissions_policy_entirely_to_the_application() {
        let policy = SecurityPolicy::new();
        let name = hyper::header::HeaderName::from_static("permissions-policy");

        let mut untouched = empty_response(StatusCode::OK);
        policy.finalize_response(&mut untouched, true);
        assert!(
            !untouched.headers().contains_key(&name),
            "hardening must not synthesize a Permissions-Policy"
        );

        let mut application_set = empty_response(StatusCode::OK);
        let _ = application_set.headers_mut().insert(
            name.clone(),
            hyper::header::HeaderValue::from_static("geolocation=(self)"),
        );
        policy.finalize_response(&mut application_set, true);
        assert_eq!(application_set.headers()[&name], "geolocation=(self)");
    }

    #[test]
    fn hardened_response_headers_preserve_application_values() {
        let policy = SecurityPolicy::new();
        let mut response = empty_response(StatusCode::BAD_REQUEST);
        response.headers_mut().insert(
            hyper::header::REFERRER_POLICY,
            hyper::header::HeaderValue::from_static("same-origin"),
        );
        response.headers_mut().append(
            hyper::header::REFERRER_POLICY,
            hyper::header::HeaderValue::from_static("unsafe-url"),
        );
        response.headers_mut().insert(
            hyper::header::SERVER,
            hyper::header::HeaderValue::from_static("secret-version"),
        );

        policy.finalize_response(&mut response, true);

        assert_eq!(
            response.headers()[hyper::header::REFERRER_POLICY],
            "same-origin"
        );
        assert_eq!(
            response
                .headers()
                .get_all(hyper::header::REFERRER_POLICY)
                .iter()
                .count(),
            1
        );
        assert_eq!(response.headers()[hyper::header::CACHE_CONTROL], "no-store");
        assert!(
            response
                .headers()
                .contains_key(hyper::header::STRICT_TRANSPORT_SECURITY)
        );
        assert!(!response.headers().contains_key(hyper::header::SERVER));
    }
}
