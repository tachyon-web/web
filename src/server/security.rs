//! Request-boundary security policy.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Body;
use hyper::{Request, Response, StatusCode};

const FORWARDED_HEADERS: [&str; 26] = [
    "forwarded",
    "cf-connecting-ip",
    "client-ip",
    "cloudfront-viewer-address",
    "do-connecting-ip",
    "fastly-client-ip",
    "fly-client-ip",
    "proxy-client-ip",
    "true-client-ip",
    "wl-proxy-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-envoy-external-address",
    "x-real-ip",
    "x-forwarded-client-cert",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-forwarded-proto",
    "x-forwarded-server",
    "x-original-forwarded-for",
    "x-original-host",
    "x-original-proto",
    "x-original-url",
    "x-rewrite-url",
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
        // A proxy reaching a dual-stack listener is reported as `::ffff:a.b.c.d`, so an
        // IPv4 network configured for it would otherwise never match and its forwarding
        // headers would be stripped as if it were untrusted.
        let candidate = match candidate {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(candidate, IpAddr::V4),
            IpAddr::V4(_) => candidate,
        };
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

    /// Restricts requests to these case-insensitive DNS names or IP literals. A leading `*.`
    /// matches exactly one DNS label, mirroring a wildcard certificate SAN.
    ///
    /// An empty explicit list rejects every authority. Authority enforcement is disabled only
    /// when this builder is never called.
    #[must_use]
    pub fn allowed_hosts(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allowed_hosts = hosts.into_iter().map(Into::into).collect::<Vec<_>>().into();
        self.flags |= ENFORCE_AUTHORITY;
        self
    }

    /// Sets the networks allowed to supply forwarding headers. Tor and I2P peers are never
    /// trusted, whatever this contains — they have no network address to match.
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

    /// Allows or rejects the HTTP `CONNECT` method. It is rejected by default. RFC 8441
    /// extended CONNECT (a WebSocket over HTTP/2) is not a tunnel and is never rejected here.
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

    /// Seeds the allow-list from a source the caller derived rather than stated — a
    /// certificate's SANs, or the ACME `domains` list — leaving an explicitly configured one
    /// untouched.
    ///
    /// An empty `hosts` leaves enforcement *off*. Deriving nothing means the caller learned
    /// nothing about which names this deployment answers to (a certificate with only IP SANs,
    /// say), which is not the same statement as [`allowed_hosts`](Self::allowed_hosts) with an
    /// empty list — and turning it into one would silently `421` every request the server ever
    /// receives.
    #[cfg(feature = "cert-gen")]
    pub(super) fn set_default_allowed_hosts(&mut self, hosts: Arc<[String]>) {
        if self.flags & ENFORCE_AUTHORITY == 0 && !hosts.is_empty() {
            self.allowed_hosts = hosts;
            self.flags |= ENFORCE_AUTHORITY;
        }
    }

    /// Whether plaintext listeners should speak HTTP/2 at all — see
    /// [`allow_h2c`](Self::allow_h2c).
    pub(super) const fn allows_h2c(&self) -> bool {
        self.flags & ALLOW_H2C != 0
    }

    /// `peer` is `None` for an anonymity transport, which can never be a trusted proxy.
    pub(super) fn inspect(
        &self,
        req: &mut Request<Body>,
        peer: Option<std::net::SocketAddr>,
        secure_transport: bool,
    ) -> Option<Response<Body>> {
        // Plaintext listeners stop offering HTTP/2 when h2c is off, so this only still fires in
        // an `http2`-only build, which has no HTTP/1.1 to fall back to.
        if !self.allows_h2c() && !secure_transport && req.version() == hyper::Version::HTTP_2 {
            return Some(empty_response(StatusCode::UPGRADE_REQUIRED));
        }
        if req.headers().contains_key(hyper::header::TRANSFER_ENCODING)
            && req.headers().contains_key(hyper::header::CONTENT_LENGTH)
        {
            return Some(empty_response(StatusCode::BAD_REQUEST));
        }
        if content_length(req.headers()).is_err() {
            return Some(empty_response(StatusCode::BAD_REQUEST));
        }
        // RFC 9112 §3.2: more than one `Host` MUST be rejected.
        if req
            .headers()
            .get_all(hyper::header::HOST)
            .iter()
            .nth(1)
            .is_some()
        {
            return Some(empty_response(StatusCode::BAD_REQUEST));
        }
        if req.headers().get(hyper::header::HOST).is_some_and(|value| {
            value
                .to_str()
                .map_or(true, |authority| authority_host(authority).is_none())
        }) || req
            .uri()
            .authority()
            .is_some_and(|authority| authority_host(authority.as_str()).is_none())
        {
            return Some(empty_response(StatusCode::BAD_REQUEST));
        }
        // RFC 8441 extended CONNECT is how WebSockets ride HTTP/2 — a routed request, not a tunnel.
        #[cfg(feature = "http2")]
        let extended_connect = req.extensions().get::<hyper::ext::Protocol>().is_some();
        #[cfg(not(feature = "http2"))]
        let extended_connect = false;
        if self.flags & REJECT_CONNECT != 0
            && req.method() == hyper::Method::CONNECT
            && !extended_connect
        {
            return Some(empty_response(StatusCode::METHOD_NOT_ALLOWED));
        }

        if self.flags & ENFORCE_AUTHORITY != 0 && !self.authority_allowed(req) {
            return Some(empty_response(StatusCode::MISDIRECTED_REQUEST));
        }

        let trusted = peer.is_some_and(|peer| {
            self.trusted_proxies
                .iter()
                .any(|network| network.contains(peer.ip()))
        });
        if self.flags & STRIP_UNTRUSTED_FORWARDING != 0 && !trusted {
            for header in FORWARDED_HEADERS {
                req.headers_mut().remove(header);
            }
        }
        None
    }

    /// Every authority a handler could read must be allowed — the request target's *and* the
    /// `Host` header's — and, when both exist, their hosts and effective ports must agree.
    /// Checking whichever came first let `GET http://allowed/` with `Host: evil` (or two
    /// conflicting authorities) reach an app that builds links from the other value.
    fn authority_allowed(&self, req: &Request<Body>) -> bool {
        // Both spellings go through `bare_host` — see its docs for why that matters.
        let is_allowed = |authority: &str| {
            bare_host(authority).is_some_and(|host| {
                self.allowed_hosts
                    .iter()
                    .any(|allowed| host_allowed(allowed, host))
            })
        };
        let target = req
            .uri()
            .authority()
            .map(hyper::http::uri::Authority::as_str);
        let header = req
            .headers()
            .get(hyper::header::HOST)
            .map(|value| value.to_str().unwrap_or_default());
        if let (Some(target), Some(header)) = (target, header)
            && !authorities_match(target, header, req.uri().scheme_str())
        {
            return false;
        }
        (target.is_some() || header.is_some())
            && target.is_none_or(is_allowed)
            && header.is_none_or(is_allowed)
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

/// Compares every part of two authorities that can affect URL construction. Omitting a
/// scheme's default port is equivalent to spelling it explicitly; any other port mismatch is
/// rejected so handlers cannot see a trusted request-target host beside an attacker-chosen
/// `Host` port.
fn authorities_match(target: &str, header: &str, scheme: Option<&str>) -> bool {
    let hosts_match = bare_host(target).is_some_and(|target| {
        bare_host(header).is_some_and(|header| target.eq_ignore_ascii_case(header))
    });
    if !hosts_match {
        return false;
    }

    let default_port = match scheme {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => Some(80),
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => Some(443),
        _ => None,
    };
    let port = |authority: &str| {
        authority
            .parse::<hyper::http::uri::Authority>()
            .ok()
            .and_then(|authority| authority.port_u16())
            .or(default_port)
    };
    port(target) == port(header)
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
/// Returns `None` for any malformed authority, including an invalid port or bracket suffix.
pub(super) fn authority_host(authority: &str) -> Option<&str> {
    if authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let bracket_end = rest.find(']')?.checked_add(2)?;
        (authority.get(..bracket_end)?, authority.get(bracket_end..)?)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        (host, port)
    } else {
        (authority, "")
    };
    let port = port.strip_prefix(':').unwrap_or(port);
    if host.is_empty()
        || host.parse::<hyper::http::uri::Authority>().is_err()
        || (!port.is_empty()
            && (!port.bytes().all(|byte| byte.is_ascii_digit()) || port.parse::<u16>().is_err()))
        || (authority.ends_with(':') && port.is_empty())
    {
        return None;
    }
    Some(host)
}

/// [`authority_host`] reduced to the form a host allow-list compares against: an IPv6
/// literal's brackets removed, so `[::1]` and `::1` are one host.
///
/// The two spellings both reach [`SecurityPolicy::inspect`] — `Authority::host` keeps the
/// brackets, a `Host` header never has them — so both must come through here or one address
/// gets different answers over HTTP/1.1 and HTTP/2.
pub(super) fn bare_host(authority: &str) -> Option<&str> {
    let host = authority_host(authority)?;
    Some(
        host.strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host),
    )
}

/// Matches one normalized host against an allow-list entry. A wildcard follows certificate
/// rules and covers exactly one label; all other entries are exact and case-insensitive.
pub(super) fn host_allowed(allowed: &str, host: &str) -> bool {
    let Some(suffix) = allowed.strip_prefix("*.") else {
        return allowed.eq_ignore_ascii_case(host);
    };
    let Some(split) = host.len().checked_sub(suffix.len()) else {
        return false;
    };
    let (Some(prefix), Some(actual_suffix)) = (host.get(..split), host.get(split..)) else {
        return false;
    };
    let Some(label) = prefix.strip_suffix('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('.') && actual_suffix.eq_ignore_ascii_case(suffix)
}

/// Parses `Content-Length`, accepting repeated or comma-joined values only when every value
/// is identical, as required by RFC 9110 section 8.6.
pub(super) fn content_length(headers: &hyper::HeaderMap) -> Result<Option<u64>, ()> {
    let mut parsed = None;
    for value in headers.get_all(hyper::header::CONTENT_LENGTH) {
        let value = value.to_str().map_err(|_| ())?;
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() || !item.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(());
            }
            let length = item.parse::<u64>().map_err(|_| ())?;
            if parsed.is_some_and(|previous| previous != length) {
                return Err(());
            }
            parsed = Some(length);
        }
    }
    Ok(parsed)
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

    /// A proxy reaching a dual-stack listener is reported as `::ffff:a.b.c.d`. Without
    /// unmapping, an IPv4 `trusted_proxies` entry never matches it and the deployment silently
    /// strips the forwarding headers of the one peer it was configured to believe.
    #[test]
    fn ipv4_network_trusts_a_proxy_arriving_over_a_dual_stack_socket() {
        let network = "10.2.0.0/16".parse::<IpNetwork>().expect("valid CIDR");
        assert!(network.contains("::ffff:10.2.4.8".parse().expect("valid IP")));
        assert!(!network.contains("::ffff:10.3.4.8".parse().expect("valid IP")));
    }

    /// Tor/I2P peers have no address. Even a trust-everything proxy list must not let one
    /// supply forwarding headers, as the old `0.0.0.0` placeholder peer did.
    #[test]
    fn anonymous_peers_are_never_trusted_proxies() {
        let policy =
            SecurityPolicy::new().trusted_proxies(["0.0.0.0/0".parse().expect("valid CIDR")]);
        let request = || {
            Request::builder()
                .uri("/")
                .header("x-forwarded-for", "198.51.100.7")
                .header("x-forwarded-client-cert", "spoofed-client-identity")
                .body(Body::empty())
                .expect("valid request")
        };

        let mut anonymous = request();
        assert!(policy.inspect(&mut anonymous, None, false).is_none());
        assert!(!anonymous.headers().contains_key("x-forwarded-for"));
        assert!(!anonymous.headers().contains_key("x-forwarded-client-cert"));

        let mut proxied = request();
        let proxy = Some("0.0.0.0:0".parse().expect("valid peer"));
        assert!(policy.inspect(&mut proxied, proxy, false).is_none());
        assert!(proxied.headers().contains_key("x-forwarded-for"));
        assert!(proxied.headers().contains_key("x-forwarded-client-cert"));
    }

    /// Deriving no hostnames (a certificate with only IP SANs, say) means "nothing was
    /// learned", not "deny everything" — the latter would `421` every request forever.
    #[cfg(feature = "cert-gen")]
    #[test]
    fn an_empty_derived_allow_list_leaves_authority_enforcement_off() {
        let mut policy = SecurityPolicy::new();
        policy.set_default_allowed_hosts(Arc::from([]));
        let mut request = Request::builder()
            .uri("/")
            .header("host", "anything.example")
            .body(Body::empty())
            .expect("valid request");
        assert!(
            policy
                .inspect(
                    &mut request,
                    Some("203.0.113.1:1".parse().expect("valid peer")),
                    false,
                )
                .is_none()
        );
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
                    Some("203.0.113.1:1".parse().expect("valid peer")),
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
                    Some("203.0.113.1:1".parse().expect("valid peer")),
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
                    Some("203.0.113.1:1".parse().expect("valid peer")),
                    true,
                )
                .expect("empty allow-list rejects every host")
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );
    }

    /// Handlers read `Host`, so the request target vouching for the authority is not enough:
    /// every spelling present must pass, and a second `Host` is malformed outright.
    #[test]
    fn every_authority_a_handler_could_read_must_be_allowed() {
        let policy = SecurityPolicy::new().allowed_hosts(["example.com"]);
        let peer = Some("203.0.113.1:1".parse().expect("valid peer"));
        let inspect = |uri: &str, hosts: &[&str]| {
            let mut builder = Request::builder().uri(uri);
            for host in hosts {
                builder = builder.header("host", *host);
            }
            let mut request = builder.body(Body::empty()).expect("valid request");
            policy
                .inspect(&mut request, peer, false)
                .map(|response| response.status())
        };

        assert_eq!(
            inspect("http://example.com/", &["evil.example"]),
            Some(StatusCode::MISDIRECTED_REQUEST)
        );
        assert_eq!(
            inspect("/", &["example.com", "evil.example"]),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(inspect("http://example.com/", &["example.com:80"]), None);
        assert_eq!(
            inspect("http://example.com/", &["example.com:443"]),
            Some(StatusCode::MISDIRECTED_REQUEST)
        );
        assert_eq!(inspect("https://example.com:443/", &["example.com"]), None);
        assert_eq!(
            inspect("/", &["example.com:not-a-port"]),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(inspect("/", &["[::1]junk"]), Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            inspect("http://user@example.com/", &[]),
            Some(StatusCode::BAD_REQUEST)
        );

        let policy = SecurityPolicy::new().allowed_hosts(["a.example", "b.example"]);
        let mut conflicting = Request::builder()
            .uri("http://a.example/")
            .header("host", "b.example")
            .body(Body::empty())
            .expect("valid request");
        assert_eq!(
            policy
                .inspect(&mut conflicting, peer, false)
                .expect("conflicting authorities are rejected")
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );
    }

    #[test]
    fn content_length_values_must_be_valid_and_unambiguous() {
        let parse = |values: &[&str]| {
            let mut headers = hyper::HeaderMap::new();
            for value in values {
                headers.append(
                    hyper::header::CONTENT_LENGTH,
                    hyper::header::HeaderValue::from_str(value).expect("valid header value"),
                );
            }
            content_length(&headers)
        };

        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(parse(&["42", "42"]), Ok(Some(42)));
        assert_eq!(parse(&["42, 42"]), Ok(Some(42)));
        assert_eq!(parse(&["42", "43"]), Err(()));
        assert_eq!(parse(&["42, 43"]), Err(()));
        assert_eq!(parse(&["invalid"]), Err(()));
        assert_eq!(parse(&["+42"]), Err(()));
    }

    #[test]
    fn wildcard_hosts_cover_exactly_one_label() {
        assert!(host_allowed("*.example.com", "www.example.com"));
        assert!(host_allowed("*.EXAMPLE.com", "WWW.example.COM"));
        assert!(!host_allowed("*.example.com", "example.com"));
        assert!(!host_allowed("*.example.com", "a.b.example.com"));
        assert!(!host_allowed("*.example.com", ".example.com"));
    }

    /// A WebSocket over HTTP/2 arrives as extended CONNECT; refusing it with the tunnel form
    /// silently broke every `ws` route served over h2.
    #[cfg(feature = "http2")]
    #[test]
    fn extended_connect_is_routed_while_a_plain_tunnel_is_refused() {
        let policy = SecurityPolicy::new();
        let peer = Some("203.0.113.1:1".parse().expect("valid peer"));

        let mut tunnel = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri("example.com:443")
            .body(Body::empty())
            .expect("valid request");
        assert_eq!(
            policy
                .inspect(&mut tunnel, peer, true)
                .expect("tunnel rejected")
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let mut websocket = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri("https://example.com/ws")
            .extension(hyper::ext::Protocol::from_static("websocket"))
            .body(Body::empty())
            .expect("valid request");
        assert!(policy.inspect(&mut websocket, peer, true).is_none());
    }

    /// `Authority::host` keeps an IPv6 literal's brackets, a `Host` header does not. Both
    /// forms must land on the same allow-list decision, or the same deployment answers
    /// HTTP/1.1 and HTTP/2 differently for one address.
    #[test]
    fn ipv6_literal_matches_whether_it_arrives_as_authority_or_host_header() {
        let policy = SecurityPolicy::new().allowed_hosts(["::1"]);
        let peer = Some("203.0.113.1:1".parse().expect("valid peer"));

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
