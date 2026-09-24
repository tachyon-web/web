//! The plaintext port-80 listener spawned alongside a TLS listener: answers ACME HTTP-01
//! challenges and redirects everything else to HTTPS.

#[cfg(feature = "cert-gen")]
use std::sync::Arc;
#[cfg(feature = "cert-gen")]
use tokio::net::TcpListener;

#[cfg(feature = "cert-gen")]
use crate::server::accept::ConnectionLimit;
#[cfg(feature = "cert-gen")]
use crate::server::security::empty_response;
#[cfg(all(feature = "cert-gen", feature = "http1"))]
use crate::server::tuning::tune_http1;
#[cfg(all(feature = "cert-gen", feature = "http2", not(feature = "http1")))]
use crate::server::tuning::tune_http2;
#[cfg(feature = "cert-gen")]
use axum::body::Body;
#[cfg(feature = "cert-gen")]
use hyper::service::service_fn;
#[cfg(feature = "cert-gen")]
use hyper::{Request, Response, StatusCode};

/// Parameters for the plaintext port-80 redirect/ACME-challenge listener.
///
/// Always defined because [`bind_and_serve`](crate::server::bind::bind_and_serve) takes an
/// `Option` of it; the fields exist only in `cert-gen` builds, the only ones that construct it.
pub(super) struct RedirectInfo {
    #[cfg(feature = "cert-gen")]
    pub addr: std::net::SocketAddr,
    #[cfg(feature = "cert-gen")]
    pub https_port: u16,
    /// A share of the server's connection pool, so this listener cannot starve the TLS one.
    #[cfg(feature = "cert-gen")]
    pub limit: ConnectionLimit,
    #[cfg(feature = "cert-gen")]
    pub policy: crate::server::SecurityPolicy,
    /// The hostnames this deployment serves. An inbound `Host` that matches none is replaced
    /// with the first entry rather than echoed into `Location`; an empty list rejects every
    /// redirect with `400`.
    #[cfg(feature = "cert-gen")]
    pub allowed_hosts: Arc<[String]>,
}

#[cfg(feature = "cert-gen")]
impl RedirectInfo {
    /// Binds the listener and drives it on a task owned by the returned handle.
    pub(super) async fn spawn(self) -> Result<crate::server::BackgroundTask, std::io::Error> {
        let listener = TcpListener::bind(self.addr).await?;
        Ok(crate::server::BackgroundTask::new(tokio::spawn(
            serve_http_redirect_and_challenges(listener, self),
        )))
    }
}

/// Parses a bind address string (e.g. `"0.0.0.0:443"`) into an `InvalidInput` error on failure.
pub(super) fn parse_addr(addr: &str) -> Result<std::net::SocketAddr, std::io::Error> {
    addr.parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

/// Writes a host into a URL authority, adding the brackets RFC 3986 §3.2.2 requires around a
/// bare IPv6 literal.
///
/// Allow-list entries are stored unbracketed, because that is the form
/// [`SecurityPolicy`](crate::server::SecurityPolicy) compares against — so an IPv6 entry
/// spliced straight into a `Location` would produce `https://::1:8443/`, which is not a URL.
#[cfg(feature = "cert-gen")]
struct UrlHost<'a>(&'a str);

#[cfg(feature = "cert-gen")]
impl std::fmt::Display for UrlHost<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.contains(':') && !self.0.starts_with('[') {
            write!(f, "[{}]", self.0)
        } else {
            f.write_str(self.0)
        }
    }
}
/// Resolves the host to put in the `Location` header of a plaintext→HTTPS redirect.
///
/// An inbound `Host` that matches no allow-list entry is replaced with the first non-wildcard
/// entry rather than echoed back, which would be an open redirect. `None` — an empty list, or
/// only wildcards and no match — means there is nowhere safe to redirect to.
///
/// Matching uses [`bare_host`](crate::server::security::bare_host), the same normalization
/// the security policy uses, so `[::1]:8443` and `::1` agree. The result is an allow-list
/// entry, or for a `*.` wildcard the inbound host that matched it, which `bare_host` has
/// already validated as a URI authority (no `/`, `@`, `?` or `#`).
#[cfg(feature = "cert-gen")]
pub(super) fn resolve_redirect_host<'a>(
    host_header: &'a str,
    allowed: &'a [String],
) -> Option<&'a str> {
    if let Some(candidate) = crate::server::security::bare_host(host_header)
        && let Some(entry) = allowed
            .iter()
            .find(|entry| crate::server::security::host_allowed(entry, candidate))
    {
        return Some(if entry.starts_with("*.") {
            candidate
        } else {
            entry.as_str()
        });
    }
    allowed
        .iter()
        .find(|entry| !entry.starts_with("*."))
        .map(String::as_str)
}
/// Plain HTTP listener that answers `/.well-known/acme-challenge/<token>` from the in-process
/// challenge store and `308`s everything else (`308` keeps the method) to the HTTPS URL.
///
/// Reachable by anyone on port 80, so it gets the same `tune_http1!` hardening (including the
/// Slowloris header timeout) as every other listener, and only HTTP/1.1 — the only thing ACME
/// validators and redirect-following clients speak here.
#[cfg(feature = "cert-gen")]
async fn serve_http_redirect_and_challenges(listener: TcpListener, info: RedirectInfo) {
    let RedirectInfo {
        https_port,
        allowed_hosts,
        limit,
        policy,
        ..
    } = info;
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    #[cfg(feature = "http1")]
    {
        tune_http1!(builder.http1());
        builder = builder.http1_only();
    }
    #[cfg(not(feature = "http1"))]
    tune_http2!(builder.http2());
    let port_suffix = if https_port == 443 {
        String::new()
    } else {
        format!(":{https_port}")
    };

    loop {
        let (stream, _peer) = crate::server::http::accept_forever(&listener, "http-redirect").await;
        let permit = limit.acquire().await;
        let io = hyper_util::rt::TokioIo::new(crate::server::stall::WriteDeadline::new(stream));
        let builder = builder.clone();
        let allowed_hosts = allowed_hosts.clone();
        let port_suffix = port_suffix.clone();
        let policy = policy.clone();

        ConnectionLimit::serve(permit, async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let mut response = redirect_or_challenge(&req, &allowed_hosts, &port_suffix);
                policy.finalize_response(&mut response, false);
                async move { Ok::<_, std::convert::Infallible>(response) }
            });
            let _ = builder.serve_connection(io, service).await;
        });
    }
}

/// The ACME HTTP-01 answer for a pending challenge token, or a `308` to the HTTPS URL.
#[cfg(feature = "cert-gen")]
fn redirect_or_challenge<B>(
    req: &Request<B>,
    allowed_hosts: &[String],
    port_suffix: &str,
) -> Response<Body> {
    #[cfg(feature = "lets-encrypt")]
    if req.method() == hyper::Method::GET
        && let Some(token) = req
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
        && let Some(key_auth) = crate::tls::acme::get_challenge(token)
    {
        let mut response = Response::new(Body::from(key_auth));
        let _ = response.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain"),
        );
        return response;
    }

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let Some(redirect_host) = resolve_redirect_host(host, allowed_hosts) else {
        return empty_response(StatusCode::BAD_REQUEST);
    };
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let location = format!(
        "https://{}{port_suffix}{path_and_query}",
        UrlHost(redirect_host)
    );
    let Ok(location) = hyper::header::HeaderValue::from_str(&location) else {
        return empty_response(StatusCode::BAD_REQUEST);
    };
    let mut response = empty_response(StatusCode::PERMANENT_REDIRECT);
    let _ = response
        .headers_mut()
        .insert(hyper::header::LOCATION, location);
    response
}

#[cfg(all(test, feature = "cert-gen"))]
mod tests {
    use super::UrlHost;

    /// Allow-list entries hold IPv6 literals unbracketed, so splicing one straight into a
    /// `Location` produced `https://::1:8443/` — not a URL any client can follow.
    #[test]
    fn url_host_brackets_a_bare_ipv6_literal_and_nothing_else() {
        assert_eq!(UrlHost("::1").to_string(), "[::1]");
        assert_eq!(UrlHost("[::1]").to_string(), "[::1]");
        assert_eq!(UrlHost("example.com").to_string(), "example.com");
    }
}
