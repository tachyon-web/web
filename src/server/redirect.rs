//! The plaintext port-80 listener beside HTTPS: answers ACME HTTP-01 challenges and
//! redirects everything else to HTTPS.

use std::sync::Arc;
use tokio::net::TcpListener;

use crate::server::accept::ConnectionLimit;
use crate::server::conn::serve_connection;
use crate::server::security::empty_response;
use crate::server::shared::{Origin, Shared};
use crate::server::stall::WriteDeadline;
use axum::body::Body;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};

/// Serves `308`s to HTTPS on `https_port`, and ACME challenges, on `listener`, drawing on
/// `limit` — a share of the server's pool, so this listener cannot starve the TLS one.
///
/// `hosts` are the names this deployment serves. An inbound `Host` that matches none is
/// replaced with the first entry rather than echoed into `Location`; with no names every
/// redirect is refused with `400`.
pub(crate) async fn serve_redirect(
    shared: Arc<Shared>,
    listener: TcpListener,
    https_port: u16,
    hosts: Arc<[String]>,
    limit: ConnectionLimit,
) {
    let port_suffix: Arc<str> = if https_port == 443 {
        Arc::from("")
    } else {
        Arc::from(format!(":{https_port}"))
    };
    loop {
        let Some((stream, peer)) =
            crate::server::http::accept_next(&listener, "http-redirect", &shared.shutdown).await
        else {
            return;
        };
        let permit = limit.acquire().await;
        let shared = shared.clone();
        let hosts = hosts.clone();
        let port_suffix = port_suffix.clone();
        ConnectionLimit::serve(permit, async move {
            let origin = Origin::plain(Some(peer));
            let handler = shared.clone();
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let mut response = redirect_or_challenge(&req, &hosts, &port_suffix);
                handler.finalize(&mut response, origin);
                async move { Ok::<_, std::io::Error>(response) }
            });
            // HTTP/1.1 only: all ACME validators and redirect-following clients speak here.
            let io = WriteDeadline::new(stream);
            let _ = serve_connection(io, service, false, &shared.shutdown).await;
        });
    }
}

/// Writes a host into a URL authority, adding the brackets RFC 3986 §3.2.2 requires around a
/// bare IPv6 literal.
///
/// Allow-list entries are stored unbracketed, because that is the form
/// [`SecurityPolicy`](crate::server::SecurityPolicy) compares against — so an IPv6 entry
/// spliced straight into a `Location` would produce `https://::1:8443/`, which is not a URL.
struct UrlHost<'a>(&'a str);

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
pub(crate) fn resolve_redirect_host<'a>(
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
/// The ACME HTTP-01 answer for a pending challenge token, or a `308` to the HTTPS URL.
pub(crate) fn redirect_or_challenge<B>(
    req: &Request<B>,
    allowed_hosts: &[String],
    port_suffix: &str,
) -> Response<Body> {
    #[cfg(feature = "acme")]
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
    resolve_redirect_host(host, allowed_hosts).map_or_else(
        || empty_response(StatusCode::BAD_REQUEST),
        |redirect_host| https_redirect(req, redirect_host, port_suffix),
    )
}

/// A `308` to `req` on `https://{host}{port_suffix}`. Only an origin-form target has a path to
/// carry over; `*` and authority-form targets go to `/`.
pub(crate) fn https_redirect<B>(req: &Request<B>, host: &str, port_suffix: &str) -> Response<Body> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(hyper::http::uri::PathAndQuery::as_str)
        .filter(|target| target.starts_with('/'))
        .unwrap_or("/");
    let location = format!("https://{}{port_suffix}{path_and_query}", UrlHost(host));
    let Ok(location) = hyper::header::HeaderValue::from_str(&location) else {
        return empty_response(StatusCode::BAD_REQUEST);
    };
    let mut response = empty_response(StatusCode::PERMANENT_REDIRECT);
    let _ = response
        .headers_mut()
        .insert(hyper::header::LOCATION, location);
    response
}

#[cfg(test)]
mod tests {
    use super::{UrlHost, https_redirect};

    /// Allow-list entries hold IPv6 literals unbracketed, so splicing one straight into a
    /// `Location` produced `https://::1:8443/` — not a URL any client can follow.
    #[test]
    fn url_host_brackets_a_bare_ipv6_literal_and_nothing_else() {
        assert_eq!(UrlHost("::1").to_string(), "[::1]");
        assert_eq!(UrlHost("[::1]").to_string(), "[::1]");
        assert_eq!(UrlHost("example.com").to_string(), "example.com");
    }

    /// The path and query survive; an asterisk-form target has no path and must not be spliced
    /// onto the host as `https://host*`.
    #[test]
    fn redirects_keep_the_path_of_origin_form_targets_only() {
        let host = format!("{:x}.example", rand::random::<u64>());
        let query = rand::random::<u32>();
        let location = |method: hyper::Method, target: String| {
            let req = hyper::Request::builder()
                .method(method)
                .uri(target)
                .body(())
                .expect("request");
            let response = https_redirect(&req, &host, ":8443");
            assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
            response.headers()[hyper::header::LOCATION]
                .to_str()
                .expect("ASCII location")
                .to_string()
        };

        assert_eq!(
            location(hyper::Method::GET, format!("/a/b?q={query}")),
            format!("https://{host}:8443/a/b?q={query}")
        );
        assert_eq!(
            location(hyper::Method::OPTIONS, "*".to_string()),
            format!("https://{host}:8443/")
        );
    }
}
