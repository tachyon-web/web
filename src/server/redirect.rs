//! The plaintext port-80 listener spawned alongside a TLS listener: answers ACME HTTP-01
//! challenges and redirects everything else to HTTPS.

#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio::net::TcpListener;

#[cfg(feature = "tls")]
use crate::server::accept::ConnectionLimit;
#[cfg(all(feature = "tls", feature = "http1"))]
use crate::server::tuning::tune_http1;
#[cfg(all(feature = "tls", feature = "http2", not(feature = "http1")))]
use crate::server::tuning::tune_http2;
#[cfg(feature = "tls")]
use axum::body::Body;
#[cfg(feature = "tls")]
use hyper::service::service_fn;
#[cfg(feature = "tls")]
use hyper::{Request, Response};

/// Parameters for the plaintext port-80 redirect/ACME-challenge listener spawned alongside a
/// TLS listener — see [`serve_http_redirect_and_challenges`].
///
/// Always defined because the shared bind path, [`bind_and_serve`](crate::server::bind::bind_and_serve),
/// takes `Option<RedirectInfo>` unconditionally — only *constructing* a `Some` (and consuming
/// it there) requires the `tls` feature.
#[derive(Clone)]
pub(super) struct RedirectInfo {
    // All three fields are only ever populated behind `#[cfg(feature = "tls")]` construction
    // sites — cfg'd out entirely (rather than left in and unread) for a non-`tls` build, so
    // that build doesn't trip `-D dead-code` over a type it can only ever hold as `None`.
    #[cfg(feature = "tls")]
    pub addr: std::net::SocketAddr,
    #[cfg(feature = "tls")]
    pub https_port: u16,
    /// A share of the server's connection pool, not the pool itself — built with
    /// [`ConnectionLimit::with_share`] so this listener cannot starve the TLS one.
    #[cfg(feature = "tls")]
    pub limit: ConnectionLimit,
    #[cfg(feature = "tls")]
    pub policy: crate::server::SecurityPolicy,
    /// The known-good hostnames this deployment serves, when available (e.g. the ACME
    /// `domains` list in [`Server::serve_all_acme`]). An inbound `Host` header that doesn't
    /// match any entry is replaced with the first domain rather than echoed into `Location`.
    /// `None` means no hostname is trusted and redirects are rejected with `400`; this is used
    /// by APIs that receive only certificate bytes and therefore cannot establish an explicit
    /// host allow-list.
    #[cfg(feature = "tls")]
    pub allowed_hosts: Option<Arc<[String]>>,
}
/// Parses a bind address string (e.g. `"0.0.0.0:443"`), wrapping the error the same way every
/// `serve_*`/`start_*` entry point below does — shared so that wrapping can't drift between
/// call sites.
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
#[cfg(feature = "tls")]
struct UrlHost<'a>(&'a str);

#[cfg(feature = "tls")]
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
/// When `allowed_hosts` is `Some` (i.e. the caller knows its real domain list — see
/// [`RedirectInfo::allowed_hosts`]), an inbound `Host` that doesn't match any entry is replaced
/// with the first allowed domain rather than echoed back: otherwise a request naming an
/// arbitrary `Host` would get a same-status redirect to an attacker-chosen origin (an open
/// redirect). `None` rejects the redirect because no request-provided authority is trustworthy.
///
/// Returns `None` when there is no host that can safely be redirected to — either no
/// allow-list was supplied, or the one that was is empty. Falling back to the inbound `Host`
/// in either case would reopen exactly the hole this function exists to close.
///
/// The inbound `Host` is reduced by [`bare_host`](crate::server::security::bare_host), the
/// same normalization the allow-list itself is matched with, so `[::1]:8443` and `::1` reach
/// one answer here too. The result is always an allow-list entry, never request-controlled
/// text, so [`UrlHost`] is all that stands between it and a well-formed `Location`.
#[cfg(feature = "tls")]
pub(super) fn resolve_redirect_host<'a>(
    host_header: &'a str,
    allowed_hosts: Option<&'a [String]>,
) -> Option<&'a str> {
    let candidate = crate::server::security::bare_host(host_header);
    let allowed = allowed_hosts?;
    allowed
        .iter()
        .find(|d| candidate.is_some_and(|host| d.eq_ignore_ascii_case(host)))
        .or_else(|| allowed.first())
        .map(String::as_str)
}
/// Plain HTTP listener that answers `/.well-known/acme-challenge/<token>` from the global
/// challenge store and `308`s everything else to the equivalent HTTPS URL.
///
/// `308` rather than `301` because it preserves the request method, so redirected `POST`s stay
/// `POST`s.
///
/// This listener is bound to port 80 and therefore reachable by anyone, even though it never
/// reaches application handlers. Its `limit` is a *share* of the server's global connection
/// budget rather than the whole of it — see
/// [`Server::redirect_connection_share`](crate::server::Server::redirect_connection_share) —
/// so a flood here cannot take the permits the TLS listener needs.
///
/// *Tachyon extension: no `axum` equivalent.*
#[cfg(feature = "tls")]
pub(super) async fn serve_http_redirect_and_challenges(
    listener: TcpListener,
    https_port: u16,
    allowed_hosts: Option<Arc<[String]>>,
    limit: ConnectionLimit,
    policy: crate::server::SecurityPolicy,
) {
    // This listener is bound to port 80 and reachable by anyone, so it gets exactly the same
    // hardening as the real one — `tune_http1!` carries the `header_read_timeout` that stops a
    // client from opening a connection, never finishing its request line, and holding one of
    // the server's global permits forever (Slowloris).
    //
    // HTTP/1.1 only: that is what ACME validators and redirect-following clients speak on port
    // 80, so HTTP/2 here would be parser surface with no user. An `http2`-only build has no
    // other choice.
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    #[cfg(feature = "http1")]
    {
        tune_http1!(builder.http1());
        builder = builder.http1_only();
    }
    #[cfg(not(feature = "http1"))]
    tune_http2!(builder.http2());
    // Fixed for this listener's lifetime, so it's formatted once here rather than per request.
    let port_suffix: Arc<str> = if https_port == 443 {
        Arc::from("")
    } else {
        Arc::from(format!(":{https_port}"))
    };

    while let Some(permit) = limit.acquire().await {
        let (stream, _peer) = crate::server::http::accept_forever(&listener, "http-redirect").await;
        let io = hyper_util::rt::TokioIo::new(crate::server::stall::WriteDeadline::new(stream));
        let builder = builder.clone();
        let allowed_hosts = allowed_hosts.clone();
        let port_suffix = port_suffix.clone();
        let policy = policy.clone();

        ConnectionLimit::serve(permit, async move {
            let _ = builder
                .serve_connection(
                    io,
                    service_fn(move |req: Request<hyper::body::Incoming>| {
                        let allowed_hosts = allowed_hosts.clone();
                        let port_suffix = port_suffix.clone();
                        let policy = policy.clone();
                        async move {
                            // Serve ACME HTTP-01 challenge response.
                            #[cfg(feature = "lets-encrypt")]
                            if req.method() == hyper::Method::GET
                                && let Some(token) = req
                                    .uri()
                                    .path()
                                    .strip_prefix("/.well-known/acme-challenge/")
                                && let Some(key_auth) = crate::tls::acme::get_challenge(token)
                            {
                                let mut resp = Response::builder()
                                    .status(200)
                                    .header("content-type", "text/plain")
                                    .body(Body::from(bytes::Bytes::from(key_auth)))
                                    .unwrap_or_else(|_| Response::new(Body::empty()));
                                policy.finalize_response(&mut resp, false);
                                return Ok::<_, std::convert::Infallible>(resp);
                            }

                            let host = req
                                .headers()
                                .get("host")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("localhost");
                            let Some(redirect_host) =
                                resolve_redirect_host(host, allowed_hosts.as_deref())
                            else {
                                // No allow-list, or an empty one — nowhere safe to send them.
                                let mut resp = Response::builder()
                                    .status(400)
                                    .body(Body::empty())
                                    .unwrap_or_else(|_| Response::new(Body::empty()));
                                policy.finalize_response(&mut resp, false);
                                return Ok::<_, std::convert::Infallible>(resp);
                            };
                            let path_and_query = req
                                .uri()
                                .path_and_query()
                                .map_or("/", hyper::http::uri::PathAndQuery::as_str);
                            let location = format!(
                                "https://{}{port_suffix}{path_and_query}",
                                UrlHost(redirect_host)
                            );

                            let mut resp =
                                hyper::header::HeaderValue::from_bytes(location.as_bytes())
                                    .map_or_else(
                                        |_| {
                                            let mut resp = Response::new(Body::empty());
                                            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                                            resp
                                        },
                                        |location| {
                                            let mut resp = Response::new(Body::empty());
                                            *resp.status_mut() =
                                                hyper::StatusCode::PERMANENT_REDIRECT;
                                            let _ = resp
                                                .headers_mut()
                                                .insert(hyper::header::LOCATION, location);
                                            resp
                                        },
                                    );
                            policy.finalize_response(&mut resp, false);
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    }),
                )
                .await;
        });
    }
}

#[cfg(all(test, feature = "tls"))]
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
