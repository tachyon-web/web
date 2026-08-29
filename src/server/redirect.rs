//! The plaintext port-80 listener spawned alongside a TLS listener: answers ACME HTTP-01
//! challenges and redirects everything else to HTTPS.

#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio::net::TcpListener;

#[cfg(feature = "tls")]
use crate::http::response::Body;
#[cfg(feature = "tls")]
use crate::server::{REQUEST_TIMEOUT, is_resource_exhaustion};
#[cfg(feature = "tls")]
use hyper::service::service_fn;
#[cfg(feature = "tls")]
use hyper::{Request, Response};

/// Per-worker connection ceiling for the plaintext port-80 redirect listener.
///
/// Far below [`crate::server::Server::max_connections`] on purpose: every connection here gets a bodyless
/// `308` or a challenge token and closes, so the queue drains fast.
#[cfg(feature = "tls")]
pub const REDIRECT_MAX_CONNECTIONS: usize = 2048;
/// Parameters for the plaintext port-80 redirect/ACME-challenge listener spawned alongside a
/// TLS listener — see [`serve_http_redirect_and_challenges`].
///
/// Always defined (not `#[cfg(feature = "tls")]`) because [`run_worker_pool`]'s signature
/// takes `Option<RedirectInfo>` unconditionally — only *constructing* a `Some` (and consuming
/// it in [`run_worker_thread`]) requires the `tls` feature.
#[derive(Clone)]
pub(super) struct RedirectInfo {
    // All three fields are only ever populated behind `#[cfg(feature = "tls")]` construction
    // sites — cfg'd out entirely (rather than left in and unread) for a non-`tls` build, so
    // that build doesn't trip `-D dead-code` over a type it can only ever hold as `None`.
    #[cfg(feature = "tls")]
    pub addr: std::net::SocketAddr,
    #[cfg(feature = "tls")]
    pub https_port: u16,
    /// The known-good hostnames this deployment serves, when available (e.g. the ACME
    /// `domains` list in [`Server::serve_all_acme`]). When `Some`, an inbound `Host` header
    /// that doesn't match any entry is replaced with the first domain rather than echoed back
    /// into the `Location` header — otherwise a request naming an arbitrary `Host` would get a
    /// same-status redirect to an attacker-chosen origin. `None` (e.g. [`Server::start_all`],
    /// which only knows a certificate, not the domain list) falls back to echoing the request's
    /// `Host` unchecked, matching this listener's long-standing behaviour there.
    #[cfg(feature = "tls")]
    pub allowed_hosts: Option<Arc<[String]>>,
}
/// Parses the port number from a bind address string (e.g., `"0.0.0.0:443"`).
/// Falls back to `default_port` if parsing fails.
#[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
pub(super) fn parse_port(addr: &str, default_port: u16) -> u16 {
    addr.split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default_port)
}
/// Parses a bind address string (e.g. `"0.0.0.0:443"`), wrapping the error the same way every
/// `serve_*`/`start_*` entry point below does — shared so that wrapping can't drift between
/// call sites.
pub(super) fn parse_addr(addr: &str) -> Result<std::net::SocketAddr, std::io::Error> {
    addr.parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

/// Strips the trailing `:port` from an HTTP `Host` header value, preserving IPv6 literals'
/// brackets (e.g. `"[::1]:8443"` → `"[::1]"`) so the result is still a valid host in a URL.
#[cfg(feature = "tls")]
pub(super) fn host_without_port(host: &str) -> &str {
    let Some(rest) = host.strip_prefix('[') else {
        return host.split(':').next().unwrap_or(host);
    };
    // `bracket_end` is an index into `rest` (one past the leading `[`); the matching `]` in
    // `host` therefore sits at `bracket_end + 1`, so slicing up to (and including) that needs
    // `..=bracket_end + 1`, i.e. an end bound of `bracket_end + 2`.
    let Some(bracket_end) = rest.find(']') else {
        return host;
    };
    let end = bracket_end.saturating_add(2);
    host.get(..end).unwrap_or(host)
}
/// Resolves the host to put in the `Location` header of a plaintext→HTTPS redirect.
///
/// When `allowed_hosts` is `Some` (i.e. the caller knows its real domain list — see
/// [`RedirectInfo::allowed_hosts`]), an inbound `Host` that doesn't match any entry is replaced
/// with the first allowed domain rather than echoed back: otherwise a request naming an
/// arbitrary `Host` would get a same-status redirect to an attacker-chosen origin (an open
/// redirect). `None` preserves the historical echo-unchecked behaviour for callers that don't
/// have a domain list to validate against (e.g. [`Server::start_all`]).
#[cfg(feature = "tls")]
pub(super) fn resolve_redirect_host<'a>(
    host_header: &'a str,
    allowed_hosts: Option<&'a [String]>,
) -> &'a str {
    let candidate = host_without_port(host_header);
    let Some(allowed) = allowed_hosts else {
        return candidate;
    };
    allowed
        .iter()
        .find(|d| d.eq_ignore_ascii_case(candidate))
        .map_or_else(
            || allowed.first().map_or(candidate, String::as_str),
            String::as_str,
        )
}
/// Plain HTTP listener that answers `/.well-known/acme-challenge/<token>` from the global
/// challenge store and `308`s everything else to the equivalent HTTPS URL.
///
/// `308` rather than `301` because it preserves the request method, so redirected `POST`s stay
/// `POST`s.
///
/// Concurrency is capped at [`REDIRECT_MAX_CONNECTIONS`] per worker. This listener is bound to
/// port 80 and therefore reachable by anyone, but it answers only redirects and ACME
/// challenges — it never reaches the router — so it uses its own fixed ceiling rather than
/// [`crate::server::Server::max_connections`], which sizes the listener that actually runs application
/// handlers.
#[cfg(feature = "tls")]
pub async fn serve_http_redirect_and_challenges(
    listener: TcpListener,
    https_port: u16,
    allowed_hosts: Option<Arc<[String]>>,
) {
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    // Without a `Timer`, hyper silently drops `header_read_timeout` (only a `warn!`, no
    // error) — this listener is bound to port 80 and reachable by anyone, so a client that
    // opens a connection and never finishes its request line would otherwise hold one of
    // [`REDIRECT_MAX_CONNECTIONS`] permits forever (Slowloris).
    let _ = builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(REQUEST_TIMEOUT);
    #[cfg(feature = "http2")]
    let _ = builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(REQUEST_TIMEOUT)
        .keep_alive_timeout(REQUEST_TIMEOUT);
    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(REDIRECT_MAX_CONNECTIONS));

    loop {
        let Ok(permit) = connection_semaphore.clone().acquire_owned().await else {
            return;
        };
        let (stream, _peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("[http-redirect] accept error: {e}");
                drop(permit);
                if is_resource_exhaustion(&e) {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let io = hyper_util::rt::TokioIo::new(stream);
        let builder = builder.clone();
        let allowed_hosts = allowed_hosts.clone();

        drop(tokio::spawn(async move {
            let _ = builder
                .serve_connection(
                    io,
                    service_fn(move |req: Request<hyper::body::Incoming>| {
                        let allowed_hosts = allowed_hosts.clone();
                        async move {
                            // Serve ACME HTTP-01 challenge response.
                            #[cfg(feature = "lets-encrypt")]
                            if let Some(token) = req
                                .uri()
                                .path()
                                .strip_prefix("/.well-known/acme-challenge/")
                                && let Some(key_auth) = crate::tls::acme::get_challenge(token)
                            {
                                let resp = Response::builder()
                                    .status(200)
                                    .header("content-type", "text/plain")
                                    .body(Body::full(bytes::Bytes::from(key_auth)))
                                    .unwrap_or_else(|_| Response::new(Body::empty()));
                                return Ok::<_, std::convert::Infallible>(resp);
                            }

                            // 308 Permanent Redirect to HTTPS (preserves method).
                            let host = req
                                .headers()
                                .get("host")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("localhost");
                            let redirect_host =
                                resolve_redirect_host(host, allowed_hosts.as_deref());
                            let port_suffix = if https_port == 443 {
                                String::new()
                            } else {
                                format!(":{https_port}")
                            };
                            let path_and_query = req
                                .uri()
                                .path_and_query()
                                .map_or("/", hyper::http::uri::PathAndQuery::as_str);
                            let location =
                                format!("https://{redirect_host}{port_suffix}{path_and_query}");

                            let resp = Response::builder()
                                .status(308) // 308 Permanent Redirect preserves the HTTP method.
                                .header("location", &location)
                                .body(Body::empty())
                                .unwrap_or_else(|_| Response::new(Body::empty()));
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    }),
                )
                .await;
            drop(permit);
        }));
    }
}
