//! Opt-in response hardening for `.onion`/`.i2p` routes — see [`anonymity_guard`].
//!
//! Requires the `tor` or `i2p` feature (either is enough; this module has no dependency on
//! either transport's own code, it just targets the failure mode they share).

use crate::http::response::Body;
use crate::routing::middleware::Next;
use hyper::header::{self, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_LOCATION, HeaderMap, LOCATION};
#[cfg(feature = "cookies")]
use hyper::header::{HeaderValue, SET_COOKIE};
use hyper::{Request, Response, StatusCode};

/// Middleware that hardens every response against the classic ways a `.onion`/`.i2p` deployment
/// accidentally deanonymizes itself.
///
/// Install with `.hoop(anonymity_guard)` on a [`Router`](crate::routing::Router) mounted on an
/// anonymity-network transport (see [`Server::serve_onion`](crate::server::Server::serve_onion)/
/// [`Server::serve_i2p_config`](crate::server::Server::serve_i2p_config)).
///
/// On every response, unconditionally:
/// - Strips `Date`, `Server`, and `X-Powered-By` — clock-skew and stack fingerprinting vectors
///   that a client reachable only over Tor/I2P has no legitimate need to see.
/// - Rewrites every `Set-Cookie` header to `SameSite=Strict`, dropping (not forwarding
///   unhardened) any that fail to parse — a cookie usable cross-site is a correlation vector
///   between this service and anywhere else the same browser profile is logged in.
///
/// Additionally, when the request's own `Host` header ends in `.onion` or `.i2p` (i.e. this
/// really is being reached over the anonymity network, not just mounted defensively on a
/// clearnet route too): every `Location`, `Content-Location`, and `Access-Control-Allow-Origin`
/// header is checked for an **absolute** URL whose host is neither the request's own `.onion`/
/// `.i2p` host nor itself anonymity-suffixed. This is the #1 real-world onion-site
/// deanonymization bug — a redirect, canonical-URL, or CORS header that echoes back the
/// operator's clearnet domain (shared config/templates between a clearnet site and its mirror
/// are the usual cause). Rather than silently rewrite or drop just that header (which would
/// mask the underlying bug), the entire response is replaced with a generic `500` — the leak is
/// logged server-side (`tracing::error!`) with the offending header and value for the operator
/// to fix, but never reaches the client.
///
/// This is defense-in-depth, not a substitute for reviewing what your handlers actually set —
/// see the `server::tor`/`server::i2p` module docs for the fuller anonymity threat model.
pub async fn anonymity_guard<S>(req: Request<Body>, next: Next<S>) -> Response<Body>
where
    S: Send + Sync + 'static,
{
    // A `HeaderValue` clone is a cheap `Bytes` refcount bump (not a heap copy), unlike
    // `to_ascii_lowercase()` — kept only to survive past `req` being moved into `next.run`
    // below; the actual case-insensitive comparisons happen after, with no allocation.
    let host_header = req.headers().get(header::HOST).cloned();

    let mut resp = next.run(req).await;

    strip_fingerprinting_headers(resp.headers_mut());
    harden_set_cookie_headers(resp.headers_mut());

    let request_host = host_header
        .as_ref()
        .and_then(|h| h.to_str().ok())
        .map(host_without_port);

    if let Some(host) = request_host
        && looks_like_anonymity_host(host)
        && let Err((leaked_header, leaked_value)) = check_no_clearnet_leak(resp.headers(), host)
    {
        tracing::error!(
            header = leaked_header,
            value = %leaked_value,
            request_host = host,
            "anonymity_guard: response header pointed at what looks like a clearnet origin on \
             a `.onion`/`.i2p` request — replacing the response with 500 instead of letting it \
             reach the client; fix the handler/middleware that set this header"
        );
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::full(bytes::Bytes::from_static(
                b"Internal Server Error",
            )))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    resp
}

/// Strips the `:port` suffix from a `Host` header value, if present. An IPv6 literal is
/// bracketed (`[::1]:8080`), so it's the brackets — not the first colon, of which the address
/// itself has several — that delimit the host there.
fn host_without_port(host: &str) -> &str {
    host.strip_prefix('[').map_or_else(
        || host.split(':').next().unwrap_or(host),
        |v6| v6.split_once(']').map_or(v6, |(h, _)| h),
    )
}

/// Case-insensitive suffix check, since `host` isn't necessarily lowercased by every caller
/// (the request `Host` header is checked as-is, without an allocating `to_ascii_lowercase`).
fn ends_with_ignore_ascii_case(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len() && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn looks_like_anonymity_host(host: &str) -> bool {
    ends_with_ignore_ascii_case(host, ".onion") || ends_with_ignore_ascii_case(host, ".i2p")
}

fn strip_fingerprinting_headers(headers: &mut HeaderMap) {
    let _ = headers.remove(header::DATE);
    let _ = headers.remove(header::SERVER);
    let _ = headers.remove("x-powered-by");
}

/// Rewrites every `Set-Cookie` header to carry `SameSite=Strict`. A header that fails to parse
/// as a cookie is dropped entirely rather than forwarded unhardened.
///
/// A no-op without the `cookies` feature — the `cookie` crate this needs to parse and
/// re-serialize `Set-Cookie` values is only pulled in when that feature is on. Enable
/// `cookies` alongside `tor`/`i2p` to get this specific hardening.
#[cfg(feature = "cookies")]
fn harden_set_cookie_headers(headers: &mut HeaderMap) {
    let original: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    if original.is_empty() {
        return;
    }
    headers.remove(SET_COOKIE);
    for value in original {
        let hardened = value.to_str().ok().and_then(|s| {
            let mut cookie = cookie::Cookie::parse(s.to_string()).ok()?;
            cookie.set_same_site(cookie::SameSite::Strict);
            HeaderValue::from_str(&cookie.to_string()).ok()
        });
        match hardened {
            Some(hv) => {
                headers.append(SET_COOKIE, hv);
            }
            None => {
                tracing::warn!(
                    "anonymity_guard: dropped a Set-Cookie header that couldn't be parsed and \
                     hardened to SameSite=Strict"
                );
            }
        }
    }
}

#[cfg(not(feature = "cookies"))]
const fn harden_set_cookie_headers(_headers: &mut HeaderMap) {}

/// Returns `Err((header name, offending value))` for the first `Location`/`Content-Location`/
/// `Access-Control-Allow-Origin` header whose value is an absolute URL pointing at a host that
/// is neither `request_host` nor itself `.onion`/`.i2p`-suffixed.
fn check_no_clearnet_leak(
    headers: &HeaderMap,
    request_host: &str,
) -> Result<(), (&'static str, String)> {
    for (name, header_name) in [
        ("location", &LOCATION),
        ("content-location", &CONTENT_LOCATION),
        ("access-control-allow-origin", &ACCESS_CONTROL_ALLOW_ORIGIN),
    ] {
        for value in headers.get_all(header_name) {
            let Ok(s) = value.to_str() else { continue };
            let Some(host) = absolute_url_host(s) else {
                continue;
            };
            if !host.eq_ignore_ascii_case(request_host) && !looks_like_anonymity_host(host) {
                return Err((name, s.to_string()));
            }
        }
    }
    Ok(())
}

/// Whether `s` is syntactically a URL scheme (RFC 3986 §3.1) — used to tell `https://host` apart
/// from a path that merely happens to contain a colon.
fn is_url_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(char::is_alphabetic)
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Extracts the host from a URL carrying an authority component — `scheme://host[:port][/...]`
/// **and** the scheme-relative `//host[:port][/...]`. Returns `None` for anything that can't
/// name a different origin (a relative path like `/foo`, or `*`/`null` as seen in
/// `Access-Control-Allow-Origin`), so there's nothing to check.
///
/// Scheme-relative URLs matter as much as fully absolute ones here and were previously missed
/// entirely: `Location: //example.com/` is resolved by every browser against the *current*
/// scheme, so it navigates off the `.onion`/`.i2p` origin to a clearnet host exactly like
/// `https://example.com/` would — it just doesn't contain `://` for the old check to find.
/// Backslashes are accepted wherever a browser accepts them in place of `/` (WHATWG URL treats
/// `https:\\host` and `https:/\host` as authority-introducing), so a leak can't hide behind one.
fn absolute_url_host(value: &str) -> Option<&str> {
    let value = value.trim();
    let after_scheme = match value.split_once(':') {
        Some((scheme, rest)) if is_url_scheme(scheme) => rest,
        _ => value,
    };
    // Two of any mix of `/` and `\` introduce the authority.
    let mut authority_chars = after_scheme.chars();
    let is_sep = |c: Option<char>| matches!(c, Some('/' | '\\'));
    if !is_sep(authority_chars.next()) || !is_sep(authority_chars.next()) {
        return None;
    }
    let rest = authority_chars.as_str();

    let host_and_rest = rest.split(['/', '\\', '?', '#']).next().unwrap_or(rest);
    let host_and_port = host_and_rest.rsplit('@').next().unwrap_or(host_and_rest);
    // IPv6 literals are bracketed (`[::1]:8080`); elsewhere the first colon starts the port.
    let host = host_and_port.strip_prefix('[').map_or_else(
        || host_and_port.split(':').next().unwrap_or(host_and_port),
        |v6| v6.split_once(']').map_or(v6, |(h, _)| h),
    );
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::routing::{Router, get};

    fn build_app<H, T>(handler: H) -> Router
    where
        H: crate::routing::handler::Handler<T, ()> + Clone + Send + Sync + 'static,
        T: Send + Sync + 'static,
    {
        Router::new().route("/", get(handler)).hoop(anonymity_guard)
    }

    fn req_with_host(host: &str) -> Request<Body> {
        Request::builder()
            .uri("/")
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    }

    /// A scheme-relative `Location` leaks the operator's clearnet host exactly like a fully
    /// absolute one — every browser resolves `//example.com/` against the current scheme and
    /// navigates straight off the onion origin. It contains no `://`, so the old check never
    /// looked at it at all.
    #[tokio::test]
    async fn scheme_relative_location_is_caught_as_a_leak() {
        for leak in [
            "//example.com/admin",
            r"\\example.com/admin",
            r"/\example.com/admin",
            "HTTPS://example.com/admin",
        ] {
            let app = build_app(move || async move {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(LOCATION, leak)
                    .body(Body::empty())
                    .unwrap()
            });
            let resp = app.handle_request(req_with_host("abc.onion")).await;
            assert_eq!(
                resp.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "leak not caught: {leak}"
            );
        }
    }

    /// The flip side: a same-origin or genuinely relative redirect must pass through untouched,
    /// or the guard would break every ordinary redirect on the site.
    #[tokio::test]
    async fn same_origin_and_relative_locations_pass_through() {
        for ok in [
            "/dashboard",
            "http://abc.onion/dashboard",
            "//abc.onion/dashboard",
            "http://other.i2p/",
        ] {
            let app = build_app(move || async move {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(LOCATION, ok)
                    .body(Body::empty())
                    .unwrap()
            });
            let resp = app.handle_request(req_with_host("abc.onion")).await;
            assert_eq!(resp.status(), StatusCode::FOUND, "wrongly rejected: {ok}");
        }
    }

    #[test]
    fn absolute_url_host_parses_ipv6_and_userinfo() {
        assert_eq!(
            absolute_url_host("https://[2001:db8::1]:8443/x"),
            Some("2001:db8::1")
        );
        assert_eq!(
            absolute_url_host("https://user:pw@example.com/x"),
            Some("example.com")
        );
        // Not authority-bearing: nothing that can name another origin.
        assert_eq!(absolute_url_host("/relative/path"), None);
        assert_eq!(absolute_url_host("*"), None);
        assert_eq!(absolute_url_host("null"), None);
    }

    #[test]
    fn host_without_port_handles_ipv6_literals() {
        assert_eq!(host_without_port("abc.onion:8080"), "abc.onion");
        assert_eq!(host_without_port("[2001:db8::1]:8080"), "2001:db8::1");
    }

    #[tokio::test]
    async fn strips_date_and_server_headers() {
        async fn handler() -> Response<Body> {
            Response::builder()
                .header(header::DATE, "Mon, 01 Jan 2024 00:00:00 GMT")
                .header(header::SERVER, "tachyon-web")
                .body(Body::empty())
                .unwrap()
        }
        let app = build_app(handler);
        let resp = app.handle_request(req_with_host("abc.onion")).await;
        assert!(resp.headers().get(header::DATE).is_none());
        assert!(resp.headers().get(header::SERVER).is_none());
    }

    #[tokio::test]
    async fn forces_samesite_strict_on_cookies() {
        async fn handler() -> Response<Body> {
            Response::builder()
                .header(header::SET_COOKIE, "session=abc; Path=/")
                .body(Body::empty())
                .unwrap()
        }
        let app = build_app(handler);
        let resp = app.handle_request(req_with_host("abc.onion")).await;
        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.contains("SameSite=Strict"), "cookie: {cookie}");
    }

    #[tokio::test]
    async fn blocks_response_leaking_a_clearnet_redirect() {
        async fn handler() -> Response<Body> {
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "https://my-real-site.example/dashboard")
                .body(Body::empty())
                .unwrap()
        }
        let app = build_app(handler);
        let resp = app.handle_request(req_with_host("abc.onion")).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get(header::LOCATION).is_none());
    }

    #[tokio::test]
    async fn allows_relative_redirects() {
        async fn handler() -> Response<Body> {
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "/dashboard")
                .body(Body::empty())
                .unwrap()
        }
        let app = build_app(handler);
        let resp = app.handle_request(req_with_host("abc.onion")).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn allows_redirects_to_the_same_onion_host() {
        async fn handler() -> Response<Body> {
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "http://abc.onion/dashboard")
                .body(Body::empty())
                .unwrap()
        }
        let app = build_app(handler);
        let resp = app.handle_request(req_with_host("abc.onion")).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn does_not_check_leaks_on_a_non_anonymity_host() {
        async fn handler() -> Response<Body> {
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "https://example.com/dashboard")
                .body(Body::empty())
                .unwrap()
        }
        let app = build_app(handler);
        let resp = app.handle_request(req_with_host("clearnet.example")).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
    }

    #[test]
    fn absolute_url_host_examples() {
        assert_eq!(
            absolute_url_host("https://example.com/foo"),
            Some("example.com")
        );
        assert_eq!(
            absolute_url_host("http://abc.onion:8080/foo"),
            Some("abc.onion")
        );
        assert_eq!(absolute_url_host("/relative/path"), None);
        assert_eq!(absolute_url_host("*"), None);
        assert_eq!(absolute_url_host("null"), None);
    }
}
