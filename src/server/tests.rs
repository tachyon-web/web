//! Tests for shared server configuration and helpers.

use super::*;
#[cfg(feature = "tls")]
use crate::server::redirect::{host_without_port, resolve_redirect_host};
use axum::Router;

/// `Server::clone` is hand-written (the field list is feature-gated, so `derive` can't be
/// used); this catches a field being dropped when a new one is added.
#[test]
#[allow(clippy::redundant_clone)]
fn clone_preserves_every_field() {
    #[cfg_attr(not(any(feature = "tls", feature = "http3")), allow(unused_mut))]
    let mut server = Server::new(Router::new())
        .max_body_size(4096)
        .max_connections(7);
    #[cfg(feature = "http3")]
    {
        server = server.max_h3_concurrent_streams(11);
    }
    #[cfg(feature = "tls")]
    {
        server = server.tls_policy(crate::tls::TlsPolicy::new().tls13_only());
    }

    let cloned = server.clone();
    assert_eq!(cloned.max_body_size, 4096);
    assert_eq!(cloned.max_connections, 7);
    #[cfg(feature = "http3")]
    assert_eq!(cloned.max_h3_concurrent_streams, 11);
    #[cfg(feature = "tls")]
    assert!(cloned.tls_policy.is_some());
}

#[cfg(feature = "tls")]
#[test]
fn host_without_port_strips_a_plain_hostname() {
    assert_eq!(host_without_port("example.com:8443"), "example.com");
    assert_eq!(host_without_port("example.com"), "example.com");
}

#[cfg(feature = "tls")]
#[test]
fn host_without_port_preserves_ipv6_brackets() {
    assert_eq!(host_without_port("[::1]:8443"), "[::1]");
    assert_eq!(host_without_port("[::1]"), "[::1]");
    assert_eq!(host_without_port("[2001:db8::1]:443"), "[2001:db8::1]");
}

#[cfg(feature = "tls")]
#[test]
fn resolve_redirect_host_echoes_unchecked_when_no_allow_list_is_known() {
    // `start_all`/`start_all_inner` only have a cert, not a domain list — matches the
    // long-standing behaviour there.
    assert_eq!(
        resolve_redirect_host("attacker.example:80", None),
        Some("attacker.example")
    );
}

#[cfg(feature = "tls")]
#[test]
fn resolve_redirect_host_rejects_a_host_that_is_not_host_shaped() {
    // With no allow-list the `Host` is echoed, so anything that isn't a bare authority lets
    // the peer control the `Location` path/query as well as its origin.
    for hostile in [
        "evil.example/path",
        "evil.example?x=1",
        "evil.example#frag",
        "user@evil.example",
        "",
        "..",
    ] {
        assert_eq!(resolve_redirect_host(hostile, None), None, "{hostile}");
    }
    // Ordinary authorities still pass, including IPv6 literals and IPv4.
    assert_eq!(resolve_redirect_host("[::1]:8443", None), Some("[::1]"));
    assert_eq!(resolve_redirect_host("10.0.0.1:80", None), Some("10.0.0.1"));
    assert_eq!(
        resolve_redirect_host("sub.example-1.com", None),
        Some("sub.example-1.com")
    );
}

#[cfg(feature = "tls")]
#[test]
fn resolve_redirect_host_accepts_a_matching_allowed_host() {
    let allowed = vec!["example.com".to_string(), "www.example.com".to_string()];
    assert_eq!(
        resolve_redirect_host("EXAMPLE.com:80", Some(&allowed)),
        Some("example.com"),
        "matching must be case-insensitive, and the request's own casing is dropped in \
         favor of the configured domain"
    );
    assert_eq!(
        resolve_redirect_host("www.example.com", Some(&allowed)),
        Some("www.example.com")
    );
}

#[cfg(feature = "tls")]
#[test]
fn resolve_redirect_host_falls_back_to_the_first_allowed_domain_on_a_mismatch() {
    // The open-redirect regression test: an inbound `Host` naming an arbitrary origin must
    // never be echoed back into a same-status `Location` header when a domain allow-list
    // is known (e.g. `serve_all_acme`'s `domains`).
    let allowed = vec!["example.com".to_string(), "www.example.com".to_string()];
    assert_eq!(
        resolve_redirect_host("evil.example:80", Some(&allowed)),
        Some("example.com")
    );

    // An allow-list that is present but empty used to fall through `allowed.first()` straight
    // back to the inbound `Host`, i.e. fail open into the very redirect this guards against.
    // With no trustworthy host and nothing to fall back to, the only safe answer is no
    // redirect at all — the caller turns this into a 400.
    assert_eq!(resolve_redirect_host("evil.example:80", Some(&[])), None);
}

#[test]
fn is_resource_exhaustion_matches_only_known_codes() {
    for code in [23, 24, 10024] {
        assert!(
            is_resource_exhaustion(&std::io::Error::from_raw_os_error(code)),
            "code: {code}"
        );
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    for code in [12, 105] {
        assert!(
            is_resource_exhaustion(&std::io::Error::from_raw_os_error(code)),
            "code: {code}"
        );
    }
    assert!(!is_resource_exhaustion(&std::io::Error::from_raw_os_error(
        2
    )));
    assert!(!is_resource_exhaustion(&std::io::Error::other(
        "not an os error"
    )));
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn rustls_config_from_pem_rejects_garbage_input() {
    let err = RustlsConfig::from_pem(b"not a cert".to_vec(), b"not a key".to_vec())
        .await
        .expect_err("garbage PEM must not build a config");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(feature = "cert-gen")]
#[tokio::test]
async fn rustls_config_from_pem_builds_from_a_valid_self_signed_cert() {
    let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
        .expect("generate self-signed cert");
    let config = RustlsConfig::from_pem(cert.cert_pem.into_bytes(), cert.key_pem.into_bytes())
        .await
        .expect("build config from valid PEM");
    assert!(!config.server_config.alpn_protocols.is_empty());
}

#[cfg(feature = "cert-gen")]
#[test]
fn bind_rustls_and_https_server_builders() {
    let cert = crate::tls::generate_self_signed_cert(vec!["localhost".to_string()])
        .expect("generate self-signed cert");
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der], cert.key_der)
        .expect("build server config");
    server_config.alpn_protocols = alpn_protocols(false);
    let config = RustlsConfig {
        server_config: Arc::new(server_config),
    };
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("parse addr");

    let https_server = bind_rustls(addr, config);
    assert_eq!(https_server.addr, addr);
    assert!(!https_server.serve_http3);
    let dbg = format!("{https_server:?}");
    assert!(dbg.contains("HttpsServer"));
    assert!(dbg.contains("serve_http3: false"));

    let https_server = https_server.serve_http3(true);
    assert!(https_server.serve_http3);
    let dbg = format!("{https_server:?}");
    assert!(dbg.contains("serve_http3: true"));
}
