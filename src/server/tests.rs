//! Tests for server configuration and shared helpers.

use super::*;
use crate::Error;

/// An idle listener must not reserve the only connection permit, or a server with a limit of
/// one serves whichever listener wins a startup race and starves the others for good.
#[cfg(feature = "http1")]
#[tokio::test]
async fn idle_listeners_do_not_hoard_connection_permits() {
    use axum::routing::get;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    let idle = TcpListener::bind("127.0.0.1:0").await.expect("bind idle");
    let active = TcpListener::bind("127.0.0.1:0").await.expect("bind active");
    let active_addr = active.local_addr().expect("active address");
    let server = Server::new(Router::new().route("/", get(|| async { "ok" })))
        .limits(Limits::default().max_connections(1))
        .http(idle)
        .http(active);
    let task = tokio::spawn(server.serve().into_future());

    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(active_addr).await?;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::time::timeout(Duration::from_secs(2), exchange)
        .await
        .expect("active listener was starved")
        .expect("request succeeds");

    task.abort();
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
}

/// Contradictions are reported before anything is bound, not silently ignored.
#[tokio::test]
async fn contradictory_configurations_fail_before_binding() {
    let config_error = |result: Result<(), Error>| matches!(result, Err(Error::Config(_)));

    assert!(config_error(Server::new(Router::new()).serve().await));
    assert!(config_error(
        Server::new(Router::new())
            .security(SecurityPolicy::new().allowed_hosts(Vec::<String>::new()))
            .http("127.0.0.1:0")
            .serve()
            .await
    ));
    #[cfg(feature = "tls")]
    {
        use crate::tls::{KeyAlgorithm, Tls};
        assert!(config_error(
            Server::new(Router::new())
                .redirect("127.0.0.1:0")
                .serve()
                .await
        ));
        assert!(config_error(
            Server::new(Router::new())
                .https("127.0.0.1:0", Tls::new())
                .serve()
                .await
        ));
        assert!(config_error(
            Server::new(Router::new())
                .https("127.0.0.1:0", Tls::new().self_signed(KeyAlgorithm::MlDsa87))
                .serve()
                .await
        ));
    }
    #[cfg(feature = "acme")]
    {
        use crate::tls::{Acme, Tls};
        let tls = Tls::new()
            .domains(["example.com"])
            .store("/nonexistent")
            .acme(Acme::lets_encrypt());
        assert!(config_error(
            Server::new(Router::new())
                .https("127.0.0.1:0", tls)
                .serve()
                .await
        ));
    }
}

#[test]
fn authority_host_strips_the_port_and_keeps_ipv6_brackets() {
    use crate::server::security::authority_host;
    assert_eq!(authority_host("example.com:8443"), Some("example.com"));
    assert_eq!(authority_host("example.com"), Some("example.com"));
    assert_eq!(authority_host("[::1]:8443"), Some("[::1]"));
    assert_eq!(authority_host("[2001:db8::1]:443"), Some("[2001:db8::1]"));
    assert_eq!(authority_host("[::1"), None);
    assert_eq!(authority_host("[::1]junk"), None);
    assert_eq!(authority_host("example.com:not-a-port"), None);
    assert_eq!(authority_host("example.com:65536"), None);
    assert_eq!(authority_host("user@example.com"), None);
}

/// The open-redirect guard: an inbound `Host` is only echoed into `Location` when allowed,
/// matched the way the security policy matches it.
#[cfg(feature = "tls")]
#[test]
fn redirects_only_ever_target_an_allowed_host() {
    use crate::server::redirect::resolve_redirect_host;

    let allowed = vec![
        "example.com".to_string(),
        "::1".to_string(),
        "*.example.org".to_string(),
    ];
    assert_eq!(
        resolve_redirect_host("EXAMPLE.com:80", &allowed),
        Some("example.com")
    );
    // Bracketed request host, unbracketed entry; `::1` isn't first, so only a match yields it.
    assert_eq!(resolve_redirect_host("[::1]:8443", &allowed), Some("::1"));
    assert_eq!(
        resolve_redirect_host("www.example.org", &allowed),
        Some("www.example.org")
    );
    let evil = format!("{:x}.evil.example:80", rand::random::<u64>());
    assert_eq!(resolve_redirect_host(&evil, &allowed), Some("example.com"));
    assert_eq!(
        resolve_redirect_host(&evil, &["*.example.org".to_string()]),
        None
    );
    assert_eq!(resolve_redirect_host(&evil, &[]), None);
}

#[test]
fn is_resource_exhaustion_matches_only_known_codes() {
    for code in [23, 24, 10024] {
        assert!(is_resource_exhaustion(&std::io::Error::from_raw_os_error(
            code
        )));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    for code in [12, 105] {
        assert!(is_resource_exhaustion(&std::io::Error::from_raw_os_error(
            code
        )));
    }
    assert!(!is_resource_exhaustion(&std::io::Error::from_raw_os_error(
        2
    )));
    assert!(!is_resource_exhaustion(&std::io::Error::other(
        "not an os error"
    )));
}
