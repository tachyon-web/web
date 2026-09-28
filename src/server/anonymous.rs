//! What the Tor and I2P transports share: an optional TLS layer terminated on each stream, over
//! a network that exposes no peer address.

use std::sync::Arc;

use hyper::service::service_fn;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::server::conn::serve_connection;
use crate::server::http::hyper_handler;
use crate::server::shared::{Origin, Shared};
use crate::server::stall::WriteDeadline;

#[cfg(feature = "tls")]
pub(crate) type Acceptor = tokio_rustls::TlsAcceptor;
/// Uninhabited: without `tls` there is never an acceptor.
#[cfg(not(feature = "tls"))]
#[derive(Clone)]
pub(crate) enum Acceptor {}

/// Loads `tls`'s certificates for the service at `host`, which is always among their names,
/// and publishes them. Under the automatic host rule their names are answered too, as a
/// clearnet endpoint's are.
#[cfg(feature = "tls")]
pub(crate) fn acceptor(
    shared: &Shared,
    tls: Option<&crate::tls::Tls>,
    host: &str,
) -> Result<Option<Acceptor>, crate::Error> {
    let Some(tls) = tls else {
        return Ok(None);
    };
    let names: Vec<String> = std::iter::once(host.to_string())
        .chain(tls.domains.iter().cloned())
        .collect();
    let built = crate::tls::certs::build(
        tls,
        &shared.tls_policy,
        &names,
        &format!("https://{host}"),
        crate::server::alpn(false),
    )?;
    if matches!(
        shared.security.host_rule(),
        crate::server::security::HostRule::Auto
    ) {
        let cert_names = built
            .store
            .infos()
            .into_iter()
            .flat_map(|info| info.names.clone());
        shared.allow_hosts(tls.domains.iter().cloned().chain(cert_names));
    }
    shared.info.add_certificates(built.store);
    Ok(Some(Acceptor::from(built.config)))
}

/// Serves HTTP on one stream, behind TLS when `acceptor` is set.
pub(crate) async fn serve_stream<IO>(
    shared: Arc<Shared>,
    stream: IO,
    acceptor: Option<Acceptor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = WriteDeadline::new(stream);
    let handler = shared.clone();
    match acceptor {
        None => {
            let svc =
                service_fn(move |req| hyper_handler(handler.clone(), req, Origin::plain(None)));
            let http2 = shared.security.allows_h2c();
            serve_connection(stream, svc, http2, &shared.shutdown).await
        }
        #[cfg(feature = "tls")]
        Some(acceptor) => {
            let timeout = crate::server::ANONYMOUS_TLS_HANDSHAKE_TIMEOUT;
            let Some(tls) =
                crate::server::http::tls_handshake(&shared, &acceptor, stream, timeout).await
            else {
                return Ok(());
            };
            let svc = service_fn(move |req| hyper_handler(handler.clone(), req, Origin::tls(None)));
            serve_connection(tls, svc, true, &shared.shutdown).await
        }
        #[cfg(not(feature = "tls"))]
        Some(never) => match never {},
    }
}

#[cfg(all(test, any(feature = "http1", feature = "tls")))]
mod tests {
    use super::*;
    use crate::server::conn::Shutdown;
    use crate::{Limits, SecurityPolicy, ServerInfo};

    /// Keep the returned trigger alive: dropping it requests shutdown.
    fn shared(
        router: axum::Router,
        policy: SecurityPolicy,
    ) -> (Shared, tokio::sync::watch::Sender<bool>) {
        let (trigger, shutdown) = Shutdown::new();
        let shared = Shared::new(
            router,
            Limits::default(),
            policy,
            ServerInfo::new(),
            shutdown,
            #[cfg(feature = "tls")]
            crate::tls::TlsPolicy::new(),
        );
        (shared, trigger)
    }

    /// An anonymous stream has no peer address, so even a trust-everything proxy list must not
    /// let it supply forwarding headers.
    #[cfg(feature = "http1")]
    #[tokio::test]
    async fn an_anonymous_stream_never_passes_forwarding_headers_through() {
        use axum::http::HeaderMap;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let router = axum::Router::new().route(
            "/",
            axum::routing::get(|headers: HeaderMap| async move {
                headers.contains_key("x-forwarded-for").to_string()
            }),
        );
        let trust_all = ["0.0.0.0/0", "::/0"].map(|cidr| cidr.parse().expect("valid CIDR"));
        let (shared, _trigger) = shared(router, SecurityPolicy::new().trusted_proxies(trust_all));
        let (mut client, server) = tokio::io::duplex(8 * 1024);
        let connection = tokio::spawn(serve_stream(Arc::new(shared), server, None));

        let forwarded = std::net::Ipv4Addr::from(rand::random::<u32>());
        let request = format!(
            "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {forwarded}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.expect("write");
        let mut response = String::new();
        client.read_to_string(&mut response).await.expect("read");

        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("false"), "{response}");
        connection.await.expect("join").expect("served");
    }

    /// An anonymous endpoint's extra TLS names are answered like a clearnet endpoint's, but
    /// never widen an explicit allow-list.
    #[cfg(feature = "tls")]
    #[test]
    fn tls_names_join_only_the_automatic_allow_list() {
        use crate::tls::{KeyAlgorithm, Tls};

        let host = format!("{:x}.onion", rand::random::<u128>());
        let extra = format!("{:x}.example", rand::random::<u64>());
        let tls = Tls::new()
            .domains([extra.clone()])
            .self_signed(KeyAlgorithm::MlDsa87);
        let explicit = SecurityPolicy::new().allowed_hosts(["clearnet.example"]);

        for (policy, answers_extra) in [(SecurityPolicy::new(), true), (explicit, false)] {
            let (shared, _trigger) = shared(axum::Router::new(), policy);
            shared.set_hosts(Some(vec!["clearnet.example".to_string()]));
            shared.allow_hosts([host.clone()]);
            assert!(
                acceptor(&shared, Some(&tls), &host)
                    .expect("build")
                    .is_some()
            );

            let hosts = shared.hosts().expect("an enforced list");
            assert_eq!(hosts.iter().filter(|name| **name == host).count(), 1);
            assert_eq!(hosts.contains(&extra), answers_extra);
        }
    }
}
