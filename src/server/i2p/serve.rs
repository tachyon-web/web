//! Publishing an eepsite and dispatching its streams.

use std::sync::Arc;

use tachyon_i2p::I2pRouter;

use super::I2pConfig;
use crate::server::accept::ConnectionLimit;
use crate::server::conn::serve_connection;
use crate::server::http::hyper_handler;
use crate::server::shared::{Origin, Shared};
use crate::server::stall::WriteDeadline;
use crate::{Endpoint, Error, Network, Reachability};

#[cfg(feature = "tls")]
type Acceptor = tokio_rustls::TlsAcceptor;
/// Uninhabited: without `tls` there is never an acceptor.
#[cfg(not(feature = "tls"))]
#[derive(Clone)]
enum Acceptor {}

/// Publishes `config`'s eepsite and serves it until the future is dropped.
pub(crate) async fn serve(shared: Arc<Shared>, config: I2pConfig) -> Result<(), Error> {
    let router = match &config.router {
        Some(router) => router.clone(),
        None => I2pRouter::start(config.nickname.clone())
            .await
            .map_err(Error::transport)?,
    };
    let mut destination = router
        .destination_from_keys_file(
            config.keys_path(),
            true,
            config.sig_type,
            &config.encryption_types,
        )
        .await
        .map_err(Error::transport)?;
    let host = destination.b32_address().to_string();
    shared.allow_host(&host);

    #[cfg(feature = "tls")]
    let acceptor: Option<Acceptor> = match &config.tls {
        Some(tls) => {
            let url = format!("https://{host}");
            let names: Vec<String> = std::iter::once(host.clone())
                .chain(tls.domains.iter().cloned())
                .collect();
            let built = crate::tls::certs::build(
                tls,
                &shared.tls_policy,
                &names,
                &url,
                crate::server::alpn(false),
            )?;
            shared.info.add_certificates(built.store);
            Some(tokio_rustls::TlsAcceptor::from(built.config))
        }
        None => None,
    };
    #[cfg(not(feature = "tls"))]
    let acceptor: Option<Acceptor> = None;

    let tls = acceptor.is_some();
    shared.info.publish(Endpoint {
        network: Network::I2p,
        host,
        port: if tls { 443 } else { 80 },
        tls,
        http3: false,
        reachability: Reachability::Unconfirmed,
    });

    loop {
        let stream = accept_i2p_forever(&mut destination).await;
        let permit = shared.connections.acquire().await;
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        ConnectionLimit::serve(permit, async move {
            if let Err(e) = handle_stream(shared, stream, acceptor).await {
                crate::telemetry_debug!("[i2p] connection error: {e}");
            }
        });
    }
}

/// Accepts the next I2P stream, retrying after a short back-off: one failed accept must not
/// end the eepsite.
async fn accept_i2p_forever(destination: &mut tachyon_i2p::Destination) -> tachyon_i2p::I2pStream {
    loop {
        match destination.accept().await {
            Ok(stream) => return stream,
            Err(e) => {
                crate::telemetry_debug!("[i2p] accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_stream(
    shared: Arc<Shared>,
    stream: tachyon_i2p::I2pStream,
    acceptor: Option<Acceptor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream = WriteDeadline::new(stream);
    let handler = shared.clone();
    match acceptor {
        None => {
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(handler.clone(), req, Origin::plain(None))
            });
            let http2 = shared.security.allows_h2c();
            serve_connection(stream, svc, http2, &shared.shutdown).await
        }
        #[cfg(feature = "tls")]
        Some(acceptor) => {
            let Some(tls) = crate::server::http::tls_handshake(&shared, &acceptor, stream).await
            else {
                return Ok(());
            };
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(handler.clone(), req, Origin::tls(None))
            });
            serve_connection(tls, svc, true, &shared.shutdown).await
        }
        #[cfg(not(feature = "tls"))]
        Some(never) => match never {},
    }
}
