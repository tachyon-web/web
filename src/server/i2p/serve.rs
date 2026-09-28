//! Publishing an eepsite and dispatching its streams.

use std::sync::Arc;

use tachyon_i2p::I2pRouter;

use super::I2pConfig;
use crate::server::accept::ConnectionLimit;
use crate::server::anonymous::serve_stream;
use crate::server::shared::Shared;
use crate::{Endpoint, Error, Network, Reachability};

/// Publishes `config`'s eepsite and serves it until the destination closes or the future is
/// dropped.
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
    shared.allow_hosts([host.clone()]);

    #[cfg(feature = "tls")]
    let acceptor = crate::server::anonymous::acceptor(&shared, config.tls.as_ref(), &host)?;
    #[cfg(not(feature = "tls"))]
    let acceptor: Option<crate::server::anonymous::Acceptor> = None;

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
        let accepted = tokio::select! {
            biased;
            () = shared.shutdown.requested() => break,
            accepted = destination.accept() => accepted,
        };
        // `accept` only fails once the destination has closed, for good.
        let stream = accepted.map_err(Error::transport)?;
        let permit = shared.connections.acquire().await;
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        ConnectionLimit::serve(permit, async move {
            if let Err(e) = serve_stream(shared, stream, acceptor).await {
                crate::telemetry_debug!("[i2p] connection error: {e}");
            }
        });
    }
    // Keep `destination` alive while its connections drain; the task is aborted after.
    std::future::pending().await
}
