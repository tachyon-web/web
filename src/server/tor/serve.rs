//! Publishing an onion service and dispatching its rendezvous streams.

use std::sync::Arc;

use arti_client::TorClient;
use arti_client::config::{CfgPath, TorClientConfigBuilder};
use futures_util::StreamExt as _;
use safelog::DisplayRedacted as _;
use tor_cell::relaycell::msg::Connected;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_hsservice::StreamRequest;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

use super::OnionConfig;
use super::config::parse_nickname;
use crate::server::accept::ConnectionLimit;
use crate::server::anonymous::{Acceptor, serve_stream};
use crate::server::shared::Shared;
use crate::{Endpoint, Error, Network, Reachability};

/// The virtual port plaintext HTTP clients connect to, as a browser assumes for `http://`.
const ONION_HTTP_PORT: u16 = 80;
/// The virtual port HTTPS clients connect to.
#[cfg(feature = "tls")]
const ONION_HTTPS_PORT: u16 = 443;

/// Publishes `config`'s onion service and serves it until the service stops or the future is
/// dropped.
pub(crate) async fn serve(shared: Arc<Shared>, config: OnionConfig) -> Result<(), Error> {
    let client = match config.client.clone() {
        Some(client) => client,
        None => bootstrap(&config).await?,
    };
    let service_config = OnionServiceConfigBuilder::default()
        .nickname(parse_nickname(&config.nickname)?)
        .build()
        .map_err(Error::transport)?;
    let Some((service, requests)) = client
        .launch_onion_service(service_config)
        .map_err(Error::transport)?
    else {
        return Err(Error::config(
            "onion services are disabled in this TorClient's config",
        ));
    };
    let host: Arc<str> = service
        .onion_address()
        .map(|addr| addr.display_unredacted().to_string())
        .ok_or_else(|| Error::transport("arti reported no onion address"))?
        .into();
    shared.allow_hosts([host.to_string()]);

    #[cfg(feature = "tls")]
    let acceptor = crate::server::anonymous::acceptor(&shared, config.tls.as_ref(), &host)?;
    #[cfg(not(feature = "tls"))]
    let acceptor: Option<Acceptor> = None;
    #[cfg(feature = "tls")]
    let redirect = config.redirect_http;
    #[cfg(not(feature = "tls"))]
    let redirect = false;

    if !redirect {
        shared.info.publish(endpoint(&host, ONION_HTTP_PORT, false));
    }
    #[cfg(feature = "tls")]
    if acceptor.is_some() {
        shared.info.publish(endpoint(&host, ONION_HTTPS_PORT, true));
    }

    // Publication (introduction points built, descriptor accepted by `HsDirs`) can take
    // minutes and can later degrade, so it is tracked for as long as the service runs.
    let mut status_events = service.status_events();
    let mut last_state = None;
    let streams = tor_hsservice::handle_rend_requests(requests);
    tokio::pin!(streams);
    // On shutdown, stop taking streams but keep `service` alive: dropping it cuts the
    // connections still draining. The task is aborted once they have closed.
    let mut draining = false;
    loop {
        tokio::select! {
            () = shared.shutdown.requested(), if !draining => draining = true,
            Some(status) = status_events.next() => {
                let state = status.state();
                if last_state != Some(state) {
                    crate::telemetry_info!("[tor] onion service status: {state:?}");
                    last_state = Some(state);
                    let reachability = if state.is_fully_reachable() {
                        Reachability::Reachable
                    } else {
                        Reachability::Pending
                    };
                    shared.info.set_reachability(&host, reachability);
                }
            }
            request = streams.next(), if !draining => {
                let Some(request) = request else { break };
                let permit = shared.connections.acquire().await;
                let shared = shared.clone();
                let acceptor = acceptor.clone();
                let host = host.clone();
                ConnectionLimit::serve(permit, async move {
                    if let Err(e) = handle_stream(shared, request, acceptor, redirect, host).await {
                        crate::telemetry_debug!("[tor] connection error: {e}");
                    }
                });
            }
            else => std::future::pending().await,
        }
    }
    drop(service);
    Err(Error::transport("the onion service stopped"))
}

fn endpoint(host: &str, port: u16, tls: bool) -> Endpoint {
    Endpoint {
        network: Network::Tor,
        host: host.to_string(),
        port,
        tls,
        http3: false,
        reachability: Reachability::Pending,
    }
}

async fn bootstrap(config: &OnionConfig) -> Result<Arc<TorClient<PreferredRuntime>>, Error> {
    let mut builder = TorClientConfigBuilder::default();
    if let Some(dir) = &config.state_dir {
        builder
            .storage()
            .state_dir(CfgPath::new_literal(dir.clone()));
    }
    if let Some(dir) = &config.cache_dir {
        builder
            .storage()
            .cache_dir(CfgPath::new_literal(dir.clone()));
    }
    if !config.vanguards {
        builder
            .vanguards()
            .mode(ExplicitOrAuto::Explicit(VanguardMode::Disabled));
    }
    // arti's relay TLS reads rustls's process-wide provider. It gets the build's default
    // policy, not the server's: relays are clients of their own, and many lack PQ groups.
    #[cfg(feature = "tls")]
    crate::tls::TlsPolicy::new().install_as_process_default();
    let client_config = builder.build().map_err(Error::transport)?;
    TorClient::create_bootstrapped(client_config)
        .await
        .map_err(Error::transport)
}

/// Accepts a rendezvous stream, bounded in time.
///
/// `StreamRequest::accept` writes a CONNECTED cell onto the circuit, and a peer that simply
/// stops reading can hold that write open by leaving the circuit's flow-control window shut.
/// This runs while holding a connection permit, so an unbounded await here would let a peer
/// pin the whole accept budget without ever speaking HTTP.
async fn accept_onion_stream(
    request: StreamRequest,
) -> Result<tor_proto::client::stream::DataStream, Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(
        crate::server::REQUEST_TIMEOUT,
        request.accept(Connected::new_empty()),
    )
    .await
    .map_err(|_| "timed out accepting onion stream")?
    .map_err(Into::into)
}

/// What to do with a rendezvous request, by the virtual port it targets. A pure function so
/// the dispatch rules are testable without a live Tor connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnionAction {
    Reject,
    ServePlaintext,
    #[cfg(feature = "tls")]
    Redirect,
    #[cfg(feature = "tls")]
    ServeTls,
}

#[cfg_attr(not(feature = "tls"), allow(unused_variables))]
const fn route_onion_request(port: u16, tls: bool, redirect_http: bool) -> OnionAction {
    match port {
        #[cfg(feature = "tls")]
        ONION_HTTP_PORT if tls && redirect_http => OnionAction::Redirect,
        ONION_HTTP_PORT => OnionAction::ServePlaintext,
        #[cfg(feature = "tls")]
        ONION_HTTPS_PORT if tls => OnionAction::ServeTls,
        _ => OnionAction::Reject,
    }
}

async fn handle_stream(
    shared: Arc<Shared>,
    request: StreamRequest,
    acceptor: Option<Acceptor>,
    redirect_http: bool,
    host: Arc<str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(not(feature = "tls"))]
    let _ = host;
    let IncomingStreamRequest::Begin(begin) = request.request() else {
        request.shutdown_circuit()?;
        return Ok(());
    };
    match route_onion_request(begin.port(), acceptor.is_some(), redirect_http) {
        OnionAction::Reject => {
            request.shutdown_circuit()?;
            Ok(())
        }
        OnionAction::ServePlaintext => {
            serve_stream(shared, accept_onion_stream(request).await?, None).await
        }
        #[cfg(feature = "tls")]
        OnionAction::ServeTls => {
            serve_stream(shared, accept_onion_stream(request).await?, acceptor).await
        }
        #[cfg(feature = "tls")]
        OnionAction::Redirect => {
            use crate::server::shared::Origin;
            let stream =
                crate::server::stall::WriteDeadline::new(accept_onion_stream(request).await?);
            let handler = shared.clone();
            let svc = hyper::service::service_fn(move |req: hyper::Request<_>| {
                let mut response = crate::server::redirect::https_redirect(&req, &host, "");
                handler.finalize(&mut response, Origin::plain(None));
                async move { Ok::<_, std::io::Error>(response) }
            });
            crate::server::conn::serve_connection(stream, svc, false, &shared.shutdown).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OnionAction, route_onion_request};

    #[test]
    fn only_the_configured_virtual_ports_are_served() {
        assert_eq!(
            route_onion_request(80, false, false),
            OnionAction::ServePlaintext
        );
        assert_eq!(route_onion_request(443, false, false), OnionAction::Reject);
        let port = rand::random_range(444..=u16::MAX);
        assert_eq!(route_onion_request(port, true, true), OnionAction::Reject);

        #[cfg(feature = "tls")]
        {
            assert_eq!(
                route_onion_request(80, true, false),
                OnionAction::ServePlaintext
            );
            assert_eq!(route_onion_request(80, true, true), OnionAction::Redirect);
            assert_eq!(route_onion_request(443, true, true), OnionAction::ServeTls);
        }
    }
}
