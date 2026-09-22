//! `Server::serve_tor*`/`serve_onion*` entry points and per-rendezvous-stream dispatch.

use super::OnionConfig;
use super::config::parse_nickname;
use crate::server::Server;
use crate::server::accept::ConnectionLimit;
#[cfg(feature = "tls")]
use crate::server::anon_tls::AnonTls;
use crate::server::conn::{NO_PEER_ADDR as ONION_PEER_ADDR, serve_connection};
use crate::server::http::hyper_handler;
use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
#[cfg(feature = "tls")]
use axum::body::Body;
use futures_util::StreamExt as _;
#[cfg(feature = "tls")]
use hyper::{Request, Response};
use safelog::DisplayRedacted as _;
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tor_cell::relaycell::msg::Connected;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_hsservice::StreamRequest;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::Runtime;

/// The virtual port plaintext HTTP clients connect to — mirrors how a clearnet browser assumes
/// port 80 for a bare `http://` URL, regardless of what port the service actually listens on
/// inside the Tor network.
const ONION_HTTP_PORT: u16 = 80;
/// The virtual port HTTPS clients connect to, matching the clearnet `https://` convention.
/// Only meaningful when the `tls` feature is enabled.
#[cfg(feature = "tls")]
const ONION_HTTPS_PORT: u16 = 443;

impl<S> Server<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Publishes this router as a Tor `.onion` hidden service and serves requests arriving
    /// over it, blocking until the service stops.
    ///
    /// Bootstraps a fresh [`TorClient`] with [`TorClientConfig::default`] — this alone can
    /// take from several seconds up to a minute or more, since it involves connecting to and
    /// syncing with the live Tor network — then behaves like
    /// [`serve_tor_with_client`](Server::serve_tor_with_client). Reuse a [`TorClient`] across
    /// calls (via `serve_tor_with_client`) rather than bootstrapping one per service.
    ///
    /// This is the plaintext-only entry point (virtual port 80 only, no HTTPS, no
    /// configuration) — available under the `tor` feature alone, no TLS stack required. For
    /// native onion HTTPS (needs the `tls` feature too), custom state/cache directories, or the
    /// other [`OnionConfig`] options, use [`serve_onion`](Server::serve_onion) instead.
    ///
    /// # Errors
    /// Returns an error if the Tor client fails to bootstrap, `nickname` is not a valid
    /// [`HsNickname`](tor_hsservice::HsNickname), or the onion service fails to launch.
    pub async fn serve_tor(
        self,
        nickname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Install this server's crypto/TLS policy as rustls's process-wide default *before*
        // bootstrapping — arti reads this global default for its own relay/channel TLS
        // connections (it has no API to accept a `ClientConfig` directly). See `TlsPolicy`'s
        // docs. Idempotent: a no-op if something already installed a default. Only relevant
        // (and only compiled) when this crate's own `tls` feature is enabled — without it,
        // arti simply falls back to whatever crypto provider it installs on its own.
        #[cfg(feature = "tls")]
        self.effective_tls_policy().install_as_process_default();
        let client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
        self.serve_tor_with_client(&client, nickname).await
    }

    /// Publishes this router as a Tor `.onion` hidden service using an already-bootstrapped
    /// [`TorClient`], and serves requests arriving over it, blocking until the service stops.
    ///
    /// Only rendezvous requests targeting virtual port 80 are accepted (the port every `.onion`
    /// HTTP client expects); anything else has its circuit shut down immediately. Requests are
    /// dispatched through the same handling pipeline as [`serve_http`](Server::serve_http) —
    /// HTTP/1.1, plus h2c with the `http2` feature — one Tokio task per stream.
    ///
    /// Since `client` is already bootstrapped, arti has already constructed its internal
    /// relay/channel TLS provider from whatever `rustls::crypto::CryptoProvider` was installed
    /// process-wide *before this call* — install one yourself (e.g.
    /// `server.effective_tls_policy()`, or simply `TlsPolicy::new().install_as_process_default()`,
    /// both requiring this crate's `tls` feature) before bootstrapping `client` if that matters
    /// to you; it's too late to affect `client` by the time this function runs.
    /// [`serve_tor`](Server::serve_tor) does this for you because it owns the bootstrap.
    ///
    /// # Errors
    /// Returns an error if `nickname` is not a valid [`HsNickname`](tor_hsservice::HsNickname),
    /// or the onion service fails to launch (for example, if onion services are disabled in
    /// `client`'s config).
    pub async fn serve_tor_with_client<R>(
        self,
        client: &TorClient<R>,
        nickname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        R: Runtime,
    {
        crate::server::enforce_fips_compliance()?;

        let hs_nickname = parse_nickname(nickname)?;
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname(hs_nickname)
            .build()?;

        let Some((service, request_stream)) = client.launch_onion_service(svc_cfg)? else {
            return Err("onion services are disabled in this TorClient's config".into());
        };

        if let Some(addr) = service.onion_address() {
            crate::telemetry_info!(
                "[tor] onion service published at {}",
                addr.display_unredacted()
            );
        }

        wait_until_reachable(&service).await;

        serve_plaintext_onion_streams(Arc::new(self), request_stream).await;

        drop(service);
        Ok(())
    }

    /// Publishes this router as a Tor `.onion` hidden service according to `config`
    /// (state/cache directories, vanguards) and serves requests arriving over it, blocking
    /// until the service stops. Bootstraps a fresh [`TorClient`] — see the bootstrap-time note
    /// on [`serve_tor`](Server::serve_tor); prefer [`serve_onion_with_client`](Server::serve_onion_with_client)
    /// to reuse one across services.
    ///
    /// # Errors
    /// Returns an error if the Tor client fails to bootstrap, `config.nickname` is not a valid
    /// [`HsNickname`](tor_hsservice::HsNickname), or the onion service fails to launch.
    pub async fn serve_onion(
        self,
        config: OnionConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = TorClientConfigBuilder::default();

        if let Some(state_dir) = &config.state_dir {
            builder
                .storage()
                .state_dir(CfgPath::new_literal(state_dir.clone()));
        }
        if let Some(cache_dir) = &config.cache_dir {
            builder
                .storage()
                .cache_dir(CfgPath::new_literal(cache_dir.clone()));
        }
        if !config.vanguards {
            builder
                .vanguards()
                .mode(ExplicitOrAuto::Explicit(VanguardMode::Disabled));
        }

        // See the equivalent comment in `serve_tor` — must happen before bootstrapping.
        #[cfg(feature = "tls")]
        self.effective_tls_policy().install_as_process_default();
        let client_config = builder.build()?;
        let client = TorClient::create_bootstrapped(client_config).await?;
        self.serve_onion_with_client(&client, config).await
    }

    /// Publishes this router as a Tor `.onion` hidden service according to `config`, using an
    /// already-bootstrapped [`TorClient`], and serves requests arriving over it, blocking until
    /// the service stops.
    ///
    /// Dispatch depends on `config` and on which features are compiled in: virtual port 80
    /// serves plaintext HTTP unless [`redirect_http`](OnionConfig::redirect_http) is enabled
    /// (in which case it issues a `308` to the `https://` equivalent) — both only possible with
    /// the `tls` feature enabled; virtual port 443 terminates TLS — self-signed by default with
    /// `cert-gen`, or a caller-supplied config via [`tls_config`](OnionConfig::tls_config) with
    /// just `tls` — and is only listened on if the `tls` feature is enabled and
    /// [`no_tls`](OnionConfig::no_tls) wasn't called. Without the `tls` feature at all, this
    /// behaves exactly like [`serve_tor_with_client`](Server::serve_tor_with_client): plaintext
    /// on virtual port 80 only. Anything else has its circuit shut down immediately.
    ///
    /// Since `client` is already bootstrapped, install a `CryptoProvider` process-wide
    /// yourself *before* bootstrapping it if you want arti's relay/channel TLS to share this
    /// server's policy — see the equivalent note on
    /// [`serve_tor_with_client`](Server::serve_tor_with_client). The self-signed certificate on
    /// virtual port 443 always uses this server's [`TlsPolicy`](crate::tls::TlsPolicy)
    /// (see [`Server::tls_policy`]), regardless of what's installed process-wide.
    ///
    /// # Errors
    /// Returns an error if `config.nickname` is not a valid
    /// [`HsNickname`](tor_hsservice::HsNickname), the onion service fails to launch, or (when
    /// TLS is enabled) the TLS configuration is invalid.
    pub async fn serve_onion_with_client<R>(
        self,
        client: &TorClient<R>,
        config: OnionConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        R: Runtime,
    {
        crate::server::enforce_fips_compliance()?;
        #[cfg(all(feature = "tls", feature = "fips"))]
        if let AnonTls::Custom(server_config) = &config.tls {
            #[cfg(feature = "cnsa")]
            {
                let _ = server_config;
                return Err("CNSA mode rejects caller-supplied onion TLS configurations".into());
            }
            #[cfg(not(feature = "cnsa"))]
            crate::server::assert_fips_server_config(server_config)?;
        }

        let hs_nickname = parse_nickname(&config.nickname)?;
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname(hs_nickname)
            .build()?;

        let Some((service, request_stream)) = client.launch_onion_service(svc_cfg)? else {
            return Err("onion services are disabled in this TorClient's config".into());
        };

        let onion_host = service
            .onion_address()
            .map(|addr| addr.display_unredacted().to_string());
        crate::telemetry_info!(
            "[tor] onion service published at {}; vanguards={}, tls={}",
            onion_host.as_deref().unwrap_or("<pending>"),
            if config.vanguards { "on" } else { "off" },
            if config.tls_enabled() { "on" } else { "off" },
        );

        wait_until_reachable(&service).await;

        if let Some(on_ready) = config.on_ready
            && let Some(host) = &onion_host
        {
            on_ready(host);
        }

        #[cfg(feature = "tls")]
        require_onion_host_for_redirect(config.redirect_http, onion_host.is_some())?;
        #[cfg(feature = "tls")]
        {
            let tls_acceptor = self.build_onion_tls_acceptor(&config.tls, onion_host.as_deref())?;
            let onion_host: Arc<str> = Arc::from(onion_host.unwrap_or_default());
            let redirect_http = config.redirect_http;

            let state = Arc::new(self);
            let limit = state.connection_limit.clone();
            let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
            tokio::pin!(stream_requests);

            while let Some(permit) = limit.acquire().await {
                let Some(stream_request) = stream_requests.next().await else {
                    break;
                };
                let state = state.clone();
                let tls_acceptor = tls_acceptor.clone();
                let onion_host = onion_host.clone();
                ConnectionLimit::serve(permit, async move {
                    if let Err(e) = handle_onion_stream(
                        state,
                        stream_request,
                        tls_acceptor,
                        redirect_http,
                        onion_host,
                    )
                    .await
                    {
                        crate::telemetry_debug!("[tor] connection error: {e}");
                    }
                });
            }

            drop(service);
            Ok(())
        }

        // No `tls` feature compiled in at all: `config.tls` can only ever be `AnonTls::None`
        // (the only variant that exists in this build), so this is exactly
        // `serve_tor_with_client`'s plaintext-only dispatch.
        #[cfg(not(feature = "tls"))]
        {
            serve_plaintext_onion_streams(Arc::new(self), request_stream).await;

            drop(service);
            Ok(())
        }
    }

    /// Builds the TLS acceptor (if any) for [`serve_onion_with_client`](Self::serve_onion_with_client),
    /// per `config.tls`. `onion_host` is only consulted for [`AnonTls::SelfSigned`], to name the
    /// generated certificate.
    #[cfg(feature = "tls")]
    fn build_onion_tls_acceptor(
        &self,
        tls: &AnonTls,
        onion_host: Option<&str>,
    ) -> Result<Option<TlsAcceptor>, Box<dyn std::error::Error + Send + Sync>> {
        // Only the `SelfSigned` arm below names a certificate, and that arm needs `cert-gen`.
        #[cfg(not(feature = "cert-gen"))]
        let _ = onion_host;
        match tls {
            AnonTls::None => Ok(None),
            #[cfg(feature = "cert-gen")]
            AnonTls::SelfSigned => {
                let domain = onion_host.unwrap_or("onion-service.invalid").to_string();
                let cert = crate::tls::generate_self_signed_cert(vec![domain])?;
                // Shares this server's crypto/TLS policy (see `Server::tls_policy`) rather than
                // stock rustls defaults, so a non-default/FIPS/custom provider set for clearnet
                // applies here too.
                let server_config = self
                    .effective_tls_policy()
                    .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())?;
                Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
            }
            AnonTls::Custom(server_config) => Ok(Some(TlsAcceptor::from(server_config.clone()))),
        }
    }
}

/// `redirect_http` builds every plaintext response's `Location` from the published onion
/// host, so an unknown host at this point would silently redirect every request to
/// `https:///...` (a malformed URL) for the service's entire lifetime instead of failing
/// loudly once at startup. Requires the `tls` feature (the only build where `redirect_http`
/// can be `true` at all).
#[cfg(feature = "tls")]
fn require_onion_host_for_redirect(
    redirect_http: bool,
    has_onion_host: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if redirect_http && !has_onion_host {
        return Err(
            "onion address unavailable after reaching the network — cannot enable \
                     `redirect_http` without a known .onion host"
                .into(),
        );
    }
    Ok(())
}

/// Accepts a rendezvous stream, bounded in time.
///
/// `StreamRequest::accept` writes a CONNECTED cell onto the circuit, and a peer that simply
/// stops reading can hold that write open by leaving the circuit's flow-control window shut.
/// This runs while holding one of `max_connections` permits, so an unbounded await here lets
/// a peer pin the whole accept budget without ever speaking HTTP — the point at which every
/// other timeout in this crate would have applied.
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

/// Awaits `service`'s status stream until it reports full reachability. This tracks real Tor
/// network activity (introduction points built, descriptor accepted by `HsDirs`) with no built-in
/// timeout, so it can legitimately take minutes on a slow or first-run bootstrap — every state
/// transition is logged so that wait doesn't look hung.
async fn wait_until_reachable(service: &tor_hsservice::RunningOnionService) {
    let mut status_events = service.status_events();
    let mut last_state = None;
    loop {
        let Some(status) = status_events.next().await else {
            crate::telemetry_warn!(
                "[tor] onion service status stream ended before reporting full reachability"
            );
            return;
        };
        let state = status.state();
        if last_state != Some(state) {
            crate::telemetry_info!("[tor] onion service status: {state:?}");
            last_state = Some(state);
        }
        if state.is_fully_reachable() {
            break;
        }
    }
    crate::telemetry_info!("[tor] onion service is fully reachable");
}

/// What to do with an incoming onion-service rendezvous request, given the virtual port it
/// targeted and the service's current TLS/redirect configuration. Kept as a pure function
/// (see the `tests` module below) independent of arti's stream types so the dispatch rules can
/// be unit-tested without a live Tor connection.
///
/// `Redirect`/`ServeTls` only exist when the `tls` feature is enabled — without it, an onion
/// service can only ever be plaintext, so [`route_onion_request`] never has a reason to produce
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnionAction {
    /// Shut the circuit down — not a port this service answers on.
    Reject,
    /// Serve the app directly over plaintext HTTP.
    ServePlaintext,
    /// Issue a `308 Permanent Redirect` to the `https://` equivalent. Requires the `tls`
    /// feature.
    #[cfg(feature = "tls")]
    Redirect,
    /// Perform a TLS handshake, then serve the app over it. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    ServeTls,
}

#[cfg_attr(not(feature = "tls"), allow(unused_variables))]
const fn route_onion_request(port: u16, tls_enabled: bool, redirect_http: bool) -> OnionAction {
    match port {
        #[cfg(feature = "tls")]
        ONION_HTTP_PORT if tls_enabled && redirect_http => OnionAction::Redirect,
        ONION_HTTP_PORT => OnionAction::ServePlaintext,
        #[cfg(feature = "tls")]
        ONION_HTTPS_PORT if tls_enabled => OnionAction::ServeTls,
        _ => OnionAction::Reject,
    }
}

/// Builds the `Location` header value for a plaintext→TLS onion redirect. Requires the `tls`
/// feature.
#[cfg(feature = "tls")]
fn redirect_location(onion_host: &str, path_and_query: &str) -> String {
    format!("https://{onion_host}{path_and_query}")
}

/// Serves plaintext HTTP over every rendezvous stream the service receives, bounded by the
/// server's `max_connections`, until the stream of requests ends.
///
/// Shared by [`serve_tor_with_client`](Server::serve_tor_with_client) and — in builds without
/// the `tls` feature, where `AnonTls::None` is the only variant that exists — by
/// [`serve_onion_with_client`](Server::serve_onion_with_client).
async fn serve_plaintext_onion_streams<S, R>(state: Arc<Server<S>>, request_stream: R)
where
    S: Clone + Send + Sync + 'static,
    R: futures_util::Stream<Item = tor_hsservice::RendRequest> + Send,
{
    let limit = state.connection_limit.clone();
    let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
    tokio::pin!(stream_requests);

    while let Some(permit) = limit.acquire().await {
        let Some(stream_request) = stream_requests.next().await else {
            break;
        };
        let state = state.clone();
        ConnectionLimit::serve(permit, async move {
            if let Err(e) = handle_plaintext_only_stream(state, stream_request).await {
                crate::telemetry_debug!("[tor] connection error: {e}");
            }
        });
    }
}

/// Handles a single rendezvous stream for [`Server::serve_tor_with_client`] — plaintext HTTP on
/// virtual port 80 only, everything else rejected.
async fn handle_plaintext_only_stream<S>(
    state: Arc<Server<S>>,
    stream_request: StreamRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    let IncomingStreamRequest::Begin(begin) = stream_request.request() else {
        stream_request.shutdown_circuit()?;
        return Ok(());
    };

    if route_onion_request(begin.port(), false, false) != OnionAction::ServePlaintext {
        stream_request.shutdown_circuit()?;
        return Ok(());
    }

    let onion_stream = accept_onion_stream(stream_request).await?;
    let svc = hyper::service::service_fn(move |req| {
        hyper_handler(state.clone(), req, ONION_PEER_ADDR, false)
    });
    serve_connection(onion_stream, svc).await
}

/// Handles a single rendezvous stream for [`Server::serve_onion_with_client`], dispatching per
/// [`route_onion_request`]. Requires the `tls` feature (see [`OnionAction`]'s docs for why the
/// non-TLS case never needs this — it reuses [`handle_plaintext_only_stream`] instead).
#[cfg(feature = "tls")]
async fn handle_onion_stream<S>(
    state: Arc<Server<S>>,
    stream_request: StreamRequest,
    tls_acceptor: Option<TlsAcceptor>,
    redirect_http: bool,
    onion_host: Arc<str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    let IncomingStreamRequest::Begin(begin) = stream_request.request() else {
        stream_request.shutdown_circuit()?;
        return Ok(());
    };

    match route_onion_request(begin.port(), tls_acceptor.is_some(), redirect_http) {
        OnionAction::Reject => {
            stream_request.shutdown_circuit()?;
            Ok(())
        }
        OnionAction::ServePlaintext => {
            let onion_stream = accept_onion_stream(stream_request).await?;
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, ONION_PEER_ADDR, false)
            });
            serve_connection(onion_stream, svc).await
        }
        OnionAction::Redirect => {
            let onion_stream = accept_onion_stream(stream_request).await?;
            let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let onion_host = onion_host.clone();
                let state = state.clone();
                async move {
                    let mut response = redirect_response(&req, &onion_host);
                    state
                        .security_policy
                        .finalize_response(&mut response, false);
                    Ok::<_, std::io::Error>(response)
                }
            });
            serve_connection(onion_stream, svc).await
        }
        OnionAction::ServeTls => {
            let Some(acceptor) = tls_acceptor else {
                stream_request.shutdown_circuit()?;
                return Ok(());
            };
            let onion_stream = accept_onion_stream(stream_request).await?;
            let _handshake_permit = state
                .tls_handshake_limit
                .clone()
                .try_acquire_owned()
                .map_err(|_| "TLS handshake concurrency limit reached")?;
            let tls_stream = tokio::time::timeout(
                crate::server::TLS_HANDSHAKE_TIMEOUT,
                acceptor.accept(onion_stream),
            )
            .await
            .map_err(|_| "TLS handshake timed out")??;
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, ONION_PEER_ADDR, true)
            });
            serve_connection(tls_stream, svc).await
        }
    }
}

/// Builds the `308 Permanent Redirect` response for a plaintext request when
/// [`OnionConfig::redirect_http`] is enabled. Requires the `tls` feature.
#[cfg(feature = "tls")]
fn redirect_response(req: &Request<hyper::body::Incoming>, onion_host: &str) -> Response<Body> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let location = redirect_location(onion_host, path_and_query);
    Response::builder()
        .status(308) // preserves the HTTP method, unlike 301/302
        .header("location", location)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "tls")]
    use super::redirect_location;
    #[cfg(feature = "tls")]
    use super::require_onion_host_for_redirect;
    use super::{OnionAction, route_onion_request};

    #[test]
    fn plaintext_serves_port_80_and_rejects_everything_else() {
        assert_eq!(
            route_onion_request(80, false, false),
            OnionAction::ServePlaintext
        );
        assert_eq!(route_onion_request(443, false, false), OnionAction::Reject);
        assert_eq!(route_onion_request(22, false, false), OnionAction::Reject);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_dual_stack_serves_both_ports_without_redirect() {
        assert_eq!(
            route_onion_request(80, true, false),
            OnionAction::ServePlaintext
        );
        assert_eq!(route_onion_request(443, true, false), OnionAction::ServeTls);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_with_redirect_forces_port_80_to_redirect() {
        assert_eq!(route_onion_request(80, true, true), OnionAction::Redirect);
        assert_eq!(route_onion_request(443, true, true), OnionAction::ServeTls);
    }

    #[test]
    fn redirect_only_applies_when_tls_is_enabled() {
        // Requesting a redirect without TLS enabled is meaningless — plaintext still wins.
        assert_eq!(
            route_onion_request(80, false, true),
            OnionAction::ServePlaintext
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn require_onion_host_for_redirect_rejects_a_missing_host_only_when_redirecting() {
        assert!(require_onion_host_for_redirect(true, false).is_err());
        assert!(require_onion_host_for_redirect(true, true).is_ok());
        assert!(require_onion_host_for_redirect(false, false).is_ok());
        assert!(require_onion_host_for_redirect(false, true).is_ok());
    }

    #[test]
    fn unknown_ports_are_always_rejected() {
        assert_eq!(route_onion_request(8080, false, false), OnionAction::Reject);
        assert_eq!(route_onion_request(8080, true, true), OnionAction::Reject);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn redirect_location_builds_the_https_equivalent_url() {
        assert_eq!(
            redirect_location("abcd1234.onion", "/foo?x=1"),
            "https://abcd1234.onion/foo?x=1"
        );
        assert_eq!(
            redirect_location("abcd1234.onion", "/"),
            "https://abcd1234.onion/"
        );
    }

    #[cfg(all(feature = "tls", feature = "http1"))]
    #[tokio::test]
    async fn redirect_response_builds_a_308_to_the_https_equivalent() {
        use hyper::Request;
        use hyper::service::service_fn;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_io, server_io) = tokio::io::duplex(8 * 1024);
        let onion_host: std::sync::Arc<str> = std::sync::Arc::from("abcd1234.onion");

        let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
            let onion_host = onion_host.clone();
            async move { Ok::<_, std::io::Error>(super::redirect_response(&req, &onion_host)) }
        });
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(server_io), svc)
                .await
        });

        client_io
            .write_all(b"GET /foo?x=1 HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");

        let mut buf = Vec::new();
        client_io
            .read_to_end(&mut buf)
            .await
            .expect("read response");
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("308"), "unexpected response: {response}");
        assert!(
            response.contains("location: https://abcd1234.onion/foo?x=1"),
            "unexpected response: {response}"
        );

        server
            .await
            .expect("server task join")
            .expect("serve_connection ok");
    }
}
