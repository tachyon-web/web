//! `Server::serve_i2p*` entry points and per-stream dispatch.

use super::I2pConfig;
use super::config::validate_nickname;
use crate::server::Server;
use crate::server::accept::ConnectionLimit;
#[cfg(feature = "tls")]
use crate::server::anon_tls::AnonTls;
use crate::server::conn::serve_connection;
use crate::server::http::hyper_handler;
use std::sync::Arc;
use tachyon_i2p::I2pRouter;
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;

impl<S> Server<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Publishes this router as an I2P eepsite and serves requests arriving over it, blocking
    /// indefinitely — the accept loop retries forever on error and has no graceful-stop
    /// mechanism today; abort the surrounding task (e.g. via `JoinHandle::abort`) to end it.
    ///
    /// Starts a fresh [`I2pRouter`] and a persistent destination under
    /// `./.tachyon-i2p/<nickname>.keys` — plaintext only, no other configuration. For a custom
    /// data directory, TLS, or an `on_ready` hook, use [`serve_i2p_config`](Self::serve_i2p_config)
    /// instead.
    ///
    /// **See the [module docs](crate::server::i2p) for why this feature does not honor
    /// `tachyon-web`'s `forbid(unsafe_code)` guarantee.**
    ///
    /// # Errors
    /// Returns an error if the I2P router fails to start (most commonly:
    /// [`tachyon_i2p::I2pError::AlreadyRunning`] if another [`I2pRouter`] is already running in
    /// this process — only one may exist per process) or the destination fails to load/create.
    pub async fn serve_i2p(
        self,
        nickname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.serve_i2p_config(I2pConfig::new(nickname)).await
    }

    /// Publishes this router as an I2P eepsite according to `config`, starting a fresh
    /// [`I2pRouter`], and serves requests arriving over it, blocking indefinitely — the accept
    /// loop retries forever on error and has no graceful-stop mechanism today; abort the
    /// surrounding task (e.g. via `JoinHandle::abort`) to end it.
    ///
    /// **See the [module docs](crate::server::i2p) for why this feature does not honor
    /// `tachyon-web`'s `forbid(unsafe_code)` guarantee.**
    ///
    /// # Errors
    /// Returns an error if the I2P router fails to start (most commonly:
    /// [`tachyon_i2p::I2pError::AlreadyRunning`] if another [`I2pRouter`] is already running in
    /// this process — only one may exist per process; use
    /// [`serve_i2p_config_with_router`](Self::serve_i2p_config_with_router) to reuse one instead),
    /// the destination fails to load/create, or (when TLS is enabled) the TLS configuration is
    /// invalid.
    pub async fn serve_i2p_config(
        self,
        config: I2pConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        validate_nickname(&config.nickname)?;
        let router = I2pRouter::start(config.nickname.clone()).await?;
        self.serve_i2p_config_with_router(&router, config).await
    }

    /// Publishes this router as an I2P eepsite according to `config`, using an already-started
    /// [`I2pRouter`] (only one may run per process — this is how a second eepsite, or a second
    /// destination used purely as an outbound client, shares the same router instead of hitting
    /// [`tachyon_i2p::I2pError::AlreadyRunning`]), and serves requests arriving over it, blocking
    /// indefinitely — the accept loop retries forever on error and has no graceful-stop
    /// mechanism today; abort the surrounding task (e.g. via `JoinHandle::abort`) to end it.
    ///
    /// **See the [module docs](crate::server::i2p) for why this feature does not honor
    /// `tachyon-web`'s `forbid(unsafe_code)` guarantee.**
    ///
    /// The self-signed certificate (when [`I2pConfig::self_signed_tls`] is used) shares this
    /// server's crypto/TLS policy — see [`Server::tls_policy`].
    ///
    /// # Errors
    /// Returns an error if `nickname` contains path separators or `..` (it's used verbatim to
    /// build the destination keys file path, as `<data_dir>/<nickname>.keys`), the destination
    /// fails to load/create, or (when TLS is enabled) the TLS configuration is invalid.
    pub async fn serve_i2p_config_with_router(
        self,
        router: &I2pRouter,
        config: I2pConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        crate::server::enforce_fips_compliance()?;
        #[cfg(all(feature = "tls", feature = "fips"))]
        if let AnonTls::Custom(server_config) = &config.tls {
            #[cfg(feature = "cnsa")]
            {
                let _ = server_config;
                return Err("CNSA mode rejects caller-supplied I2P TLS configurations".into());
            }
            #[cfg(not(feature = "cnsa"))]
            crate::server::assert_fips_server_config(server_config)?;
        }
        validate_nickname(&config.nickname)?;

        let keys_path = config.keys_path();
        let is_public = true;
        let mut destination = router
            .destination_from_keys_file(
                keys_path,
                is_public,
                config.sig_type,
                &config.encryption_types,
            )
            .await?;

        let address = destination.b32_address().to_string();
        crate::telemetry_info!("[i2p] eepsite published at {address}");
        if let Some(on_ready) = config.on_ready {
            on_ready(&address);
        }

        // Without the `tls` feature `config.tls` can only ever be `AnonTls::None` (the only
        // variant that exists in that build), so there is no acceptor to build and the loop
        // below is unconditionally plaintext.
        #[cfg(feature = "tls")]
        let tls_acceptor = match &config.tls {
            AnonTls::None => None,
            #[cfg(feature = "cert-gen")]
            AnonTls::SelfSigned => {
                let cert = crate::tls::generate_self_signed_cert(vec![address.clone()])?;
                let server_config = self
                    .effective_tls_policy()
                    .server_config_from_pem(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())?;
                Some(TlsAcceptor::from(Arc::new(server_config)))
            }
            AnonTls::Custom(server_config) => Some(TlsAcceptor::from(
                self.finalize_tls_config((**server_config).clone()),
            )),
        };

        let state = Arc::new(self);
        let limit = state.connection_limit.clone();
        while let Some(permit) = limit.acquire().await {
            let stream = accept_i2p_forever(&mut destination).await;
            let state = state.clone();
            #[cfg(feature = "tls")]
            let tls_acceptor = tls_acceptor.clone();
            ConnectionLimit::serve(permit, async move {
                #[cfg(feature = "tls")]
                let result = handle_i2p_stream(state, stream, tls_acceptor).await;
                #[cfg(not(feature = "tls"))]
                let result = handle_i2p_stream_plaintext(state, stream).await;
                if let Err(e) = result {
                    crate::telemetry_debug!("[i2p] connection error: {e}");
                }
            });
        }
        Ok(())
    }
}

/// Accepts the next I2P stream, retrying after recoverable errors.
///
/// Mirrors [`crate::server::http::accept_forever`]: a failed accept is logged and retried
/// after a short back-off rather than ending the eepsite, so the caller's loop only ever
/// stops when the connection limiter is closed.
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

/// Handles a single accepted I2P stream when the `tls` feature is off: plaintext HTTP dispatch
/// only, sharing the same [`serve_connection`] helper (and thus HTTP/1.1-vs-HTTP/2 negotiation
/// logic) `tor`'s serve module uses.
#[cfg(not(feature = "tls"))]
async fn handle_i2p_stream_plaintext<S>(
    state: Arc<Server<S>>,
    stream: tachyon_i2p::I2pStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    let http2 = state.security_policy.allows_h2c();
    let svc = hyper::service::service_fn(move |req| hyper_handler(state.clone(), req, None, false));
    serve_connection(stream, svc, http2).await
}

/// Handles a single accepted I2P stream: TLS (if configured) then HTTP dispatch, sharing the
/// same [`serve_connection`] helper (and thus HTTP/1.1-vs-HTTP/2 negotiation logic) `tor`'s
/// serve module uses. Requires the `tls` feature (see [`handle_i2p_stream_plaintext`] for the
/// non-TLS build).
#[cfg(feature = "tls")]
async fn handle_i2p_stream<S>(
    state: Arc<Server<S>>,
    stream: tachyon_i2p::I2pStream,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Clone + Send + Sync + 'static,
{
    match tls_acceptor {
        None => {
            let http2 = state.security_policy.allows_h2c();
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, None, false)
            });
            serve_connection(stream, svc, http2).await
        }
        Some(acceptor) => {
            let handshake_permit = state
                .tls_handshake_limit
                .clone()
                .try_acquire_owned()
                .map_err(|_| "TLS handshake concurrency limit reached")?;
            let tls_stream = tokio::time::timeout(
                crate::server::TLS_HANDSHAKE_TIMEOUT,
                acceptor.accept(stream),
            )
            .await
            .map_err(|_| "TLS handshake timed out")??;
            drop(handshake_permit);
            let svc = hyper::service::service_fn(move |req| {
                hyper_handler(state.clone(), req, None, true)
            });
            serve_connection(tls_stream, svc, true).await
        }
    }
}
