//! Fluent multi-transport server builder — see the [module docs](super#publishing-over-more-than-one-transport-at-once).
//!
//! [`MultiServer`] is the preferred way to publish one [`Router`](crate::routing::Router) over
//! more than one transport at once. It owns exactly the boilerplate a hand-rolled
//! `tokio::spawn` + `tokio::select!` around individual `serve_*` calls would otherwise require:
//! one task per configured transport, all driven concurrently, with the whole group torn down
//! as soon as any one of them finishes (success or error).

use super::Server;
use tokio::net::TcpListener;

/// One transport this [`MultiServer`] will drive, alongside its configuration.
enum Transport {
    Http(TcpListener),
    // Boxed because `rustls::ServerConfig` is ~280 bytes against the ~40 of the next-largest
    // variant, and `Vec<Transport>` pays the largest variant's size for *every* element — so
    // an unboxed config made a plain HTTP-only `MultiServer` seven times bigger than it needs
    // to be. Boxing costs one allocation per HTTPS transport, of which there are a handful at
    // startup and never any afterwards.
    #[cfg(feature = "tls")]
    Https(TcpListener, Box<rustls::ServerConfig>),
    #[cfg(feature = "http3")]
    H3(s2n_quic::Server),
    #[cfg(feature = "tor")]
    Onion(super::tor::OnionConfig),
    #[cfg(feature = "i2p")]
    I2p(super::i2p::I2pConfig),
}

/// Builds a group of transports to drive concurrently from one [`Server`] — see the
/// [module docs](crate::server#publishing-over-more-than-one-transport-at-once).
///
/// Constructed via [`Server::with_http`]/[`Server::with_https`]/[`Server::with_onion`]/
/// [`Server::with_i2p`]/[`Server::with_h3`], chained with more of the same to add further
/// transports, and finished with [`serve`](Self::serve).
#[must_use = "MultiServer does nothing until `.serve()` is called and awaited"]
pub struct MultiServer<S> {
    server: Server<S>,
    transports: Vec<Transport>,
}

impl<S> std::fmt::Debug for MultiServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiServer")
            .field("transports", &self.transports.len())
            .finish_non_exhaustive()
    }
}

impl<S> MultiServer<S>
where
    S: Clone + Send + Sync + 'static,
{
    pub(super) const fn new(server: Server<S>) -> Self {
        Self {
            server,
            transports: Vec::new(),
        }
    }

    /// Adds a plaintext clearnet HTTP transport bound to `listener` — see
    /// [`Server::serve_http`].
    pub fn with_http(mut self, listener: TcpListener) -> Self {
        self.transports.push(Transport::Http(listener));
        self
    }

    /// Adds a clearnet HTTPS transport bound to `listener`, terminated with `config` — see
    /// [`Server::serve_https_config`]. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    pub fn with_https(mut self, listener: TcpListener, config: rustls::ServerConfig) -> Self {
        self.transports
            .push(Transport::Https(listener, Box::new(config)));
        self
    }

    /// Adds an HTTP/3-over-QUIC transport — see [`Server::serve_h3`]. Requires the `http3`
    /// feature.
    #[cfg(feature = "http3")]
    pub fn with_h3(mut self, quic_server: s2n_quic::Server) -> Self {
        self.transports.push(Transport::H3(quic_server));
        self
    }

    /// Adds a Tor `.onion` hidden-service transport — see [`Server::serve_onion`]. Requires
    /// the `tor` feature.
    #[cfg(feature = "tor")]
    pub fn with_onion(mut self, config: super::tor::OnionConfig) -> Self {
        self.transports.push(Transport::Onion(config));
        self
    }

    /// Adds an I2P `.b32.i2p` eepsite transport — see [`Server::serve_i2p_config`]. Requires
    /// the `i2p` feature ([⚠️ breaks `forbid(unsafe_code)`](super::i2p)).
    #[cfg(feature = "i2p")]
    pub fn with_i2p(mut self, config: super::i2p::I2pConfig) -> Self {
        self.transports.push(Transport::I2p(config));
        self
    }

    /// Runs every configured transport concurrently, one Tokio task each, and blocks until the
    /// **first** one finishes — success or error — at which point every other transport task is
    /// aborted and that outcome is returned.
    ///
    /// Each transport is driven from an independent clone of this `MultiServer`'s underlying
    /// [`Server`] (cheap — [`Server`]'s settings are `Arc`/`Copy` under the hood), so
    /// [`Server::max_body_size`]/[`Server::max_connections`]/[`Server::tls_policy`]/
    /// [`Server::response_jitter`] apply identically across all of them.
    ///
    /// # Errors
    ///
    /// Returns an error if no transport was configured (call at least one `.with_*` method
    /// first), if any configured transport fails to start, or if it fails at any point while
    /// running.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.transports.is_empty() {
            return Err(
                "MultiServer::serve called with no transports configured — call at least one \
                 `.with_http`/`.with_https`/`.with_h3`/`.with_onion`/`.with_i2p` first"
                    .into(),
            );
        }

        let mut set = tokio::task::JoinSet::new();
        for transport in self.transports {
            let server = self.server.clone();
            match transport {
                Transport::Http(listener) => {
                    set.spawn(async move { server.serve_http(listener).await.map_err(Into::into) });
                }
                #[cfg(feature = "tls")]
                Transport::Https(listener, config) => {
                    set.spawn(async move {
                        server
                            .serve_https_config(listener, *config)
                            .await
                            .map_err(Into::into)
                    });
                }
                #[cfg(feature = "http3")]
                Transport::H3(quic_server) => {
                    set.spawn(
                        async move { server.serve_h3(quic_server).await.map_err(Into::into) },
                    );
                }
                #[cfg(feature = "tor")]
                Transport::Onion(config) => {
                    set.spawn(async move { server.serve_onion(config).await });
                }
                #[cfg(feature = "i2p")]
                Transport::I2p(config) => {
                    set.spawn(async move { server.serve_i2p_config(config).await });
                }
            }
        }

        let Some(result) = set.join_next().await else {
            return Err("MultiServer: no transport task was actually spawned".into());
        };
        set.abort_all();

        match result {
            Ok(outcome) => outcome,
            Err(join_err) => Err(Box::new(join_err)),
        }
    }
}
