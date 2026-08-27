//! Plumbing shared by the [`tor`](super::tor) and [`i2p`](super::i2p) anonymity-transport
//! modules. Both publish a [`Server`](super::Server) that terminates TLS the same three ways
//! (off, self-signed, or a caller-supplied config) and both offer an identical "call me once the
//! address is known" hook — that shared shape lives here once instead of being redefined nearly
//! verbatim in each module.

#[cfg(feature = "tls")]
use std::sync::Arc;

/// How (or whether) an anonymity-transport service terminates TLS.
///
/// Used by `OnionConfig`/`I2pConfig`'s `tls` field; each config type still owns its *meaning*
/// (e.g. whether `SelfSigned` is the default) and its own builder methods, since that varies
/// per transport.
#[derive(Clone)]
pub(super) enum AnonTls {
    /// Plaintext only.
    None,
    /// TLS using an ephemeral self-signed certificate, generated once the service's address is
    /// known. Requires the `cert-gen` feature.
    #[cfg(feature = "cert-gen")]
    SelfSigned,
    /// TLS using a caller-supplied config — e.g. the same `rustls::ServerConfig` used for a
    /// clearnet [`Server::serve_https_config`](crate::server::Server::serve_https_config)
    /// listener. Requires the `tls` feature.
    #[cfg(feature = "tls")]
    Custom(Arc<rustls::ServerConfig>),
}

impl std::fmt::Debug for AnonTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            #[cfg(feature = "cert-gen")]
            Self::SelfSigned => f.write_str("SelfSigned"),
            #[cfg(feature = "tls")]
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

/// Callback invoked once with a published anonymity-transport address (no scheme, e.g.
/// `"abcd...xyz.onion"`/`"abcd...xyz.b32.i2p"`) — see `OnionConfig::on_ready`/
/// `I2pConfig::on_ready`.
pub(super) type OnReadyHook = Box<dyn FnOnce(&str) + Send>;
