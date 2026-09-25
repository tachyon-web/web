//! The single error type every fallible `tachyon_web` call returns.

use std::borrow::Cow;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Why a [`Server`](crate::Server) could not start or stopped running.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The configuration is contradictory or incomplete. Reported before anything is bound.
    Config(Cow<'static, str>),
    /// A listener could not be bound.
    Bind {
        /// The address that failed to bind.
        addr: String,
        /// The underlying OS error.
        source: std::io::Error,
    },
    /// Any other I/O failure: reading certificate files, the certificate store, the FIPS
    /// self-check.
    Io(std::io::Error),
    /// A certificate or key could not be generated, parsed, or matched to each other.
    Certificate(Cow<'static, str>),
    /// Tor or I2P failed to bootstrap or publish the service.
    Transport(BoxError),
}

impl Error {
    pub(crate) fn config(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Config(message.into())
    }

    #[cfg(feature = "tls")]
    pub(crate) fn certificate(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Certificate(message.into())
    }

    #[cfg(any(feature = "tor", feature = "i2p"))]
    pub(crate) fn transport(error: impl Into<BoxError>) -> Self {
        Self::Transport(error.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message) => write!(f, "invalid configuration: {message}"),
            Self::Bind { addr, source } => write!(f, "failed to bind {addr}: {source}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Certificate(message) => write!(f, "certificate error: {message}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            Self::Io(e) => Some(e),
            Self::Transport(e) => Some(e.as_ref()),
            Self::Config(_) | Self::Certificate(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use std::error::Error as _;

    #[test]
    fn errors_name_their_cause_and_keep_their_source() {
        let addr = format!("127.0.0.1:{}", rand::random::<u16>());
        let bind = Error::Bind {
            addr: addr.clone(),
            source: std::io::Error::from(std::io::ErrorKind::AddrInUse),
        };
        assert!(bind.to_string().contains(&addr));
        assert!(bind.source().is_some());

        let config = Error::config("no transports");
        assert!(config.to_string().contains("no transports"));
        assert!(config.source().is_none());
        assert!(
            Error::from(std::io::Error::other("disk"))
                .source()
                .is_some()
        );
    }
}
