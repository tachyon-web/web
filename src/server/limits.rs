//! [`Limits`]: the size and concurrency ceilings a [`Server`](crate::Server) enforces.

/// The size and concurrency ceilings a [`Server`](crate::Server) enforces, shared across every
/// transport it runs so adding listeners does not multiply them.
///
/// A plain value: set the fields you care about, in any order, and hand it to
/// [`Server::limits`](crate::Server::limits). A zero count is read as one, so a mistake cannot
/// stop the server accepting anything; `usize::MAX` is read as the largest count supported.
///
/// ```rust
/// use tachyon_web::Limits;
///
/// let limits = Limits::default()
///     .max_body_size(64 * 1024 * 1024)
///     .max_connections(1_024);
/// assert_eq!(limits.max_body_size, 64 * 1024 * 1024);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest request body, in bytes. Enforced on the wire *and* applied as the app's
    /// `DefaultBodyLimit`, so `Json`, `Bytes` and friends accept the same size. A route's own
    /// `DefaultBodyLimit` still overrides it downward. Default: 2 MiB.
    pub max_body_size: usize,
    /// Concurrent connections across every transport. Default: 4,096.
    pub max_connections: usize,
    /// Handlers running at once; excess requests get an immediate `503` rather than a queue.
    /// Default: 1,024.
    pub max_active_requests: usize,
    /// TLS handshakes in flight; excess connections are dropped before any asymmetric crypto.
    /// Default: 1,024.
    pub max_tls_handshakes: usize,
    /// HTTP/3 streams per QUIC connection. H3 bodies are buffered, so one connection can pin
    /// about `max_h3_streams × max_body_size`. Default: 32.
    pub max_h3_streams: usize,
    /// Percentage of `max_connections` the port-80 redirect listener may hold, so cheap
    /// plaintext connections cannot starve TLS. Never less than one connection. Default: 15.
    pub redirect_share: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_size: 2 * 1024 * 1024,
            max_connections: 4_096,
            max_active_requests: 1_024,
            max_tls_handshakes: 1_024,
            max_h3_streams: 32,
            redirect_share: 15,
        }
    }
}

impl Limits {
    /// Sets [`max_body_size`](Self::max_body_size).
    #[must_use]
    pub const fn max_body_size(mut self, bytes: usize) -> Self {
        self.max_body_size = bytes;
        self
    }

    /// Sets [`max_connections`](Self::max_connections).
    #[must_use]
    pub const fn max_connections(mut self, limit: usize) -> Self {
        self.max_connections = limit;
        self
    }

    /// Sets [`max_active_requests`](Self::max_active_requests).
    #[must_use]
    pub const fn max_active_requests(mut self, limit: usize) -> Self {
        self.max_active_requests = limit;
        self
    }

    /// Sets [`max_tls_handshakes`](Self::max_tls_handshakes).
    #[must_use]
    pub const fn max_tls_handshakes(mut self, limit: usize) -> Self {
        self.max_tls_handshakes = limit;
        self
    }

    /// Sets [`max_h3_streams`](Self::max_h3_streams).
    #[must_use]
    pub const fn max_h3_streams(mut self, limit: usize) -> Self {
        self.max_h3_streams = limit;
        self
    }

    /// Sets [`redirect_share`](Self::redirect_share), clamped to 100.
    #[must_use]
    pub const fn redirect_share(mut self, percent: u8) -> Self {
        self.redirect_share = if percent > 100 { 100 } else { percent };
        self
    }

    /// Every count raised to at least one and capped at what a semaphore (and a `u32`
    /// `acquire_many` drain) can hold, so `usize::MAX` means "as many as possible", not a panic.
    pub(crate) fn sanitized(self) -> Self {
        let max = tokio::sync::Semaphore::MAX_PERMITS
            .min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
        Self {
            max_connections: self.max_connections.clamp(1, max),
            max_active_requests: self.max_active_requests.clamp(1, max),
            max_tls_handshakes: self.max_tls_handshakes.clamp(1, max),
            max_h3_streams: self.max_h3_streams.clamp(1, max),
            redirect_share: self.redirect_share.min(100),
            ..self
        }
    }

    /// The redirect listener's slice of the pool, in connections: rounded down, floored at one.
    #[cfg(feature = "tls")]
    pub(crate) fn redirect_connections(self) -> usize {
        self.max_connections
            .saturating_mul(usize::from(self.redirect_share))
            .checked_div(100)
            .unwrap_or(0)
            .max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::Limits;

    #[test]
    fn counts_are_clamped_and_the_redirect_share_keeps_one_connection() {
        let limits = Limits::default()
            .max_connections(0)
            .max_active_requests(0)
            .max_tls_handshakes(0)
            .max_h3_streams(0)
            .redirect_share(0)
            .sanitized();
        assert_eq!(limits.max_connections, 1);
        assert_eq!(limits.max_active_requests, 1);
        assert_eq!(limits.max_tls_handshakes, 1);
        assert_eq!(limits.max_h3_streams, 1);
        #[cfg(feature = "tls")]
        assert_eq!(limits.redirect_connections(), 1);

        let connections = rand::random_range(100..100_000);
        let limits = Limits::default()
            .max_connections(connections)
            .redirect_share(200);
        assert_eq!(limits.redirect_share, 100);
        #[cfg(feature = "tls")]
        assert_eq!(limits.sanitized().redirect_connections(), connections);

        let limits = Limits::default()
            .max_connections(rand::random_range(usize::MAX / 2..=usize::MAX))
            .sanitized();
        assert!(limits.max_connections <= tokio::sync::Semaphore::MAX_PERMITS);
        assert!(u32::try_from(limits.max_connections).is_ok());
    }
}
