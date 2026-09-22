//! The connection-concurrency limit shared by every transport.
//!
//! Plain TCP, TLS, the port-80 redirect listener, Tor and I2P all bound in-flight connections
//! the same way, and each used to open-code it: an `Arc<Semaphore>`, an `acquire_owned()`
//! before each accept, and a hand-written `drop(permit)` on every path out of the connection
//! task. `serve_https` alone had four such paths — a TLS handshake error, a handshake timeout,
//! the HTTP/2 branch and the HTTP/1.1 branch — and missing one leaks a permit for the lifetime
//! of the process.
//!
//! Here the permit is moved into the connection task and released when that task ends, so
//! there is no per-transport accounting left to get wrong.

use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Applies the per-connection socket tuning every TCP accept path shares.
///
/// Both paths go through here — [`Server`](crate::server::Server)'s accept loop and the
/// free-standing [`axum::serve`] — so the two can't drift apart on socket options the way they
/// previously did (`axum::serve` left Nagle on, adding up to a round of delayed-ACK latency to
/// every small response it wrote).
pub(super) fn tune_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Whether an accept error is an ordinary vanished-peer case rather than a listener fault.
///
/// A peer that aborts between SYN and `accept` makes the call fail; that is routine traffic,
/// not an operational problem. Logging it at `error!` would let any remote peer drive
/// unbounded log volume, which is its own denial of service — on disk, on a log pipeline's
/// bill, and on an operator's ability to spot a real event in the noise.
pub(super) fn is_connection_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

/// Bounds how many connections a transport serves concurrently.
///
/// A limiter may carry a *share* on top of the pool: a sub-budget that one transport alone
/// draws from, while still taking a permit from the pool every other transport uses. The
/// port-80 redirect listener runs on one (see
/// [`Server::redirect_connection_share`](crate::server::Server::redirect_connection_share)),
/// so cheap plaintext connections can't hold permits the TLS listener needs. Because a shared
/// connection holds *both* permits, the share caps that listener without raising the
/// process-wide ceiling.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionLimit {
    pool: Arc<Semaphore>,
    share: Option<Arc<Semaphore>>,
}

/// The permits one connection holds for its lifetime — the pool's, plus its transport's share
/// of the pool where one applies.
#[derive(Debug)]
pub(super) struct ConnectionPermit {
    _pool: OwnedSemaphorePermit,
    _share: Option<OwnedSemaphorePermit>,
}

impl ConnectionLimit {
    /// A limiter allowing `max_conns` connections in flight at once.
    pub(super) fn new(max_conns: usize) -> Self {
        Self {
            pool: Arc::new(Semaphore::new(max_conns)),
            share: None,
        }
    }

    /// The same pool, additionally capped at `permits` connections for the one transport that
    /// uses the returned limiter.
    #[cfg(any(feature = "cert-gen", feature = "lets-encrypt"))]
    pub(super) fn with_share(&self, permits: usize) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            share: Some(Arc::new(Semaphore::new(permits))),
        }
    }

    /// Waits for capacity, yielding the permits to hold for one connection's lifetime.
    ///
    /// Acquiring *before* accepting is deliberate: a server at capacity stops taking
    /// connections off the listen backlog rather than accepting them and immediately
    /// queueing, so the backpressure is visible to the peer.
    ///
    /// The share is taken first. The other order would have a listener sitting on a pool
    /// permit — one every transport competes for — while it waited for its own sub-budget,
    /// which is the starvation this exists to prevent.
    ///
    /// `None` once either limiter is closed, which is how a transport is told to stop.
    pub(super) async fn acquire(&self) -> Option<ConnectionPermit> {
        let share = match &self.share {
            Some(share) => Some(Arc::clone(share).acquire_owned().await.ok()?),
            None => None,
        };
        Some(ConnectionPermit {
            _pool: Arc::clone(&self.pool).acquire_owned().await.ok()?,
            _share: share,
        })
    }

    /// Serves one connection on its own task, holding `permit` until it finishes.
    pub(super) fn serve(permit: ConnectionPermit, conn: impl Future<Output = ()> + Send + 'static) {
        super::http::spawn_connection(async move {
            conn.await;
            drop(permit);
        });
    }
}

#[cfg(all(test, any(feature = "cert-gen", feature = "lets-encrypt")))]
mod tests {
    use super::ConnectionLimit;
    use std::time::Duration;

    /// The starvation guard: a share-limited listener stops at its own sub-budget while the
    /// rest of the pool stays available to everything else. Before shares existed, port 80 and
    /// port 443 drew on one semaphore and a flood of cheap redirects could hold all of it.
    #[tokio::test(start_paused = true)]
    async fn a_share_limited_listener_cannot_drain_the_pool_it_draws_from() {
        let pool = ConnectionLimit::new(10);
        let redirect = pool.with_share(2);

        let _first = redirect.acquire().await.expect("first share permit");
        let _second = redirect.acquire().await.expect("second share permit");

        assert!(
            tokio::time::timeout(Duration::from_secs(1), redirect.acquire())
                .await
                .is_err(),
            "the shared listener must stop at its share even with the pool far from full"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), pool.acquire())
                .await
                .is_ok(),
            "the pool's remaining permits must stay reachable by every other transport"
        );
    }

    /// A shared connection holds a pool permit too, so the share caps one listener rather than
    /// handing the process a second budget on top of `max_connections`.
    #[tokio::test(start_paused = true)]
    async fn a_share_does_not_widen_the_pool() {
        let pool = ConnectionLimit::new(2);
        let redirect = pool.with_share(2);

        let _first = redirect.acquire().await.expect("first share permit");
        let _second = redirect.acquire().await.expect("second share permit");

        assert!(
            tokio::time::timeout(Duration::from_secs(1), pool.acquire())
                .await
                .is_err(),
            "two shared connections must have consumed the whole two-permit pool"
        );
    }
}
