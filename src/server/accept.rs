//! The connection-concurrency limit shared by every transport.
//!
//! The permit is moved into the connection task and released when that task ends, so no
//! transport has to release it by hand on each of its exit paths.

use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Applies the per-connection socket tuning every TCP accept path shares.
pub(super) fn tune_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Whether an accept error is an ordinary vanished-peer case rather than a listener fault.
///
/// Routine and remote-triggerable, so it must not be logged at `error!`: any peer could drive
/// unbounded log volume.
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
/// A limiter may carry a *share*: a sub-budget one transport alone draws from, on top of the
/// pool every transport uses. The port-80 redirect listener runs on one (see
/// [`Server::redirect_connection_share`](crate::server::Server::redirect_connection_share)), so
/// cheap plaintext connections can't hold permits the TLS listener needs. A shared connection
/// holds *both* permits, so the share never raises the process-wide ceiling.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionLimit {
    pool: Arc<Semaphore>,
    share: Option<Arc<Semaphore>>,
}

/// The permits one connection holds for its lifetime.
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
    #[cfg(feature = "cert-gen")]
    pub(super) fn with_share(&self, permits: usize) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            share: Some(Arc::new(Semaphore::new(permits))),
        }
    }

    /// Waits for capacity, yielding the permits to hold for one connection's lifetime.
    ///
    /// Callers acquire after accepting, so an idle listener never reserves a pool permit
    /// another transport needs. The share is taken first for the same reason: waiting on it
    /// while holding a pool permit would starve everyone else.
    pub(super) async fn acquire(&self) -> ConnectionPermit {
        let share = match &self.share {
            Some(share) => Some(acquire(share).await),
            None => None,
        };
        ConnectionPermit {
            _pool: acquire(&self.pool).await,
            _share: share,
        }
    }

    /// Serves one connection on its own task, holding `permit` until it finishes.
    pub(super) fn serve(permit: ConnectionPermit, conn: impl Future<Output = ()> + Send + 'static) {
        drop(tokio::spawn(async move {
            conn.await;
            drop(permit);
        }));
    }
}

async fn acquire(semaphore: &Arc<Semaphore>) -> OwnedSemaphorePermit {
    match Arc::clone(semaphore).acquire_owned().await {
        Ok(permit) => permit,
        // Only a closed semaphore fails, and these are private and never closed.
        Err(_) => std::future::pending().await,
    }
}

#[cfg(all(test, feature = "cert-gen"))]
mod tests {
    use super::ConnectionLimit;
    use std::time::Duration;

    /// The starvation guard: a share-limited listener stops at its own sub-budget while the
    /// rest of the pool stays available to everything else.
    #[tokio::test(start_paused = true)]
    async fn a_share_limited_listener_cannot_drain_the_pool_it_draws_from() {
        let pool = ConnectionLimit::new(10);
        let redirect = pool.with_share(2);

        let _first = redirect.acquire().await;
        let _second = redirect.acquire().await;

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

        let _first = redirect.acquire().await;
        let _second = redirect.acquire().await;

        assert!(
            tokio::time::timeout(Duration::from_secs(1), pool.acquire())
                .await
                .is_err(),
            "two shared connections must have consumed the whole two-permit pool"
        );
    }
}
