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

/// Bounds how many connections a transport serves concurrently.
#[derive(Debug, Clone)]
pub(super) struct ConnectionLimit(Arc<Semaphore>);

impl ConnectionLimit {
    /// A limiter allowing `max_conns` connections in flight at once.
    pub(super) fn new(max_conns: usize) -> Self {
        Self(Arc::new(Semaphore::new(max_conns)))
    }

    /// Waits for capacity, yielding the permit to hold for one connection's lifetime.
    ///
    /// Acquiring *before* accepting is deliberate: a server at capacity stops taking
    /// connections off the listen backlog rather than accepting them and immediately
    /// queueing, so the backpressure is visible to the peer.
    ///
    /// `None` once the limiter is closed, which is how a transport is told to stop.
    pub(super) async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.0).acquire_owned().await.ok()
    }

    /// Serves one connection on its own task, holding `permit` until it finishes.
    pub(super) fn serve(
        permit: OwnedSemaphorePermit,
        conn: impl Future<Output = ()> + Send + 'static,
    ) {
        super::http::spawn_connection(async move {
            conn.await;
            drop(permit);
        });
    }
}
