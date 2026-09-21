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
/// free-standing [`serve()`](crate::server::serve) — so the two can't drift apart on socket
/// options the way they previously did (`serve()` left Nagle on, adding up to a round of
/// delayed-ACK latency to every small response it wrote).
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
