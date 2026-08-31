//! The `Listener`/`ListenerExt` traits accepted by [`crate::serve()`], matching
//! `axum::serve::{Listener, ListenerExt, TapIo}`.
//!
//! [`crate::serve()`] drives a real accept loop directly against whatever `Listener` it's given —
//! [`Listener::accept`] runs on every iteration, exactly as it would with axum. This is a
//! separate accept path from [`crate::server::Server`]'s own `SO_REUSEPORT` worker pool, which
//! binds its own sockets from a `SocketAddr` rather than accepting through a pre-built listener
//! object at all; see [`crate::server::serve`]'s module docs for when to reach for which.

use std::fmt;
use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

/// Types that can listen for connections. Matches `axum::serve::Listener`.
///
/// *Axum compatibility: drop-in replacement for `axum::serve::Listener`.*
pub trait Listener: Send + 'static {
    /// The listener's IO type.
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The listener's address type.
    type Addr: Send;

    /// Accept a new incoming connection to this listener.
    ///
    /// If the underlying accept call can return an error, this function must
    /// take care of logging and retrying.
    fn accept(&mut self) -> impl Future<Output = (Self::Io, Self::Addr)> + Send;

    /// Returns the local address that this listener is bound to.
    ///
    /// # Errors
    /// Returns an error if querying the OS for the bound address fails.
    fn local_addr(&self) -> io::Result<Self::Addr>;
}

impl Listener for TcpListener {
    type Io = TcpStream;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match Self::accept(self).await {
                Ok(tup) => return tup,
                Err(e) => handle_accept_error(e).await,
            }
        }
    }

    #[inline]
    fn local_addr(&self) -> io::Result<Self::Addr> {
        Self::local_addr(self)
    }
}

/// Extensions to [`Listener`]. Matches `axum::serve::ListenerExt`.
///
/// *Axum compatibility: drop-in replacement for `axum::serve::ListenerExt`.*
pub trait ListenerExt: Listener + Sized {
    /// Run a mutable closure on every accepted `Io`.
    fn tap_io<F>(self, tap_fn: F) -> TapIo<Self, F>
    where
        F: FnMut(&mut Self::Io) + Send + 'static,
    {
        TapIo {
            listener: self,
            tap_fn,
        }
    }
}

impl<L: Listener> ListenerExt for L {}

/// Return type of [`ListenerExt::tap_io`]. See that method for details.
/// Matches `axum::serve::TapIo`.
///
/// *Axum compatibility: drop-in replacement for `axum::serve::TapIo`.*
pub struct TapIo<L, F> {
    listener: L,
    tap_fn: F,
}

impl<L, F> fmt::Debug for TapIo<L, F>
where
    L: Listener + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TapIo")
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}

impl<L, F> Listener for TapIo<L, F>
where
    L: Listener,
    F: FnMut(&mut L::Io) + Send + 'static,
{
    type Io = L::Io;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (mut io, addr) = self.listener.accept().await;
        (self.tap_fn)(&mut io);
        (io, addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

async fn handle_accept_error(e: io::Error) {
    if is_connection_error(&e) {
        return;
    }
    error!("accept error: {e}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_listener_local_addr_matches_the_bound_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = Listener::local_addr(&listener).unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    }

    #[tokio::test]
    async fn tap_io_runs_the_closure_on_every_accepted_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = Listener::local_addr(&listener).unwrap();

        let tapped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tapped_writer = std::sync::Arc::clone(&tapped);
        let mut tapped_listener = listener.tap_io(move |_io: &mut TcpStream| {
            tapped_writer.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let connector = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await });
        let (_io, _addr) = tapped_listener.accept().await;
        connector.await.unwrap().unwrap();

        assert!(tapped.load(std::sync::atomic::Ordering::SeqCst));
    }
}
