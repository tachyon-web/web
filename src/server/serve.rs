//! `axum::serve`'s `Serve`/`WithGracefulShutdown` builder types, backed by
//! [`crate::server::Server`]'s worker-pool internally.
//!
//! Axum's `axum::serve(listener, app)` returns a builder implementing
//! [`IntoFuture`] rather than an `async fn`'s bare future, so
//! `.with_graceful_shutdown(signal)` can be chained on before the final
//! `.await`. This mirrors that shape. See [`Serve::with_graceful_shutdown`]
//! for the one real behavioral difference from Axum's version.

use crate::routing::Router;
use crate::server::Server;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use tokio::net::TcpListener;

/// The future returned by [`fn@crate::serve`] before any
/// `.with_graceful_shutdown()` call.
///
/// Implements [`IntoFuture`], so `tachyon_web::serve(listener, router).await`
/// keeps working exactly as a plain `async fn` would; `.with_graceful_shutdown()`
/// is also available, matching `axum::serve::Serve`.
#[must_use = "futures do nothing unless polled or `.await`ed"]
pub struct Serve {
    pub(crate) listener: TcpListener,
    pub(crate) router: Router<()>,
}

impl std::fmt::Debug for Serve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serve").finish_non_exhaustive()
    }
}

impl Serve {
    /// Races the server against `signal`: returns as soon as either the
    /// server errors or `signal` resolves. Matches
    /// `axum::serve::Serve::with_graceful_shutdown`.
    ///
    /// # Limitation vs. Axum
    ///
    /// This does not (yet) stop tachyon's worker-pool threads from
    /// continuing to accept connections — there is no cooperative shutdown
    /// channel wired through the worker pool's accept loop yet (a real
    /// architectural addition, deliberately out of scope for this shim).
    /// What this *does* do: make the returned future itself resolve as soon
    /// as `signal` fires, so
    /// `tachyon_web::serve(listener, app).with_graceful_shutdown(sig).await`
    /// returns control to the caller (e.g. so `main` can proceed to exit)
    /// exactly when Axum code expects it to.
    pub fn with_graceful_shutdown<F>(self, signal: F) -> WithGracefulShutdown<F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        WithGracefulShutdown {
            listener: self.listener,
            router: self.router,
            signal,
        }
    }
}

impl IntoFuture for Serve {
    type Output = Result<(), std::io::Error>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(run(self.listener, self.router))
    }
}

/// Returned by [`Serve::with_graceful_shutdown`]. Matches
/// `axum::serve::WithGracefulShutdown`.
#[must_use = "futures do nothing unless polled or `.await`ed"]
pub struct WithGracefulShutdown<F> {
    listener: TcpListener,
    router: Router<()>,
    signal: F,
}

impl<F> std::fmt::Debug for WithGracefulShutdown<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithGracefulShutdown").finish_non_exhaustive()
    }
}

impl<F> IntoFuture for WithGracefulShutdown<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    type Output = Result<(), std::io::Error>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(race(run(self.listener, self.router), self.signal))
    }
}

async fn run(listener: TcpListener, router: Router<()>) -> Result<(), std::io::Error> {
    let addr = listener.local_addr()?;
    // drop the listener so the port is free to bind SO_REUSEPORT sockets in the worker pool
    drop(listener);

    let server = Server::new(router);
    server.start_http_addr(addr).await
}

/// The actual race logic, factored out so it can be unit-tested against
/// cheap fake futures instead of a real worker-pool server — spawning that
/// for a test would leave background OS threads running past the test
/// (`run`'s worker threads have no cooperative shutdown hook; see
/// [`Serve::with_graceful_shutdown`]'s doc comment) and can trip the
/// documented pre-existing `spawn_blocking`/runtime-drop hang this crate's
/// test suite already works around elsewhere.
async fn race<M, F>(main: M, signal: F) -> Result<(), std::io::Error>
where
    M: Future<Output = Result<(), std::io::Error>>,
    F: Future<Output = ()>,
{
    tokio::select! {
        res = main => res,
        () = signal => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn race_returns_as_soon_as_the_signal_fires_even_if_main_never_resolves() {
        let main = std::future::pending::<Result<(), std::io::Error>>();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let signal = async move {
            let _ = rx.await;
        };

        let handle = tokio::spawn(race(main, signal));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!handle.is_finished());

        tx.send(()).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("race must return promptly once signaled")
            .expect("task must not panic");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn race_returns_mains_result_when_main_finishes_first() {
        let main = async { Err::<(), _>(std::io::Error::other("boom")) };
        let signal = std::future::pending::<()>();

        let result = race(main, signal).await;
        assert!(result.is_err());
    }
}
