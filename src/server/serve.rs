//! `axum::serve`'s generic `serve`/`Serve`/`WithGracefulShutdown`/`IncomingStream`.
//!
//! Backed by a real per-listener accept loop — matching axum's own model exactly, rather than
//! delegating to [`crate::server::Server`]'s `SO_REUSEPORT` worker pool.
//!
//! [`Server::serve_http`](crate::server::Server::serve_http)/`.start_http_addr()`/etc. keep the
//! worker-pool architecture entirely — this module only covers the free-standing
//! [`serve()`](fn@serve) entry point, so it can match axum's generic-`MakeService` signature
//! (and, transitively, [`IncomingStream`]'s shape) byte for byte. That does mean this specific
//! entry point no longer gets the worker pool's multi-core accept scaling: reach for
//! [`Server::serve_http`](crate::server::Server::serve_http)/`.start_http_addr()` instead if
//! that matters more to you than the axum-drop-in signature.

use crate::http::response::Body;
/// Re-exported at this path so `tachyon_web::serve::{IncomingStream, Listener, ListenerExt,
/// TapIo}` matches `axum::serve::{IncomingStream, Listener, ListenerExt, TapIo}`.
pub use crate::routing::tower_compat::IncomingStream;
pub use crate::server::{Listener, ListenerExt, TapIo};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::pin::Pin;
use tower::Service;

type Request = crate::http::Request;
type Response = crate::http::response::Response;

/// Starts serving requests accepted from `listener`, dispatching each connection through a
/// fresh `tower::Service` produced by `make_service`.
///
/// Matches `axum::serve::serve` exactly: a bare [`crate::routing::Router`] (already implementing
/// `Service<IncomingStream<'_, L>>` by cloning itself per connection) can be passed directly,
/// with no `.into_make_service()` needed.
///
/// The returned [`Serve`] implements [`IntoFuture`], so `serve(listener, router).await` runs
/// forever (or until an accept error), and `.with_graceful_shutdown(signal)` can be chained on
/// first — see the [module docs](self) for how this differs from
/// [`Server`](crate::server::Server)'s own accept loop.
///
/// *Axum compatibility: drop-in replacement for `axum::serve`.*
pub fn serve<L, M, S>(listener: L, make_service: M) -> Serve<L, M, S>
where
    L: Listener,
    M: for<'a> Service<IncomingStream<'a, L>, Error = Infallible, Response = S>,
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
{
    Serve {
        listener,
        make_service,
        _marker: PhantomData,
    }
}

/// The future returned by [`fn@serve`] before any `.with_graceful_shutdown()` call.
///
/// Implements [`IntoFuture`], matching `axum::serve::Serve`.
///
/// *Axum compatibility: drop-in replacement for `axum::serve::Serve`.*
#[must_use = "futures do nothing unless polled or `.await`ed"]
pub struct Serve<L, M, S> {
    listener: L,
    make_service: M,
    _marker: PhantomData<fn() -> S>,
}

impl<L, M, S> std::fmt::Debug for Serve<L, M, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serve").finish_non_exhaustive()
    }
}

impl<L, M, S> Serve<L, M, S>
where
    L: Listener,
{
    /// Runs until either the accept loop errors or `signal` resolves — and, unlike
    /// [`crate::server::Server`]'s worker pool, actually stops accepting new connections and
    /// gracefully drains every in-flight one (via `.graceful_shutdown()`) before returning.
    /// Matches `axum::serve::Serve::with_graceful_shutdown`.
    pub fn with_graceful_shutdown<F>(self, signal: F) -> WithGracefulShutdown<L, M, S, F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        WithGracefulShutdown {
            listener: self.listener,
            make_service: self.make_service,
            signal,
            _marker: PhantomData,
        }
    }

    /// Returns the local address this server is bound to.
    ///
    /// # Errors
    /// Returns an error if querying the OS for the bound address fails.
    pub fn local_addr(&self) -> std::io::Result<L::Addr> {
        self.listener.local_addr()
    }
}

impl<L, M, S> IntoFuture for Serve<L, M, S>
where
    L: Listener,
    M: for<'a> Service<IncomingStream<'a, L>, Error = Infallible, Response = S> + Send + 'static,
    for<'a> <M as Service<IncomingStream<'a, L>>>::Future: Send,
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
{
    type Output = Result<(), std::io::Error>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(run(self.listener, self.make_service))
    }
}

/// Returned by [`Serve::with_graceful_shutdown`]. Matches `axum::serve::WithGracefulShutdown`.
///
/// *Axum compatibility: drop-in replacement for `axum::serve::WithGracefulShutdown`.*
#[must_use = "futures do nothing unless polled or `.await`ed"]
pub struct WithGracefulShutdown<L, M, S, F> {
    listener: L,
    make_service: M,
    signal: F,
    _marker: PhantomData<fn() -> S>,
}

impl<L, M, S, F> std::fmt::Debug for WithGracefulShutdown<L, M, S, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithGracefulShutdown")
            .finish_non_exhaustive()
    }
}

impl<L, M, S, F> WithGracefulShutdown<L, M, S, F>
where
    L: Listener,
{
    /// The address this listener is bound to.
    ///
    /// # Errors
    /// Returns an error if querying the OS for the bound address fails.
    pub fn local_addr(&self) -> std::io::Result<L::Addr> {
        self.listener.local_addr()
    }
}

impl<L, M, S, F> IntoFuture for WithGracefulShutdown<L, M, S, F>
where
    L: Listener,
    M: for<'a> Service<IncomingStream<'a, L>, Error = Infallible, Response = S> + Send + 'static,
    for<'a> <M as Service<IncomingStream<'a, L>>>::Future: Send,
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
    F: Future<Output = ()> + Send + 'static,
{
    type Output = Result<(), std::io::Error>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(run_with_shutdown(
            self.listener,
            self.make_service,
            self.signal,
        ))
    }
}

/// Adapts a `tower::Service` into the `hyper::service::Service` shape
/// [`crate::server::conn`]'s connection drivers expect, mapping the (statically unreachable)
/// `Infallible` error into the `io::Error` they require.
struct HyperService<S>(S);

impl<S> hyper::service::Service<hyper::Request<hyper::body::Incoming>> for HyperService<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let mut svc = self.0.clone();
        let req = req.map(Body::stream);
        Box::pin(async move {
            use tower::ServiceExt as _;
            match svc.ready().await {
                Ok(ready) => match ready.call(req).await {
                    Ok(resp) => Ok(resp),
                    Err(never) => match never {},
                },
                Err(never) => match never {},
            }
        })
    }
}

async fn run<L, M, S>(mut listener: L, mut make_service: M) -> Result<(), std::io::Error>
where
    L: Listener,
    M: for<'a> Service<IncomingStream<'a, L>, Error = Infallible, Response = S>,
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
{
    loop {
        let (io, remote_addr) = listener.accept().await;
        let io = TokioIo::new(io);

        std::future::poll_fn(|cx| make_service.poll_ready(cx))
            .await
            .unwrap_or_else(|never: Infallible| match never {});
        let tower_svc = make_service
            .call(IncomingStream::new(&io, remote_addr))
            .await
            .unwrap_or_else(|never: Infallible| match never {});

        tokio::spawn(async move {
            let _ = crate::server::conn::serve_connection(io.into_inner(), HyperService(tower_svc))
                .await;
        });
    }
}

async fn run_with_shutdown<L, M, S, F>(
    mut listener: L,
    mut make_service: M,
    signal: F,
) -> Result<(), std::io::Error>
where
    L: Listener,
    M: for<'a> Service<IncomingStream<'a, L>, Error = Infallible, Response = S>,
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
    F: Future<Output = ()> + Send + 'static,
{
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let (close_tx, mut close_rx) = tokio::sync::mpsc::channel::<()>(1);

    tokio::spawn(async move {
        signal.await;
        let _ = shutdown_tx.send(true);
    });

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (io, remote_addr) = accepted;
                let io = TokioIo::new(io);

                std::future::poll_fn(|cx| make_service.poll_ready(cx))
                    .await
                    .unwrap_or_else(|never: Infallible| match never {});
                let tower_svc = make_service
                    .call(IncomingStream::new(&io, remote_addr))
                    .await
                    .unwrap_or_else(|never: Infallible| match never {});

                let mut conn_shutdown = shutdown_rx.clone();
                let close_tx = close_tx.clone();
                tokio::spawn(async move {
                    let shutdown_signal = async move {
                        // A receiver cloned *after* the flip would otherwise wait for the
                        // *next* change, which never comes — check the already-flipped value
                        // first rather than relying solely on `changed()`.
                        if !*conn_shutdown.borrow() {
                            let _ = conn_shutdown.changed().await;
                        }
                    };
                    let _ = crate::server::conn::serve_connection_graceful(
                        io.into_inner(),
                        HyperService(tower_svc),
                        shutdown_signal,
                    )
                    .await;
                    drop(close_tx);
                });
            }
            _ = shutdown_rx.changed() => {
                break;
            }
        }
    }

    drop(close_tx);
    // Resolves once every spawned connection task above has dropped its `close_tx` clone —
    // i.e. once every in-flight connection has actually finished draining.
    let _ = close_rx.recv().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::response::IntoResponse;
    use crate::routing::Router;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::net::TcpListener;

    async fn bind() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn serve_accepts_a_real_connection_and_dispatches_to_the_router() {
        let listener = bind().await;
        let addr = listener.local_addr().unwrap();

        let app: Router<()> =
            Router::new().route("/", crate::get(|| async { "hello from real accept loop" }));

        let handle = tokio::spawn(serve(listener, app).into_future());

        // Give the accept loop a moment to start polling.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);

        handle.abort();
    }

    #[tokio::test]
    async fn with_graceful_shutdown_stops_accepting_and_drains_in_flight_requests() {
        let listener = bind().await;
        let addr: SocketAddr = listener.local_addr().unwrap();

        let started = Arc::new(AtomicUsize::new(0));
        let started_clone = started.clone();
        let app: Router<()> = Router::new().route(
            "/slow",
            crate::get(move || {
                let started = started_clone.clone();
                async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    "done".into_response()
                }
            }),
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let signal = async move {
            let _ = shutdown_rx.await;
        };
        let handle = tokio::spawn(
            serve(listener, app)
                .with_graceful_shutdown(signal)
                .into_future(),
        );

        tokio::time::sleep(Duration::from_millis(20)).await;

        // Start a slow request, then signal shutdown while it's still in flight.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri("/slow")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let send_fut = sender.send_request(req);

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
        let _ = shutdown_tx.send(());

        // The in-flight request must still complete successfully even though shutdown fired.
        let resp = send_fut.await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);

        // And the whole `serve(...).with_graceful_shutdown(...)` future must resolve on its own
        // once that connection finished draining.
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("graceful shutdown must resolve promptly once draining finishes")
            .expect("task must not panic")
            .expect("serve must return Ok");
    }
}
