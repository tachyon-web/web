//! Thread-per-core worker pool: binds one `SO_REUSEPORT` listener per CPU core and runs a
//! caller-supplied accept loop on each, so [`Server::start_http`]/`start_https`/etc. scale
//! across cores without a shared-listener bottleneck.

use std::future::Future;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::server::redirect::RedirectInfo;
#[cfg(feature = "tls")]
use crate::server::redirect::serve_http_redirect_and_challenges;
use crate::server::{Server, enforce_fips_compliance};

thread_local! {
    pub(super) static IS_LOCAL_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Binds `addr` with `SO_REUSEADDR`/`SO_REUSEPORT` so one worker thread per core can share the
/// port — see [`run_worker_pool`].
///
/// On Linux, `SO_REUSEPORT` lets *any* process running as the same effective UID join this
/// listener's group and receive a share of its inbound connections — there is no additional
/// namespace or capability check. That's inherent to the mechanism (no `SO_REUSEPORT_LB` or
/// eBPF socket-selection filter is installed here), not a bug, but it's worth knowing given
/// this crate's anonymity-transport features: a compromised same-UID process could observe or
/// intercept a share of plaintext connections it otherwise has no access to.
fn bind_reuseport(addr: std::net::SocketAddr) -> Result<std::net::TcpListener, std::io::Error> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        socket.set_reuse_port(true)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    socket.listen(4096)?;
    Ok(std::net::TcpListener::from(socket))
}

/// One worker thread's body: binds its share of `addr` (and, if configured, the redirect
/// listener), reports the bind outcome over `bind_tx`, then runs `serve_fn` for the rest of
/// this thread's life. Factored out of [`run_worker_pool`] to keep that function under
/// clippy's line-count lint.
async fn run_worker_thread<S, F, Fut>(
    server: Arc<Server<S>>,
    serve_fn: Arc<F>,
    addr: std::net::SocketAddr,
    redirect_info: Option<RedirectInfo>,
    bind_tx: std::sync::mpsc::Sender<Result<(), std::io::Error>>,
) where
    S: Clone + Send + Sync + 'static,
    F: Fn(Server<S>, TcpListener) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), std::io::Error>> + Send + 'static,
{
    IS_LOCAL_WORKER.with(|flag| flag.set(true));

    // Only used for the HTTP->HTTPS redirect listener, which requires TLS.
    #[cfg(not(feature = "tls"))]
    let _ = &redirect_info;

    #[cfg(feature = "tls")]
    if let Some(info) = redirect_info {
        let r_listener_res = bind_reuseport(info.addr).and_then(TcpListener::from_std);
        match r_listener_res {
            Ok(l) => {
                tokio::task::spawn_local(async move {
                    serve_http_redirect_and_challenges(l, info.https_port, info.allowed_hosts)
                        .await;
                });
            }
            Err(e) => {
                tracing::error!("worker redirect bind error: {e}");
            }
        }
    }

    let listener_res = bind_reuseport(addr).and_then(TcpListener::from_std);
    let listener = match listener_res {
        Ok(l) => {
            let _ = bind_tx.send(Ok(()));
            l
        }
        Err(e) => {
            tracing::error!("worker bind error: {e}");
            let _ = bind_tx.send(Err(e));
            return;
        }
    };

    let server_clone = (*server).clone();
    let _ = serve_fn(server_clone, listener).await;
}

pub(super) async fn run_worker_pool<S, F, Fut>(
    server: Server<S>,
    addr: std::net::SocketAddr,
    redirect_info: Option<RedirectInfo>,
    serve_fn: F,
) -> Result<(), std::io::Error>
where
    S: Clone + Send + Sync + 'static,
    F: Fn(Server<S>, TcpListener) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), std::io::Error>> + Send + 'static,
{
    // Fails fast, with the real error text, before binding a listener on every core: every
    // worker thread runs `serve_fn` via `let _ = serve_fn(...).await` (its return value is
    // otherwise unobservable, since the accept loop is expected to run forever), so a
    // same-check failure inside `serve_fn` itself only ever surfaced as the generic "all
    // worker threads exited" error below, with the actual cause left to a log line. This
    // check is cheap and a no-op without the `fips` feature, so running it unconditionally
    // here (plain HTTP included) costs nothing.
    enforce_fips_compliance()?;

    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let mut handles = Vec::new();
    let server = Arc::new(server);
    let serve_fn = Arc::new(serve_fn);
    // Each worker thread reports whether it managed to bind its listener, so
    // that a totally unbindable address (e.g. permission denied, or already
    // in use on every core) produces a real `Err` instead of hanging forever
    // on the `pending()` below with only a log line to show for it.
    let (bind_tx, bind_rx) = std::sync::mpsc::channel::<Result<(), std::io::Error>>();

    for i in 0..cores {
        let server = server.clone();
        let serve_fn = serve_fn.clone();
        let core_id = core_ids.get(i).copied();
        let bind_tx = bind_tx.clone();
        let redirect_info = redirect_info.clone();
        let handle = std::thread::Builder::new()
            .name(format!("tachyon-worker-{i}"))
            .spawn(move || {
                if let Some(id) = core_id {
                    let _ = core_affinity::set_for_current(id);
                }

                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    tracing::error!("failed to build tokio runtime for worker thread");
                    return;
                };

                let local = tokio::task::LocalSet::new();
                local.block_on(
                    &rt,
                    run_worker_thread(server, serve_fn, addr, redirect_info, bind_tx),
                );
            })?;
        handles.push(handle);
    }
    drop(bind_tx);

    let (bind_results, bind_rx) = tokio::task::spawn_blocking(move || {
        let results = (0..cores)
            .filter_map(|_| bind_rx.recv().ok())
            .collect::<Vec<_>>();
        (results, bind_rx)
    })
    .await
    .unwrap_or_else(|_| (Vec::new(), std::sync::mpsc::channel().1));
    let bound = bind_results.iter().filter(|r| r.is_ok()).count();
    if bound == 0 {
        return Err(bind_results
            .into_iter()
            .find_map(std::result::Result::err)
            .unwrap_or_else(|| {
                std::io::Error::other("all worker threads failed to bind their listener")
            }));
    }
    if bound < cores {
        tracing::warn!(
            "Only {bound}/{cores} worker threads bound successfully; running in a degraded state"
        );
    }

    let _ = handles;
    // Each worker's accept loop runs indefinitely, so under normal operation this task
    // should never resolve. But a worker can still exit early *after* a successful bind —
    // e.g. `serve_fn`'s own `enforce_fips_compliance()` check failing right at the start of
    // `serve_http`/`serve_https` — and previously that left this function blocked on
    // `pending::<()>().await` forever, reporting nothing beyond a `tracing::error!` from
    // inside the dead thread. Every worker holds its `bind_tx` clone for its entire
    // lifetime (it's captured by the async block that runs `serve_fn`), so waiting for the
    // channel to close — every clone dropped, meaning every worker thread has exited,
    // whether from returning or panicking — is a reliable "the whole pool has died" signal.
    //
    // This waits on a plain `std::thread`, not `tokio::task::spawn_blocking`: a
    // `spawn_blocking` closure is tracked by the runtime's blocking pool, and — because it
    // can't be preempted — `Runtime::drop` blocks the dropping thread until it returns.
    // Under normal operation it never does (the accept loops run forever), so a caller that
    // `tokio::spawn`s this and later drops or aborts that task (a test tearing down its own
    // runtime, for instance) would hang forever on the runtime's own shutdown, long after
    // the task itself was supposedly cancelled. A bare OS thread carries no such obligation:
    // the runtime shuts down without waiting for it, and this future itself stays cancellable
    // through the `oneshot` receiver like any other `.await` point.
    let (hangup_tx, hangup_rx) = tokio::sync::oneshot::channel();
    let _ = std::thread::Builder::new()
        .name("tachyon-worker-hangup".to_string())
        .spawn(move || {
            while bind_rx.recv().is_ok() {}
            let _ = hangup_tx.send(());
        });
    match hangup_rx.await {
        Ok(()) => Err(std::io::Error::other(
            "all worker threads exited without accepting a connection — check for an early \
             error from `serve_fn` (e.g. FIPS enforcement) in the logs above",
        )),
        Err(_) => Err(std::io::Error::other(
            "hangup watcher thread dropped without reporting",
        )),
    }
}
