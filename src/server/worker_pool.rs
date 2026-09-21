//! Address binding shared by the convenience `start_*` methods.

use std::future::Future;
use tokio::net::TcpListener;

use crate::server::redirect::RedirectInfo;
#[cfg(feature = "tls")]
use crate::server::redirect::serve_http_redirect_and_challenges;
use crate::server::{Server, enforce_fips_compliance};

/// Binds one listener and serves it on the caller's Tokio runtime.
pub(super) async fn run_worker_pool<S, F, Fut>(
    server: Server<S>,
    addr: std::net::SocketAddr,
    redirect_info: Option<RedirectInfo>,
    serve_fn: F,
) -> Result<(), std::io::Error>
where
    S: Clone + Send + Sync + 'static,
    F: FnOnce(Server<S>, TcpListener) -> Fut,
    Fut: Future<Output = Result<(), std::io::Error>>,
{
    enforce_fips_compliance()?;

    #[cfg(not(feature = "tls"))]
    let _ = redirect_info;

    #[cfg(feature = "tls")]
    if let Some(info) = redirect_info {
        let listener = TcpListener::bind(info.addr).await?;
        drop(tokio::spawn(async move {
            serve_http_redirect_and_challenges(listener, info.https_port, info.allowed_hosts).await;
        }));
    }

    let listener = TcpListener::bind(addr).await?;
    serve_fn(server, listener).await
}
