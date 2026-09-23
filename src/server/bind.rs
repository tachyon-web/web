use std::future::Future;

use tokio::net::TcpListener;

use super::redirect::RedirectInfo;
#[cfg(feature = "tls")]
use super::redirect::serve_http_redirect_and_challenges;
use super::{Server, enforce_fips_compliance};

pub(super) async fn bind_and_serve<S, F, Fut>(
    server: Server<S>,
    addr: std::net::SocketAddr,
    redirect: Option<RedirectInfo>,
    serve: F,
) -> Result<(), std::io::Error>
where
    S: Clone + Send + Sync + 'static,
    F: FnOnce(Server<S>, TcpListener) -> Fut,
    Fut: Future<Output = Result<(), std::io::Error>>,
{
    enforce_fips_compliance()?;

    // Bound first so a primary-listener failure cannot briefly bring up the redirect listener.
    let listener = TcpListener::bind(addr).await?;

    #[cfg(not(feature = "tls"))]
    let _ = redirect;

    #[cfg(feature = "tls")]
    let _redirect_task = match redirect {
        Some(info) => Some(spawn_redirect_listener(info).await?),
        None => None,
    };

    serve(server, listener).await
}

/// Binds the plaintext redirect/ACME-challenge listener and drives it on its own task.
///
/// Split out of [`bind_and_serve`] so `serve_all_acme` can bring this listener up *before* it
/// starts the ACME loop. HTTP-01 validation is answered here, so an order placed while nothing
/// is bound to the cleartext address fails and spends one of the CA's failed-validation
/// attempts for nothing.
#[cfg(feature = "tls")]
pub(super) async fn spawn_redirect_listener(
    info: RedirectInfo,
) -> Result<super::BackgroundTask, std::io::Error> {
    let listener = TcpListener::bind(info.addr).await?;
    Ok(super::BackgroundTask::new(tokio::spawn(async move {
        serve_http_redirect_and_challenges(
            listener,
            info.https_port,
            info.allowed_hosts,
            info.limit,
            info.policy,
        )
        .await;
    })))
}
