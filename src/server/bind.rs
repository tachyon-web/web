use std::future::Future;

use tokio::net::TcpListener;

use super::redirect::RedirectInfo;
use super::{Server, enforce_fips_compliance};

/// Binds `addr`, then the redirect listener if any, then hands the bound listener to `serve`.
///
/// The primary listener binds first so its failure cannot briefly bring up the redirect one,
/// and the redirect listener is up before `serve` runs — `serve_all_acme` relies on that to
/// answer HTTP-01 before its first order.
pub(super) async fn bind_and_serve<F, Fut>(
    server: Server,
    addr: std::net::SocketAddr,
    redirect: Option<RedirectInfo>,
    serve: F,
) -> Result<(), std::io::Error>
where
    F: FnOnce(Server, TcpListener) -> Fut,
    Fut: Future<Output = Result<(), std::io::Error>>,
{
    enforce_fips_compliance()?;
    let listener = TcpListener::bind(addr).await?;

    #[cfg(feature = "cert-gen")]
    let _redirect_task = match redirect {
        Some(info) => Some(info.spawn().await?),
        None => None,
    };
    #[cfg(not(feature = "cert-gen"))]
    let _ = redirect;

    serve(server, listener).await
}
