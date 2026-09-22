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

    #[cfg(not(feature = "tls"))]
    let _ = redirect;

    #[cfg(feature = "tls")]
    if let Some(info) = redirect {
        let listener = TcpListener::bind(info.addr).await?;
        drop(tokio::spawn(async move {
            serve_http_redirect_and_challenges(
                listener,
                info.https_port,
                info.allowed_hosts,
                info.limit,
                info.policy,
            )
            .await;
        }));
    }

    let listener = TcpListener::bind(addr).await?;
    serve(server, listener).await
}
