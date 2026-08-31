//! Shared hyper connection-dispatch helper for transports that aren't plain TCP (currently Tor
//! `.onion` and I2P `.b32.i2p` streams) — factored out so the HTTP/1.1-vs-HTTP/2 protocol
//! negotiation logic exists exactly once instead of being duplicated per transport.

use crate::http::response::Body;
use crate::server::REQUEST_TIMEOUT;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// Placeholder peer address used where the underlying transport has no real socket address to
/// report (Tor/I2P both exist specifically to hide the client's real address).
///
/// Every request over Tor/I2P reports the *same* [`ConnectInfo`](crate::routing::extract::ConnectInfo)
/// (`0.0.0.0:0`), so per-IP logic keyed on it degrades in two ways worth knowing about before
/// relying on it: any per-peer rate limiter collapses to a single shared bucket for all
/// anonymous traffic, and a "trust anything that isn't a global address" check (a common way
/// to gate internal/trusted-network behaviour) will treat every one of these requests as
/// trusted, since `0.0.0.0` is not a global address — a real hazard in a process that also
/// serves a clearnet listener in the same router.
#[cfg(any(feature = "tor", feature = "i2p"))]
pub(super) const NO_PEER_ADDR: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Serves one hyper connection over `io`, using whichever of `http1`/`http2` are enabled.
pub(super) async fn serve_connection<IO, Svc>(
    io: IO,
    svc: Svc,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Svc: hyper::service::Service<
            Request<hyper::body::Incoming>,
            Response = Response<Body>,
            Error = std::io::Error,
        > + Send
        + 'static,
    Svc::Future: Send,
{
    let io = TokioIo::new(io);

    #[cfg(all(feature = "http1", feature = "http2"))]
    {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        // Without a `Timer`, hyper silently drops `header_read_timeout` (only a `warn!`, no
        // error) — leaving a peer that opens a stream and never finishes its request line
        // able to hold this connection's slot in `max_connections` forever (Slowloris).
        let _ = builder
            .http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(REQUEST_TIMEOUT);
        let _ = builder
            .http2()
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(REQUEST_TIMEOUT)
            .keep_alive_timeout(REQUEST_TIMEOUT);
        // RFC 8441: advertise support for the extended CONNECT bootstrap so `ws::WebSocketUpgrade`
        // can accept WebSocket-over-HTTP/2 requests.
        #[cfg(feature = "ws")]
        let _ = builder.http2().enable_connect_protocol();
        builder.serve_connection_with_upgrades(io, svc).await?;
    }
    #[cfg(all(feature = "http1", not(feature = "http2")))]
    {
        hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(REQUEST_TIMEOUT)
            .serve_connection(io, svc)
            .with_upgrades()
            .await?;
    }
    #[cfg(all(feature = "http2", not(feature = "http1")))]
    {
        // As above: `mut` is only load-bearing under `ws`.
        #[cfg_attr(not(feature = "ws"), allow(unused_mut))]
        let mut builder =
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        let _ = builder
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(REQUEST_TIMEOUT)
            .keep_alive_timeout(REQUEST_TIMEOUT);
        #[cfg(feature = "ws")]
        let _ = builder.enable_connect_protocol();
        builder.serve_connection(io, svc).await?;
    }

    Ok(())
}

/// Like [`serve_connection`], but drives the connection to a graceful close (finish in-flight
/// requests, refuse new ones on the same connection) as soon as `shutdown` resolves, instead of
/// running until the peer disconnects. Used by [`crate::server::serve`]'s
/// `.with_graceful_shutdown()`, which — unlike [`crate::server::Server`]'s own worker-pool
/// accept loop — drives this connection directly and so can cooperate with a real per-connection
/// shutdown signal.
pub(super) async fn serve_connection_graceful<IO, Svc, Sig>(
    io: IO,
    svc: Svc,
    shutdown: Sig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Svc: hyper::service::Service<
            Request<hyper::body::Incoming>,
            Response = Response<Body>,
            Error = std::io::Error,
        > + Send
        + 'static,
    Svc::Future: Send,
    Sig: std::future::Future<Output = ()>,
{
    let io = TokioIo::new(io);
    tokio::pin!(shutdown);

    #[cfg(all(feature = "http1", feature = "http2"))]
    {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        let _ = builder
            .http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(REQUEST_TIMEOUT);
        let _ = builder
            .http2()
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(REQUEST_TIMEOUT)
            .keep_alive_timeout(REQUEST_TIMEOUT);
        #[cfg(feature = "ws")]
        let _ = builder.http2().enable_connect_protocol();
        let conn = builder.serve_connection_with_upgrades(io, svc);
        tokio::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res?,
            () = &mut shutdown => {
                conn.as_mut().graceful_shutdown();
                conn.await?;
            }
        }
    }
    #[cfg(all(feature = "http1", not(feature = "http2")))]
    {
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(REQUEST_TIMEOUT)
            .serve_connection(io, svc)
            .with_upgrades();
        tokio::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res?,
            () = &mut shutdown => {
                conn.as_mut().graceful_shutdown();
                conn.await?;
            }
        }
    }
    #[cfg(all(feature = "http2", not(feature = "http1")))]
    {
        #[cfg_attr(not(feature = "ws"), allow(unused_mut))]
        let mut builder =
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        let _ = builder
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(REQUEST_TIMEOUT)
            .keep_alive_timeout(REQUEST_TIMEOUT);
        #[cfg(feature = "ws")]
        let _ = builder.enable_connect_protocol();
        let conn = builder.serve_connection(io, svc);
        tokio::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res?,
            () = &mut shutdown => {
                conn.as_mut().graceful_shutdown();
                conn.await?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::service::service_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(any(feature = "tor", feature = "i2p"))]
    #[test]
    fn no_peer_addr_is_the_unspecified_ipv4_wildcard() {
        assert_eq!(
            NO_PEER_ADDR.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(NO_PEER_ADDR.port(), 0);
    }

    /// Drives `serve_connection` over an in-memory duplex pipe (no real socket, no Tor/I2P
    /// network needed) — this is the same helper both transports call, so exercising it once
    /// here covers the HTTP1-vs-HTTP2 negotiation logic those transports share.
    #[tokio::test]
    async fn serve_connection_round_trips_a_request_over_a_duplex_pipe() {
        let (mut client_io, server_io) = tokio::io::duplex(8 * 1024);

        let svc = service_fn(|_req: Request<hyper::body::Incoming>| async {
            Ok::<_, std::io::Error>(Response::new(Body::full(Bytes::from_static(
                b"hello from conn",
            ))))
        });

        let server = tokio::spawn(async move { serve_connection(server_io, svc).await });

        client_io
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");

        let mut buf = Vec::new();
        client_io
            .read_to_end(&mut buf)
            .await
            .expect("read response");
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("200"), "unexpected response: {response}");
        assert!(
            response.contains("hello from conn"),
            "unexpected response: {response}"
        );

        server
            .await
            .expect("server task join")
            .expect("serve_connection ok");
    }
}
