//! Shared hyper connection-dispatch helper for transports that aren't plain TCP (currently Tor
//! `.onion` and I2P `.b32.i2p` streams) — factored out so the HTTP/1.1-vs-HTTP/2 protocol
//! negotiation logic exists exactly once instead of being duplicated per transport.

use crate::http::response::Body;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// Placeholder peer address used where the underlying transport has no real socket address to
/// report (Tor/I2P both exist specifically to hide the client's real address).
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
        // Only the `ws` branch below needs `&mut`, so without that feature the binding is
        // immutable — and `unused_mut` is denied crate-wide, which broke every `tor`/`i2p`
        // build that didn't also enable `ws`.
        #[cfg_attr(not(feature = "ws"), allow(unused_mut))]
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        // RFC 8441: advertise support for the extended CONNECT bootstrap so `ws::WebSocketUpgrade`
        // can accept WebSocket-over-HTTP/2 requests.
        #[cfg(feature = "ws")]
        let _ = builder.http2().enable_connect_protocol();
        builder.serve_connection_with_upgrades(io, svc).await?;
    }
    #[cfg(all(feature = "http1", not(feature = "http2")))]
    {
        hyper::server::conn::http1::Builder::new()
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
        #[cfg(feature = "ws")]
        let _ = builder.enable_connect_protocol();
        builder.serve_connection(io, svc).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::service::service_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
