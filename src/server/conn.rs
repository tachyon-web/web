//! Shared hyper connection-dispatch helper for transports that aren't plain TCP (currently Tor
//! `.onion` and I2P `.b32.i2p` streams) — factored out so the HTTP/1.1-vs-HTTP/2 protocol
//! negotiation logic exists exactly once instead of being duplicated per transport.

#[cfg(feature = "http1")]
use crate::server::tuning::tune_http1;
#[cfg(feature = "http2")]
use crate::server::tuning::tune_http2;
use axum::body::Body;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// Placeholder peer address used where the underlying transport has no real socket address to
/// report (Tor/I2P both exist specifically to hide the client's real address).
///
/// Every request over Tor/I2P reports the *same* [`ConnectInfo`](axum::extract::ConnectInfo)
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
///
/// Tuning comes from [`tuning`](crate::server::tuning), the same place the TCP and TLS
/// listeners get theirs, so a limit added there applies to every transport at once.
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
    // A shutdown signal that never fires: `select!` then always takes the connection arm,
    // which is exactly the non-graceful behaviour.
    serve_connection_graceful(io, svc, std::future::pending()).await
}

/// Like [`serve_connection`], but drives the connection to a graceful close (finish in-flight
/// requests, refuse new ones on the same connection) as soon as `shutdown` resolves, instead of
/// running until the peer disconnects. Used by [`crate::server::serve`]'s
/// `.with_graceful_shutdown()`, which — unlike [`crate::server::Server`]'s own convenience
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

    // Exactly one of these three is compiled — see the crate-level `compile_error!` in `lib.rs`.
    // The builder is bound at function scope because the connection future borrows it.
    #[cfg(all(feature = "http1", feature = "http2"))]
    let builder = {
        let mut b =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        tune_http1!(b.http1());
        tune_http2!(b.http2());
        b
    };
    #[cfg(all(feature = "http1", feature = "http2"))]
    let conn = builder.serve_connection_with_upgrades(io, svc);

    #[cfg(all(feature = "http1", not(feature = "http2")))]
    let builder = {
        let mut b = hyper::server::conn::http1::Builder::new();
        tune_http1!(b);
        b
    };
    #[cfg(all(feature = "http1", not(feature = "http2")))]
    let conn = builder.serve_connection(io, svc).with_upgrades();

    #[cfg(all(feature = "http2", not(feature = "http1")))]
    let builder = {
        let mut b = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        tune_http2!(b);
        b
    };
    #[cfg(all(feature = "http2", not(feature = "http1")))]
    let conn = builder.serve_connection(io, svc);

    tokio::pin!(conn);
    tokio::select! {
        res = conn.as_mut() => res?,
        () = &mut shutdown => {
            conn.as_mut().graceful_shutdown();
            conn.await?;
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
            Ok::<_, std::io::Error>(Response::new(Body::from(Bytes::from_static(
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

    /// `serve_connection` is the path Tor and I2P take. It used to build its own hyper
    /// builders and set only the keep-alives, so those two transports ran on hyper's default
    /// HTTP/2 settings while plain TCP and TLS ran on `tuning::tune_http2!`.
    ///
    /// Every window/frame/stream value the tuning pins now coincides with hyper's own
    /// defaults, so none of them can tell the two apart. `enable_connect_protocol` can:
    /// hyper leaves it off, `tune_http2!` turns it on. That assertion is the real guard here;
    /// the rest are ordinary value checks that would catch a typo'd constant.
    #[cfg(all(feature = "http2", feature = "ws"))]
    #[tokio::test]
    async fn serve_connection_applies_the_shared_http2_tuning() {
        // RFC 9113 §6.5.2 and RFC 8441 §3 setting identifiers.
        const MAX_CONCURRENT_STREAMS: u16 = 0x3;
        const INITIAL_WINDOW_SIZE: u16 = 0x4;
        const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
        const SETTINGS_FRAME: u8 = 0x4;
        const ACK: u8 = 0x1;

        let (mut client_io, server_io) = tokio::io::duplex(16 * 1024);
        let svc = service_fn(|_req: Request<hyper::body::Incoming>| async {
            Ok::<_, std::io::Error>(Response::new(Body::empty()))
        });
        drop(tokio::spawn(async move {
            serve_connection(server_io, svc).await
        }));

        // Client connection preface + an empty SETTINGS frame, so the server finishes its
        // half of the handshake and flushes the SETTINGS we want to inspect.
        client_io
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("write preface");
        client_io
            .write_all(&[0, 0, 0, SETTINGS_FRAME, 0, 0, 0, 0, 0])
            .await
            .expect("write empty settings");

        let mut header = [0u8; 9];
        let mut settings = Vec::new();
        // The server's SETTINGS is the first frame it sends; spare iterations cover a
        // WINDOW_UPDATE or PING arriving first.
        for _ in 0..4u8 {
            client_io
                .read_exact(&mut header)
                .await
                .expect("read frame header");
            let len = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]]))
                .expect("frame length fits usize");
            let mut payload = vec![0u8; len];
            client_io
                .read_exact(&mut payload)
                .await
                .expect("read frame payload");

            if header[3] != SETTINGS_FRAME || header[4] & ACK != 0 {
                continue;
            }
            for entry in payload.as_chunks::<6>().0 {
                settings.push((
                    u16::from_be_bytes([entry[0], entry[1]]),
                    u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
                ));
            }
            break;
        }

        let get = |id: u16| settings.iter().find(|(k, _)| *k == id).map(|(_, v)| *v);
        assert_eq!(
            get(ENABLE_CONNECT_PROTOCOL),
            Some(1),
            "serve_connection must go through tuning::tune_http2!, which enables RFC 8441 \
             CONNECT; hyper leaves it off, so this is what tells the two apart. Got {settings:?}"
        );
        assert_eq!(
            get(INITIAL_WINDOW_SIZE),
            Some(1024 * 1024),
            "got {settings:?}"
        );
        assert_eq!(get(MAX_CONCURRENT_STREAMS), Some(200), "got {settings:?}");
    }
}
