//! Serving one HTTP connection over any byte stream — TCP, TLS, a Tor stream or an I2P stream —
//! so HTTP/1.1-vs-HTTP/2 negotiation and graceful shutdown exist exactly once.

#[cfg(feature = "http1")]
use crate::server::tuning::tune_http1;
#[cfg(feature = "http2")]
use crate::server::tuning::tune_http2;
use axum::body::Body;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// A signal every connection watches: once it fires, each finishes its in-flight requests,
/// refuses new ones (HTTP/1.1 closes after the current response, HTTP/2 sends `GOAWAY`), and
/// ends. It also fires if the server future is dropped.
#[derive(Clone, Debug)]
pub(crate) struct Shutdown(tokio::sync::watch::Receiver<bool>);

impl Shutdown {
    pub(crate) fn new() -> (tokio::sync::watch::Sender<bool>, Self) {
        let (trigger, signal) = tokio::sync::watch::channel(false);
        (trigger, Self(signal))
    }

    pub(crate) async fn requested(&self) {
        let _ = self.0.clone().wait_for(|stop| *stop).await;
    }
}

/// Drives a hyper connection future, switching it to graceful shutdown when `shutdown` fires.
/// A macro because the connection types share `graceful_shutdown` by name, not by trait.
macro_rules! serve_gracefully {
    ($shutdown:expr, $conn:expr) => {{
        let conn = $conn;
        tokio::pin!(conn);
        tokio::select! {
            result = conn.as_mut() => result,
            () = $shutdown.requested() => {
                conn.as_mut().graceful_shutdown();
                conn.await
            }
        }
    }};
}

/// Serves one hyper connection over `io`, using whichever of `http1`/`http2` are enabled.
///
/// `http2` offers HTTP/2 beside HTTP/1.1 (by connection preface, which also covers TLS with
/// ALPN `h2`). Pass `false` on a plaintext stream whose
/// [`SecurityPolicy`](crate::SecurityPolicy) refuses h2c, so the HTTP/2 stack is not reachable
/// there at all. An `http2`-only build has nothing else to speak and ignores it.
///
/// `io` should already be wrapped in [`WriteDeadline`](crate::server::stall::WriteDeadline) at
/// its lowest layer — under TLS, not over it.
pub(crate) async fn serve_connection<IO, Svc>(
    io: IO,
    svc: Svc,
    http2: bool,
    shutdown: &Shutdown,
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

    // Exactly one of these three is compiled — see the crate-level `compile_error!` in `lib.rs`.
    // `auto`'s own `http1_only` is ignored by `serve_connection_with_upgrades`, so HTTP/1.1
    // alone goes through hyper's plain builder instead.
    #[cfg(all(feature = "http1", feature = "http2"))]
    if http2 {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        tune_http1!(builder.http1());
        tune_http2!(builder.http2());
        return serve_gracefully!(shutdown, builder.serve_connection_with_upgrades(io, svc));
    }

    #[cfg(feature = "http1")]
    {
        #[cfg(not(feature = "http2"))]
        let _ = http2;
        let mut builder = hyper::server::conn::http1::Builder::new();
        tune_http1!(builder);
        serve_gracefully!(shutdown, builder.serve_connection(io, svc).with_upgrades())?;
    }

    #[cfg(all(feature = "http2", not(feature = "http1")))]
    {
        let _ = http2;
        let mut builder =
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        tune_http2!(builder);
        serve_gracefully!(shutdown, builder.serve_connection(io, svc))?;
    }

    Ok(())
}

#[cfg(all(test, feature = "http1"))]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Drives `serve_connection` over an in-memory duplex pipe — the helper every transport
    /// calls, so this covers the negotiation they share.
    #[tokio::test]
    async fn serve_connection_round_trips_a_request_over_a_duplex_pipe() {
        let (mut client_io, server_io) = tokio::io::duplex(8 * 1024);

        let svc = service_fn(|_req: Request<hyper::body::Incoming>| async {
            Ok::<_, std::io::Error>(Response::new(Body::from(bytes::Bytes::from_static(
                b"hello from conn",
            ))))
        });

        let (_trigger, shutdown) = Shutdown::new();
        let server =
            tokio::spawn(async move { serve_connection(server_io, svc, true, &shutdown).await });

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

    /// Every transport must use `tune_http2!`. Its window/frame/stream values match hyper's
    /// defaults, so `enable_connect_protocol` (off in hyper) is what tells the two apart.
    #[cfg(all(feature = "http1", feature = "http2"))]
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
        let (_trigger, shutdown) = Shutdown::new();
        drop(tokio::spawn(async move {
            serve_connection(server_io, svc, true, &shutdown).await
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
