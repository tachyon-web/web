//! Write-stall deadline for stream transports (TCP, TLS, Tor, I2P).
//!
//! hyper's HTTP/1.1 has no write timeout, so a peer that stops reading a response kept its
//! connection — and its permit — forever. HTTP/3 already bounds each write with
//! [`RESPONSE_WRITE_TIMEOUT`]; this is the same rule one layer down, under hyper.

use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use crate::server::RESPONSE_WRITE_TIMEOUT;

pin_project_lite::pin_project! {
    /// Fails a write, flush or shutdown that makes no progress for [`RESPONSE_WRITE_TIMEOUT`].
    ///
    /// The timer is armed on the first `Pending` and cleared by any progress, so a draining
    /// client never trips it and an idle keep-alive connection never allocates one.
    #[derive(Debug)]
    pub(super) struct WriteDeadline<IO> {
        #[pin]
        inner: IO,
        stall: Option<Pin<Box<Sleep>>>,
    }
}

impl<IO> WriteDeadline<IO> {
    pub(super) const fn new(inner: IO) -> Self {
        Self { inner, stall: None }
    }
}

fn bounded<T>(
    stall: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
    poll: Poll<std::io::Result<T>>,
) -> Poll<std::io::Result<T>> {
    if poll.is_ready() {
        *stall = None;
        return poll;
    }
    let deadline =
        stall.get_or_insert_with(|| Box::pin(tokio::time::sleep(RESPONSE_WRITE_TIMEOUT)));
    if deadline.as_mut().poll(cx).is_ready() {
        return Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "peer stopped reading",
        )));
    }
    Poll::Pending
}

impl<IO: AsyncRead> AsyncRead for WriteDeadline<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite> AsyncWrite for WriteDeadline<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let poll = this.inner.poll_write(cx, buf);
        bounded(this.stall, cx, poll)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let poll = this.inner.poll_write_vectored(cx, bufs);
        bounded(this.stall, cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let poll = this.inner.poll_flush(cx);
        bounded(this.stall, cx, poll)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let poll = this.inner.poll_shutdown(cx);
        bounded(this.stall, cx, poll)
    }
}

#[cfg(test)]
mod tests {
    use super::WriteDeadline;
    use crate::server::RESPONSE_WRITE_TIMEOUT;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A reader that drains in time keeps the writer alive past the deadline; one that stops
    /// reading gets the write failed instead of pinned forever.
    #[tokio::test(start_paused = true)]
    async fn a_write_fails_only_after_the_peer_stops_reading() {
        let (mut peer, io) = tokio::io::duplex(64);
        let mut io = WriteDeadline::new(io);

        // Blocked for most of three deadlines, but never a whole one without progress.
        let slow_reader = async {
            let mut drained = [0_u8; 64];
            for _ in 0..4 {
                tokio::time::advance(RESPONSE_WRITE_TIMEOUT.saturating_sub(Duration::from_secs(1)))
                    .await;
                peer.read_exact(&mut drained).await.expect("drain");
            }
        };
        let (written, ()) = tokio::join!(io.write_all(&[0_u8; 4 * 64]), slow_reader);
        written.expect("a reader that keeps draining is never cut off");

        let stalled = io
            .write_all(&[0_u8; 2 * 64])
            .await
            .expect_err("peer stopped reading");
        assert_eq!(stalled.kind(), std::io::ErrorKind::TimedOut);
    }
}
