//! Bridges an async `AsyncRead + AsyncWrite` stream to the blocking `std::io::Read`/`Write`
//! traits that `tungstenite`'s frame-level types (`FrameSocket`) require, so the raw-frame
//! engine in [`super::socket`] can drive them from async code.
//!
//! `WouldBlock` stands in for `Poll::Pending`: a blocking call that would otherwise park the
//! thread instead returns `ErrorKind::WouldBlock`, and the caller re-polls once the registered
//! waker fires. Read and write each get their own waker slot (`WakerProxy`) so a reader task and
//! a writer task — as produced by [`super::WebSocket::split`] — can each be woken independently
//! without clobbering the other's waker.

use futures_util::task::{self, ArcWake};
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Default)]
struct WakerProxy {
    read_waker: task::AtomicWaker,
    write_waker: task::AtomicWaker,
}

impl ArcWake for WakerProxy {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.read_waker.wake();
        arc_self.write_waker.wake();
    }
}

/// Which waker slot a blocking call should register into.
pub(super) enum Direction {
    Read,
    Write,
}

/// Presents an async stream as a blocking `Read + Write`, translating `Poll::Pending` into
/// `ErrorKind::WouldBlock` under the current task's waker.
pub(super) struct AllowStd<S> {
    inner: S,
    read_waker_proxy: Arc<WakerProxy>,
    write_waker_proxy: Arc<WakerProxy>,
}

impl<S> AllowStd<S> {
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            read_waker_proxy: Arc::default(),
            write_waker_proxy: Arc::default(),
        }
    }

    /// Registers `cx`'s waker for `direction`, so a future blocking call in that direction wakes
    /// the task back up once the underlying stream becomes ready.
    pub(super) fn register(&self, direction: &Direction, cx: &Context<'_>) {
        match direction {
            Direction::Read => {
                self.write_waker_proxy.read_waker.register(cx.waker());
                self.read_waker_proxy.read_waker.register(cx.waker());
            }
            Direction::Write => {
                self.write_waker_proxy.write_waker.register(cx.waker());
                self.read_waker_proxy.write_waker.register(cx.waker());
            }
        }
    }
}

impl<S> AllowStd<S>
where
    S: Unpin,
{
    fn with_context<F, R>(&mut self, direction: &Direction, f: F) -> Poll<io::Result<R>>
    where
        F: FnOnce(&mut Context<'_>, Pin<&mut S>) -> Poll<io::Result<R>>,
    {
        let waker = match direction {
            Direction::Read => task::waker_ref(&self.read_waker_proxy),
            Direction::Write => task::waker_ref(&self.write_waker_proxy),
        };
        let mut cx = Context::from_waker(&waker);
        f(&mut cx, Pin::new(&mut self.inner))
    }
}

impl<S> Read for AllowStd<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match self.with_context(&Direction::Read, |cx, stream| {
            stream.poll_read(cx, &mut read_buf)
        }) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<S> Write for AllowStd<S>
where
    S: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.with_context(&Direction::Write, |cx, stream| stream.poll_write(cx, buf)) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.with_context(&Direction::Write, |cx, stream| stream.poll_flush(cx)) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
