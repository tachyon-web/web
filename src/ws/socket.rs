//! The raw-frame WebSocket engine.
//!
//! `tungstenite`'s own high-level `protocol::WebSocket` normalizes frames into `Message`s before
//! we'd ever see them, discarding the RSV1 bit — which is exactly what `permessage-deflate`
//! (RFC 7692) needs to tell a compressed message from a plain one. So instead of driving that
//! high-level type, this engine talks directly to `tungstenite::protocol::frame::FrameSocket`
//! (which hands us raw [`Frame`]s, header included) over the [`compat::AllowStd`] async/sync
//! bridge, and reimplements the bits of RFC 6455 that the high-level type would otherwise give us
//! for free: fragment reassembly, ping/pong/close handling, and server-side unmasking.
//!
//! Compression, when negotiated, is applied to a full reassembled message rather than per-frame:
//! RSV1 is only meaningful on the first frame of a message (continuation frames never set it).

use super::compat::{AllowStd, Direction};
use super::deflate::PerMessageDeflate;
use crate::http::error::Error;
use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, Stream};
use hyper::header::HeaderValue;
use hyper_util::rt::TokioIo;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::sync::PollSender;
use tungstenite::Error as WsError;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::protocol::frame::coding::{Control, Data as OpData, OpCode};
use tungstenite::protocol::frame::{CloseFrame, Frame, FrameHeader, FrameSocket, Utf8Bytes};

pub use tungstenite::Message;

type Io = AllowStd<TokioIo<hyper::upgrade::Upgraded>>;

/// Bound on the channels [`WebSocket::split`] bridges through to its background task — enough to
/// smooth out scheduling jitter without letting a stalled peer or slow consumer queue unbounded
/// messages in memory.
const SPLIT_CHANNEL_CAPACITY: usize = 32;

/// Cap on how many frames a single [`WebSocket::poll_recv`] call will process (control frames,
/// fragment continuations — anything that doesn't itself produce a `Message`) before yielding
/// back to the executor. Without this, a peer that bursts many small already-buffered frames
/// (they only need to fit in the 128 KiB read buffer) could keep one `poll_recv` call spinning
/// synchronously for the whole burst, denying the executor thread to other connections' tasks in
/// the meantime. Matches the order of magnitude of tokio's own internal I/O coop budget.
const RECV_YIELD_BUDGET: u32 = 128;

/// An established WebSocket connection.
///
/// See the [module docs](super) for an example.
pub struct WebSocket {
    frames: FrameSocket<Io>,
    protocol: Option<HeaderValue>,
    config: WebSocketConfig,
    deflate: Option<PerMessageDeflate>,
    fragment: Option<Fragment>,
    outgoing: VecDeque<Frame>,
    /// Set whenever a frame is handed to the socket's own internal write buffer; cleared once a
    /// `flush` actually completes. Lets [`WebSocket::poll_drain_outgoing`] skip the flush syscall
    /// path entirely on the (common) poll where there's nothing new to push out.
    flush_needed: bool,
    sent_close: bool,
    closed: bool,
}

struct Fragment {
    opcode: OpData,
    compressed: bool,
    buffer: BytesMut,
}

impl std::fmt::Debug for WebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocket").finish_non_exhaustive()
    }
}

fn protocol_error(err: &WsError) -> Error {
    Error::Internal(err.to_string())
}

/// XORs `data` in place against the 4-byte rolling `mask`, per RFC 6455 §5.3 — processed 8 (then
/// 4, then 1) bytes at a time rather than byte-by-byte, since every single client frame passes
/// through here and the mask pattern repeats every 4 bytes regardless of chunk width.
fn unmask(data: &mut [u8], mask: [u8; 4]) {
    let mask8 = u64::from_ne_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let mut chunks8 = data.chunks_exact_mut(8);
    for chunk in &mut chunks8 {
        let word = u64::from_ne_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]) ^ mask8;
        chunk.copy_from_slice(&word.to_ne_bytes());
    }

    let mask4 = u32::from_ne_bytes(mask);
    let mut chunks4 = chunks8.into_remainder().chunks_exact_mut(4);
    for chunk in &mut chunks4 {
        let word = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ mask4;
        chunk.copy_from_slice(&word.to_ne_bytes());
    }

    for (i, byte) in chunks4.into_remainder().iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
}

/// Whether `code` is legal to receive on the wire in a Close frame, per RFC 6455 §7.4.
///
/// `1000..=1003` and `1007..=1011` are the defined codes minus 1004 (reserved) and 1005/1006
/// (reserved for local/API use only — "MUST NOT be set as a status code in a Close control frame
/// by an endpoint"); `1012..=2999` is reserved for future protocol revisions and isn't yet
/// assigned; `3000..=4999` is open for libraries/frameworks/applications. This matches the
/// Autobahn Test Suite's reference behavior (cases 7.9.*) for what a compliant receiver accepts.
const fn is_valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999)
}

fn parse_close(payload: &[u8]) -> Result<Option<CloseFrame>, Error> {
    match payload.len() {
        0 => Ok(None),
        1 => Err(Error::Internal("invalid WebSocket close frame".to_string())),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if !is_valid_close_code(code) {
                return Err(Error::Internal(format!(
                    "received an invalid or reserved WebSocket close code: {code}"
                )));
            }
            let reason = std::str::from_utf8(&payload[2..])
                .map_err(|_| Error::Internal("WebSocket close reason is not UTF-8".to_string()))?;
            Ok(Some(CloseFrame {
                code: code.into(),
                reason: reason.to_string().into(),
            }))
        }
    }
}

/// Rejects frames RFC 6455 says must never reach the application: an unnegotiated reserved bit
/// (§5.2), or a control frame that's fragmented or exceeds the 125-byte control-frame cap
/// (§5.4/§5.5).
///
/// `deflate_negotiated` gates RSV1, which is only meaningful as `permessage-deflate`'s
/// "this message is compressed" marker (RFC 7692 §6): without the extension it's an
/// unnegotiated reserved bit like RSV2/RSV3, and even with it, it may only appear on the
/// *first* frame of a data message — never on a continuation frame, and never on a control
/// frame, both of which are always uncompressed.
fn validate_frame_header(
    header: &FrameHeader,
    payload_len: usize,
    deflate_negotiated: bool,
) -> Result<(), Error> {
    if header.rsv2 || header.rsv3 {
        return Err(Error::Internal(
            "received a WebSocket frame with an unsupported reserved bit set".to_string(),
        ));
    }
    if header.rsv1 {
        let rsv1_allowed = deflate_negotiated
            && matches!(header.opcode, OpCode::Data(OpData::Text | OpData::Binary));
        if !rsv1_allowed {
            return Err(Error::Internal(
                "received a WebSocket frame with RSV1 set where it is not permitted".to_string(),
            ));
        }
    }
    if matches!(header.opcode, OpCode::Control(_)) {
        if !header.is_final {
            return Err(Error::Internal(
                "WebSocket control frames must not be fragmented".to_string(),
            ));
        }
        if payload_len > 125 {
            return Err(Error::Internal(
                "WebSocket control frame payload exceeds 125 bytes".to_string(),
            ));
        }
    }
    Ok(())
}

/// Runs one blocking `tungstenite` frame-socket call, translating `WouldBlock` into `Pending`
/// after registering `cx`'s waker for `direction`.
fn poll_io<T>(
    frames: &mut FrameSocket<Io>,
    direction: &Direction,
    cx: &Context<'_>,
    f: impl FnOnce(&mut FrameSocket<Io>) -> Result<T, WsError>,
) -> Poll<Result<T, WsError>> {
    frames.get_mut().register(direction, cx);
    match f(frames) {
        Ok(value) => Poll::Ready(Ok(value)),
        Err(WsError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
        Err(err) => Poll::Ready(Err(err)),
    }
}

impl WebSocket {
    pub(super) fn new(
        io: TokioIo<hyper::upgrade::Upgraded>,
        protocol: Option<HeaderValue>,
        config: WebSocketConfig,
        deflate: Option<PerMessageDeflate>,
    ) -> Self {
        Self {
            frames: FrameSocket::new(AllowStd::new(io)),
            protocol,
            config,
            deflate,
            fragment: None,
            outgoing: VecDeque::new(),
            flush_needed: false,
            sent_close: false,
            closed: false,
        }
    }

    /// Pushes any frames queued for output (auto Pong replies, close echoes, user-sent messages)
    /// out to the wire, retrying on `WouldBlock` until either it's all flushed or an error occurs.
    /// Skips the flush call entirely when nothing has been written since the last one.
    fn poll_drain_outgoing(&mut self, cx: &Context<'_>) -> Poll<Result<(), WsError>> {
        while let Some(frame) = self.outgoing.pop_front() {
            match poll_io(&mut self.frames, &Direction::Write, cx, |fs| {
                fs.write(frame)
            }) {
                Poll::Ready(Ok(())) => self.flush_needed = true,
                other => return other,
            }
        }
        if !self.flush_needed {
            return Poll::Ready(Ok(()));
        }
        match poll_io(&mut self.frames, &Direction::Write, cx, FrameSocket::flush) {
            Poll::Ready(Ok(())) => {
                self.flush_needed = false;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }

    fn finish_message(
        &mut self,
        opcode: OpData,
        compressed: bool,
        payload: Bytes,
    ) -> Result<Option<Message>, Error> {
        let bytes = if compressed {
            let deflate = self.deflate.as_mut().ok_or_else(|| {
                Error::Internal("RSV1 set but permessage-deflate was not negotiated".to_string())
            })?;
            Bytes::from(deflate.decompress(&payload, self.config.max_message_size)?)
        } else {
            payload
        };
        match opcode {
            OpData::Text => {
                let text = Utf8Bytes::try_from(bytes)
                    .map_err(|e| Error::Internal(format!("invalid UTF-8 in text message: {e}")))?;
                Ok(Some(Message::Text(text)))
            }
            OpData::Binary => Ok(Some(Message::Binary(bytes))),
            OpData::Continue | OpData::Reserved(_) => {
                unreachable!("caller only passes Text/Binary")
            }
        }
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<Option<Message>, Error> {
        let header = frame.header().clone();
        let raw = frame.into_payload();
        validate_frame_header(&header, raw.len(), self.deflate.is_some())?;
        let payload = self.unmask_payload(&header, raw)?;

        match header.opcode {
            OpCode::Control(Control::Ping) => {
                self.outgoing.push_back(Frame::pong(payload.clone()));
                Ok(Some(Message::Ping(payload)))
            }
            OpCode::Control(Control::Pong) => Ok(Some(Message::Pong(payload))),
            OpCode::Control(Control::Close) => self.handle_close(&payload),
            OpCode::Control(Control::Reserved(code)) => Err(Error::Internal(format!(
                "received reserved WebSocket control opcode {code}"
            ))),
            OpCode::Data(data @ (OpData::Text | OpData::Binary)) => {
                self.handle_data_frame(data, &header, payload)
            }
            OpCode::Data(OpData::Continue) => self.handle_continue_frame(&header, &payload),
            OpCode::Data(OpData::Reserved(code)) => Err(Error::Internal(format!(
                "received reserved WebSocket data opcode {code}"
            ))),
        }
    }

    /// Server-side unmasking (RFC 6455 §5.3): reclaims `raw`'s buffer in place when we're the
    /// sole owner rather than copying it. Rejects unmasked frames unless configured to accept
    /// them.
    fn unmask_payload(&self, header: &FrameHeader, raw: Bytes) -> Result<Bytes, Error> {
        if let Some(mask) = header.mask {
            let mut buf = raw
                .try_into_mut()
                .unwrap_or_else(|shared| BytesMut::from(&shared[..]));
            unmask(&mut buf, mask);
            Ok(buf.freeze())
        } else if self.config.accept_unmasked_frames {
            Ok(raw)
        } else {
            Err(Error::Internal(
                "received an unmasked frame from the client".to_string(),
            ))
        }
    }

    fn handle_close(&mut self, payload: &Bytes) -> Result<Option<Message>, Error> {
        let close_frame = parse_close(payload)?;
        if !self.sent_close {
            self.outgoing.push_back(Frame::close(close_frame.clone()));
            self.sent_close = true;
        }
        self.closed = true;
        Ok(Some(Message::Close(close_frame)))
    }

    fn handle_data_frame(
        &mut self,
        data: OpData,
        header: &FrameHeader,
        payload: Bytes,
    ) -> Result<Option<Message>, Error> {
        if self.fragment.is_some() {
            return Err(Error::Internal(
                "received a new data frame while a fragmented message was in progress".to_string(),
            ));
        }
        if header.is_final {
            return self.finish_message(data, header.rsv1, payload);
        }
        let buffer = payload
            .try_into_mut()
            .unwrap_or_else(|shared| BytesMut::from(&shared[..]));
        // Checked here too, not just on continuation frames below: otherwise a single oversized
        // non-final frame could sit in memory unbounded whenever `max_frame_size` is configured
        // larger than `max_message_size`.
        self.check_message_size(buffer.len())?;
        self.fragment = Some(Fragment {
            opcode: data,
            compressed: header.rsv1,
            buffer,
        });
        Ok(None)
    }

    fn handle_continue_frame(
        &mut self,
        header: &FrameHeader,
        payload: &Bytes,
    ) -> Result<Option<Message>, Error> {
        let len = {
            let fragment = self.fragment.as_mut().ok_or_else(|| {
                Error::Internal(
                    "received a continuation frame with no message in progress".to_string(),
                )
            })?;
            fragment.buffer.extend_from_slice(payload);
            fragment.buffer.len()
        };
        self.check_message_size(len)?;
        if !header.is_final {
            return Ok(None);
        }
        let Fragment {
            opcode,
            compressed,
            buffer,
        } = self.fragment.take().unwrap_or_else(|| unreachable!());
        self.finish_message(opcode, compressed, buffer.freeze())
    }

    fn check_message_size(&self, len: usize) -> Result<(), Error> {
        if let Some(max) = self.config.max_message_size
            && len > max
        {
            return Err(Error::Internal(
                "WebSocket message exceeds the configured maximum size".to_string(),
            ));
        }
        Ok(())
    }

    fn poll_recv(&mut self, cx: &Context<'_>) -> Poll<Option<Result<Message, Error>>> {
        let mut budget = RECV_YIELD_BUDGET;
        loop {
            match self.poll_drain_outgoing(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => {
                    self.closed = true;
                    return Poll::Ready(Some(Err(protocol_error(&err))));
                }
                Poll::Pending => return Poll::Pending,
            }
            if self.closed {
                return Poll::Ready(None);
            }

            budget -= 1;
            if budget == 0 {
                // Yield cooperatively: re-register interest so we're polled again promptly, but
                // let the executor run other tasks first instead of monopolizing this thread.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let max_frame_size = self.config.max_frame_size;
            let frame = match poll_io(&mut self.frames, &Direction::Read, cx, |fs| {
                fs.read(max_frame_size)
            }) {
                Poll::Ready(Ok(Some(frame))) => frame,
                Poll::Ready(Ok(None)) => {
                    self.closed = true;
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(err)) => {
                    self.closed = true;
                    return Poll::Ready(Some(Err(protocol_error(&err))));
                }
                Poll::Pending => return Poll::Pending,
            };

            match self.handle_frame(frame) {
                Ok(Some(msg)) => return Poll::Ready(Some(Ok(msg))),
                Ok(None) => {}
                Err(err) => {
                    self.closed = true;
                    return Poll::Ready(Some(Err(err)));
                }
            }
        }
    }

    fn queue_data(&mut self, opcode: OpData, payload: Bytes) -> Result<(), Error> {
        let compressed = match &mut self.deflate {
            Some(deflate) => deflate.compress_if_smaller(&payload)?,
            None => None,
        };
        let (rsv1, bytes) =
            compressed.map_or_else(move || (false, payload), |c| (true, Bytes::from(c)));
        let mut frame = Frame::message(bytes, OpCode::Data(opcode), true);
        frame.header_mut().rsv1 = rsv1;
        self.outgoing.push_back(frame);
        Ok(())
    }

    fn queue_message(&mut self, msg: Message) -> Result<(), Error> {
        match msg {
            Message::Text(text) => self.queue_data(OpData::Text, Bytes::from(text)),
            Message::Binary(data) => self.queue_data(OpData::Binary, data),
            Message::Ping(data) => {
                self.outgoing.push_back(Frame::ping(data));
                Ok(())
            }
            Message::Pong(data) => {
                self.outgoing.push_back(Frame::pong(data));
                Ok(())
            }
            Message::Close(frame) => {
                self.outgoing.push_back(Frame::close(frame));
                self.sent_close = true;
                Ok(())
            }
            Message::Frame(frame) => {
                self.outgoing.push_back(frame);
                Ok(())
            }
        }
    }

    /// Receive the next message. Returns `None` once the stream has closed.
    pub async fn recv(&mut self) -> Option<Result<Message, Error>> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Send a message.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying connection has been closed or a protocol
    /// error occurs while writing.
    pub async fn send(&mut self, msg: Message) -> Result<(), Error> {
        self.queue_message(msg)?;
        poll_fn(|cx| self.poll_drain_outgoing(cx))
            .await
            .map_err(|e| protocol_error(&e))
    }

    /// Flush any buffered outgoing messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying connection has been closed or a protocol
    /// error occurs while flushing.
    pub async fn flush(&mut self) -> Result<(), Error> {
        poll_fn(|cx| self.poll_drain_outgoing(cx))
            .await
            .map_err(|e| protocol_error(&e))
    }

    /// Gracefully close the connection, consuming it.
    ///
    /// # Errors
    ///
    /// Returns an error if a protocol error occurs while closing.
    pub async fn close(mut self) -> Result<(), Error> {
        if !self.sent_close {
            self.outgoing.push_back(Frame::close(None));
            self.sent_close = true;
        }
        poll_fn(|cx| self.poll_drain_outgoing(cx))
            .await
            .map_err(|e| protocol_error(&e))
    }

    /// The selected WebSocket subprotocol, if one was negotiated.
    #[must_use]
    pub const fn protocol(&self) -> Option<&HeaderValue> {
        self.protocol.as_ref()
    }

    /// Split into independent sink and stream halves, for concurrent read/write tasks.
    ///
    /// Internally this hands the connection off to a background task (since the raw frame
    /// socket, like a plain TCP stream, isn't safe to drive concurrently from two tasks at once)
    /// and bridges to it over a pair of bounded channels — bounded so a stalled peer or a
    /// consumer that stops polling the stream applies real backpressure instead of letting
    /// queued messages grow without limit.
    pub fn split(
        self,
    ) -> (
        impl Sink<Message, Error = Error> + Send,
        impl Stream<Item = Result<Message, Error>> + Send,
    ) {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Message>(SPLIT_CHANNEL_CAPACITY);
        let (in_tx, in_rx) =
            tokio::sync::mpsc::channel::<Result<Message, Error>>(SPLIT_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let mut socket = self;
            loop {
                tokio::select! {
                    incoming = socket.recv() => {
                        match incoming {
                            Some(msg) => {
                                if in_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    outgoing = out_rx.recv() => {
                        match outgoing {
                            Some(msg) => {
                                if socket.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        (
            PollSender::new(out_tx).sink_map_err(map_poll_sender_err),
            SplitStream { rx: in_rx },
        )
    }
}

fn map_poll_sender_err<T>(_: tokio_util::sync::PollSendError<T>) -> Error {
    Error::Internal("WebSocket connection closed".to_string())
}

struct SplitStream {
    rx: tokio::sync::mpsc::Receiver<Result<Message, Error>>,
}

impl Stream for SplitStream {
    type Item = Result<Message, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::{is_valid_close_code, parse_close, unmask};

    /// Reference implementation (one byte at a time) to check the word-at-a-time `unmask`
    /// against, across every remainder case its 8/4/1-byte chunking can hit.
    fn naive_unmask(data: &mut [u8], mask: [u8; 4]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }

    #[test]
    fn unmask_matches_naive_reference_across_all_remainder_lengths() {
        let mask = [0x12, 0x34, 0x56, 0x78];
        // 0..=20 sweeps every combination of (whole 8-byte chunks, whole 4-byte chunks, 0..4
        // trailing bytes) that `unmask`'s three-stage chunking can produce.
        for len in 0u8..=20 {
            let original: Vec<u8> = (0..len).collect();

            let mut fast = original.clone();
            unmask(&mut fast, mask);

            let mut reference = original.clone();
            naive_unmask(&mut reference, mask);

            assert_eq!(fast, reference, "mismatch at length {len}");
        }
    }

    #[test]
    fn unmask_is_its_own_inverse() {
        let mask = [0xde, 0xad, 0xbe, 0xef];
        let original = b"the quick brown fox jumps over the lazy dog!!".to_vec();

        let mut round_tripped = original.clone();
        unmask(&mut round_tripped, mask);
        unmask(&mut round_tripped, mask);

        assert_eq!(round_tripped, original);
    }

    #[test]
    fn close_code_boundaries_rfc6455() {
        // Valid per RFC 6455 §7.4 / Autobahn Test Suite cases 7.9.*.
        for code in [
            1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 4999,
        ] {
            assert!(is_valid_close_code(code), "expected {code} to be valid");
        }
        // Invalid: below the defined range, the three reserved-for-local-use-only codes, the
        // unassigned 1012..=2999 range, and anything at or past 5000.
        for code in [0, 999, 1004, 1005, 1006, 1012, 1015, 1999, 2000, 2999, 5000] {
            assert!(!is_valid_close_code(code), "expected {code} to be invalid");
        }
    }

    #[test]
    fn parse_close_empty_payload_is_a_bare_close() {
        assert_eq!(parse_close(&[]).unwrap(), None);
    }

    #[test]
    fn parse_close_rejects_a_single_byte_payload() {
        assert!(parse_close(&[0x03]).is_err());
    }

    #[test]
    fn parse_close_rejects_an_invalid_code() {
        // 1005 ("No Status Rcvd") is reserved for local/API use only, never for the wire.
        let payload = [0x03, 0xed]; // 1005 big-endian
        assert!(parse_close(&payload).is_err());
    }

    #[test]
    fn parse_close_rejects_non_utf8_reason() {
        let mut payload = vec![0x03, 0xe8]; // 1000 big-endian
        payload.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8
        assert!(parse_close(&payload).is_err());
    }

    #[test]
    fn parse_close_accepts_a_valid_code_and_reason() {
        let mut payload = vec![0x03, 0xe8]; // 1000 big-endian
        payload.extend_from_slice(b"bye");
        let frame = parse_close(&payload).unwrap().unwrap();
        assert_eq!(u16::from(frame.code), 1000);
        assert_eq!(frame.reason.to_string(), "bye");
    }
}
