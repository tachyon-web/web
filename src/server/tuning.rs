//! The hyper connection tuning shared by every transport.
//!
//! These are macros rather than functions because the same settings apply to unrelated
//! types with identical setters: `hyper::server::conn::http1::Builder` and `hyper_util`'s
//! `auto::Http1Builder` (likewise for HTTP/2). They live in their own module so that every
//! transport — plain TCP, TLS, the port-80 redirect listener, Tor and I2P — reaches the
//! *same* definition.
//!
//! Before this module existed, `conn.rs` (the Tor/I2P path) set only the keep-alives and
//! otherwise ran on hyper's defaults, while the TCP and TLS listeners ran on the full tuning.
//! That is the kind of drift a second copy produces: silent, and only in the settings that
//! happen not to match. `conn::tests::serve_connection_applies_the_shared_http2_tuning` is
//! what pins the Tor/I2P path to this module — note that every value below now *coincides*
//! with hyper's own defaults except `enable_connect_protocol`, so that is the one the test
//! can actually use to tell "went through here" from "got hyper's defaults".

/// Applies the HTTP/1.1 connection tuning shared by every listener.
///
/// `writev` is opt-in per call site — forcing vectored writes over a TLS stream, which
/// buffers its own records, is a different tradeoff than over a bare socket.
///
/// Gated on `http1` because every call site is, and `unused_macros` is denied.
#[cfg(feature = "http1")]
macro_rules! tune_http1 {
    ($builder:expr) => {{
        let tuned = &mut $builder;
        // Without a `Timer`, hyper silently drops `header_read_timeout` (only a `warn!`, no
        // error) — leaving a peer that opens a stream and never finishes its request line
        // able to hold this connection's slot in `max_connections` forever (Slowloris).
        let _ = tuned
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout($crate::server::REQUEST_TIMEOUT)
            .keep_alive(true)
            .max_buf_size(8192)
            // Already the default; pinned because inheriting it is a bet on that never
            // changing, and it is a request-smuggling primitive if it does — desync is
            // entirely a disagreement about where one request ends, so an origin that accepts
            // a header a fronting proxy rejects is the whole bug class (RFC 9112 §2.2).
            // `allow_multiple_spaces_in_request_line_delimiters` deserves the same treatment
            // but `hyper_util`'s `auto` builder doesn't re-export it; it defaults strict.
            .ignore_invalid_headers(false)
            // The HTTP/1.1 counterpart to HPACK's per-field accounting: an explicit ceiling on
            // header *count*, not just the total bytes `max_buf_size` bounds. Same value hyper
            // defaults to — stated here so the limit is ours rather than inherited.
            .max_headers(100);
    }};
}

/// Applies the HTTP/2 connection tuning shared by every listener — see [`tune_http1`] for
/// why this is a macro.
#[cfg(feature = "http2")]
macro_rules! tune_http2 {
    ($builder:expr) => {{
        let tuned = &mut $builder;
        let _ = tuned
            .timer(hyper_util::rt::TokioTimer::new())
            // Matched to the connection window below, so one stream can use the whole
            // connection budget. The previous 64 KiB capped a *single* upload at
            // window/RTT — roughly 655 KB/s at a 100ms RTT — while saving nothing: the
            // connection window already bounds in-flight request data to 1 MiB per
            // connection either way, so the stream window only decides whether one stream
            // or sixteen have to share it.
            .initial_stream_window_size(1024 * 1024)
            .initial_connection_window_size(1024 * 1024)
            .max_frame_size(16384)
            .max_concurrent_streams(200)
            // Bounds the decoded size of one header block. With RFC 9113 §6.5.2's mandatory
            // 32-byte-per-field accounting (which h2 implements), this doubles as a cap of
            // ~512 header fields — the per-entry allocation amplification that the HPACK half
            // of CVE-2026-49975 turned into a memory bomb against servers that counted only
            // total decoded bytes. Same value hyper defaults to, pinned rather than inherited.
            .max_header_list_size(16 * 1024)
            // Per *stream*, and the only thing bounding what a stalled reader can pin:
            // CVE-2026-49975's second half is a peer that advertises a zero flow-control
            // window and drips `WINDOW_UPDATE`s to keep the stream alive while the response
            // sits in this buffer. hyper's ~400 KiB default times 200 streams is 80 MiB of
            // attacker-pinned memory per connection; 64 KiB brings that to 12.8 MiB. Costs a
            // draining client nothing — capacity is released as soon as bytes reach the
            // connection, so this only caps read-ahead past a peer that has stopped reading.
            .max_send_buf_size(64 * 1024)
            // `keep_alive_timeout` alone does nothing — hyper only sends the pings (and
            // enforces the timeout) once `keep_alive_interval` is also set. Without this, a
            // dead or idle peer that completes the handshake and goes silent holds its
            // connection permit forever.
            .keep_alive_interval($crate::server::REQUEST_TIMEOUT)
            .keep_alive_timeout($crate::server::REQUEST_TIMEOUT);
        // RFC 8441: let `ws::WebSocketUpgrade` accept WebSocket-over-HTTP/2 requests.
        #[cfg(feature = "ws")]
        let _ = tuned.enable_connect_protocol();
    }};
}

#[cfg(feature = "http1")]
pub(crate) use tune_http1;
#[cfg(feature = "http2")]
pub(crate) use tune_http2;
