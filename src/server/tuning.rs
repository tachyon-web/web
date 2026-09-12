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
//! Most of those defaults coincide, so the divergence was mostly invisible — except for the
//! initial stream window, where hyper defaults to 1 MiB and the tuning pins 64 KiB. That is
//! the kind of drift a second copy produces: silent, and only in the settings that happen not
//! to match. `conn::tests::serve_connection_applies_the_shared_http2_tuning` pins it.

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
            .max_buf_size(8192);
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
            .initial_stream_window_size(65535)
            .initial_connection_window_size(1024 * 1024)
            .max_frame_size(16384)
            .max_concurrent_streams(200)
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
