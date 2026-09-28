//! The hyper connection tuning shared by every transport.
//!
//! These are macros rather than functions because the same settings apply to unrelated
//! types with identical setters: `hyper::server::conn::http1::Builder` and `hyper_util`'s
//! `auto::Http1Builder` (likewise for HTTP/2). They live in their own module so that every
//! transport — plain TCP, TLS, the port-80 redirect listener, Tor and I2P — reaches the
//! *same* definition.
//!
//! `conn::tests::serve_connection_applies_the_shared_http2_tuning` pins the Tor/I2P path to
//! this module. The HTTP/2 window, frame and stream values below coincide with hyper's own
//! defaults, so it tells "went through here" from "got hyper's defaults" by
//! `enable_connect_protocol` instead.

/// Applies the HTTP/1.1 connection tuning shared by every listener.
#[cfg(feature = "http1")]
macro_rules! tune_http1 {
    ($builder:expr) => {{
        let tuned = &mut $builder;
        // Without a `Timer`, hyper silently ignores `header_read_timeout` (Slowloris).
        let _ = tuned
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout($crate::server::REQUEST_TIMEOUT)
            .keep_alive(true)
            .max_buf_size(8192)
            // Pinned defaults: accepting headers a fronting proxy rejects is a request-smuggling
            // primitive (RFC 9112 §2.2).
            .ignore_invalid_headers(false)
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
            // Equal windows: the connection window already bounds in-flight data, so a smaller
            // stream window would only throttle single uploads.
            .initial_stream_window_size(1024 * 1024)
            .initial_connection_window_size(1024 * 1024)
            .max_frame_size(16384)
            .max_concurrent_streams(200)
            // With RFC 9113 §6.5.2's 32-byte-per-field overhead this also caps a header block at
            // ~512 fields (the HPACK half of CVE-2026-49975).
            .max_header_list_size(16 * 1024)
            // Per stream: bounds what a peer holding its window shut can pin (the other half of
            // CVE-2026-49975) — 12.5 MiB per connection here vs. ~78 MiB at hyper's default.
            .max_send_buf_size(64 * 1024)
            // `keep_alive_timeout` does nothing without an interval; a silent peer would
            // otherwise hold its connection permit forever.
            .keep_alive_interval($crate::server::REQUEST_TIMEOUT)
            .keep_alive_timeout($crate::server::REQUEST_TIMEOUT);
        // RFC 8441: lets the app's `WebSocketUpgrade` accept WebSocket-over-HTTP/2 requests.
        let _ = tuned.enable_connect_protocol();
    }};
}

#[cfg(feature = "http1")]
pub(crate) use tune_http1;
#[cfg(feature = "http2")]
pub(crate) use tune_http2;
