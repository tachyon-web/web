//! WebSocket support (RFC 6455), mirroring Axum's `extract::ws` API.
//!
//! Enabled via the `ws` feature. WebSocket upgrades happen over an already-accepted
//! HTTP/1.1 connection — for TLS, that connection is already decrypted by the time it
//! reaches the router, so `wss://` works automatically: bind with [`crate::Server::serve_https`]
//! (or any of the other TLS entry points) exactly as you would for plain `ws://` with
//! [`crate::Server::serve_http`]. There is nothing protocol-specific to configure.
//!
//! With the `http2` feature enabled, [`WebSocketUpgrade`] also accepts the RFC 8441 bootstrap:
//! an HTTP/2 extended `CONNECT` request with a `:protocol` pseudo-header of `websocket`. Once
//! the tunnel is established the wire format is identical RFC 6455 framing either way, so
//! handlers don't need to care which transport a given [`WebSocket`] came from. HTTP/3 does not
//! define a WebSocket bootstrap and is not supported.
//!
//! The `permessage-deflate` extension (RFC 7692) is negotiated automatically whenever the client
//! offers it — disable it with [`WebSocketUpgrade::deflate`] or tune it with
//! [`WebSocketUpgrade::deflate_config`].
//!
//! # Example
//!
//! ```rust,no_run
//! use tachyon_web::ws::{WebSocket, WebSocketUpgrade};
//! use tachyon_web::http::Response;
//! use tachyon_web::http::response::Body;
//! use tachyon_web::{Router, get};
//!
//! async fn handler(ws: WebSocketUpgrade) -> Response<Body> {
//!     ws.on_upgrade(handle_socket)
//! }
//!
//! async fn handle_socket(mut socket: WebSocket) {
//!     while let Some(Ok(msg)) = socket.recv().await {
//!         if socket.send(msg).await.is_err() {
//!             break;
//!         }
//!     }
//! }
//!
//! let _app: Router<()> = Router::new().route("/ws", get(handler));
//! ```

mod compat;
mod deflate;
mod socket;

use crate::http::error::Error;
use crate::http::response::Body;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Response, StatusCode};
use std::borrow::Cow;
use std::future::Future;
use tungstenite::handshake::derive_accept_key;

pub use deflate::DeflateConfig;
pub use socket::{Message, WebSocket};
pub use tungstenite::protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode};

/// Extractor for establishing a WebSocket connection out of an HTTP/1.1 (or, with the `http2`
/// feature, HTTP/2 extended-`CONNECT`) request.
///
/// See the [module docs](self) for an example.
#[must_use]
pub struct WebSocketUpgrade<F = DefaultOnFailedUpgrade> {
    config: WebSocketConfig,
    protocol: Option<HeaderValue>,
    kind: UpgradeKind,
    on_upgrade: hyper::upgrade::OnUpgrade,
    on_failed_upgrade: F,
    sec_websocket_protocol: Vec<HeaderValue>,
    origin: Option<HeaderValue>,
    deflate_offers: Vec<deflate::Offer>,
    deflate_enabled: bool,
    deflate_config: DeflateConfig,
}

/// Which bootstrap produced this upgrade, and the bits of state each one needs to finish the
/// handshake: HTTP/1.1 needs the client's key to derive `Sec-WebSocket-Accept`; the RFC 8441
/// HTTP/2 path needs nothing extra (there is no accept-key concept — see RFC 8441 §5).
enum UpgradeKind {
    Http1 {
        sec_websocket_key: HeaderValue,
    },
    #[cfg(feature = "http2")]
    Http2,
}

impl<F> std::fmt::Debug for WebSocketUpgrade<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketUpgrade")
            .field("protocol", &self.protocol)
            .field("sec_websocket_protocol", &self.sec_websocket_protocol)
            .finish_non_exhaustive()
    }
}

impl<F> WebSocketUpgrade<F> {
    /// Read buffer capacity. The default value is 128 KiB.
    pub const fn read_buffer_size(mut self, size: usize) -> Self {
        self.config.read_buffer_size = size;
        self
    }

    /// The target minimum size of the write buffer to reach before writing the data
    /// to the underlying stream. The default value is 128 KiB.
    ///
    /// If set to `0`, each message is eagerly written to the underlying stream.
    pub const fn write_buffer_size(mut self, size: usize) -> Self {
        self.config.write_buffer_size = size;
        self
    }

    /// The max size of the write buffer in bytes. The default value is unlimited.
    pub const fn max_write_buffer_size(mut self, max: usize) -> Self {
        self.config.max_write_buffer_size = max;
        self
    }

    /// Set the maximum message size (defaults to 64 MiB).
    pub const fn max_message_size(mut self, max: usize) -> Self {
        self.config.max_message_size = Some(max);
        self
    }

    /// Set the maximum frame size (defaults to 16 MiB).
    pub const fn max_frame_size(mut self, max: usize) -> Self {
        self.config.max_frame_size = Some(max);
        self
    }

    /// Allow the server to accept unmasked frames (defaults to `false`).
    pub const fn accept_unmasked_frames(mut self, accept: bool) -> Self {
        self.config.accept_unmasked_frames = accept;
        self
    }

    /// Enable or disable offering the `permessage-deflate` extension (RFC 7692) to the client.
    /// Enabled by default; when the client doesn't offer it, this has no effect either way.
    pub const fn deflate(mut self, enabled: bool) -> Self {
        self.deflate_enabled = enabled;
        self
    }

    /// Tune `permessage-deflate` parameters — context takeover and window size. See
    /// [`DeflateConfig`]. No effect if [`deflate`](Self::deflate) is disabled or the client
    /// didn't offer the extension.
    pub const fn deflate_config(mut self, config: DeflateConfig) -> Self {
        self.deflate_config = config;
        self
    }

    /// Set the server's supported subprotocols, in decreasing order of preference.
    ///
    /// If any of them matches one the client requested (via `Sec-WebSocket-Protocol`),
    /// the response includes a `Sec-WebSocket-Protocol` header naming it.
    pub fn protocols<I>(mut self, protocols: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Cow<'static, str>>,
    {
        self.protocol = protocols.into_iter().map(Into::into).find_map(|proto| {
            let value = match proto {
                Cow::Owned(s) => HeaderValue::from_str(&s).ok()?,
                Cow::Borrowed(s) => HeaderValue::from_static(s),
            };
            self.sec_websocket_protocol
                .contains(&value)
                .then_some(value)
        });
        self
    }

    /// The WebSocket subprotocols requested by the client, via `Sec-WebSocket-Protocol`.
    pub fn requested_protocols(&self) -> impl Iterator<Item = &HeaderValue> {
        self.sec_websocket_protocol.iter()
    }

    /// Return the selected WebSocket subprotocol, if [`protocols`](Self::protocols) matched one.
    #[must_use]
    pub const fn selected_protocol(&self) -> Option<&HeaderValue> {
        self.protocol.as_ref()
    }

    /// The `Origin` header sent by the client, if any.
    ///
    /// Present for browser clients (and absent for most non-browser WebSocket clients).
    /// Exposed for handlers that want to make their own origin decision inline.
    #[must_use]
    pub const fn origin(&self) -> Option<&HeaderValue> {
        self.origin.as_ref()
    }

    /// Provide a callback invoked if completing the (background) connection upgrade fails.
    ///
    /// By default, failures are silently ignored.
    pub fn on_failed_upgrade<C>(self, callback: C) -> WebSocketUpgrade<C>
    where
        C: OnFailedUpgrade,
    {
        WebSocketUpgrade {
            config: self.config,
            protocol: self.protocol,
            kind: self.kind,
            on_upgrade: self.on_upgrade,
            on_failed_upgrade: callback,
            sec_websocket_protocol: self.sec_websocket_protocol,
            origin: self.origin,
            deflate_offers: self.deflate_offers,
            deflate_enabled: self.deflate_enabled,
            deflate_config: self.deflate_config,
        }
    }

    /// Finalize the upgrade, running `callback` with the [`WebSocket`] once the underlying
    /// connection has actually switched protocols.
    ///
    /// The returned [`Response`] must be returned from the handler unmodified for the
    /// upgrade to complete.
    #[must_use = "the response from `on_upgrade` must be returned from the handler"]
    pub fn on_upgrade<C, Fut>(self, callback: C) -> Response<Body>
    where
        C: FnOnce(WebSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
        F: OnFailedUpgrade,
    {
        let on_upgrade = self.on_upgrade;
        let config = self.config;
        let on_failed_upgrade = self.on_failed_upgrade;
        let protocol = self.protocol.clone();
        let agreement = self
            .deflate_enabled
            .then(|| deflate::negotiate(&self.deflate_offers, self.deflate_config))
            .flatten();

        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(err) => {
                    on_failed_upgrade.call(Error::Internal(err.to_string()));
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(upgraded);
            let deflate = agreement.map(deflate::PerMessageDeflate::new);
            callback(WebSocket::new(io, protocol, config, deflate)).await;
        });

        let mut response = match self.kind {
            UpgradeKind::Http1 { sec_websocket_key } => Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::CONNECTION, HeaderValue::from_static("upgrade"))
                .header(header::UPGRADE, HeaderValue::from_static("websocket"))
                .header(
                    header::SEC_WEBSOCKET_ACCEPT,
                    derive_accept_key(sec_websocket_key.as_bytes()),
                )
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty())),
            #[cfg(feature = "http2")]
            UpgradeKind::Http2 => Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty())),
        };

        if let Some(protocol) = self.protocol {
            response
                .headers_mut()
                .insert(header::SEC_WEBSOCKET_PROTOCOL, protocol);
        }
        if let Some(agreement) = agreement {
            response.headers_mut().insert(
                header::SEC_WEBSOCKET_EXTENSIONS,
                deflate::agreement_header_value(agreement),
            );
        }
        response
    }
}

/// What to do when completing a WebSocket connection upgrade fails.
///
/// See [`WebSocketUpgrade::on_failed_upgrade`].
pub trait OnFailedUpgrade: Send + 'static {
    /// Handle the failure.
    fn call(self, error: Error);
}

impl<F> OnFailedUpgrade for F
where
    F: FnOnce(Error) + Send + 'static,
{
    fn call(self, error: Error) {
        self(error);
    }
}

/// The default [`OnFailedUpgrade`]: silently ignores the error.
#[non_exhaustive]
#[derive(Debug)]
pub struct DefaultOnFailedUpgrade;

impl OnFailedUpgrade for DefaultOnFailedUpgrade {
    fn call(self, _error: Error) {}
}

fn header_eq(headers: &HeaderMap, key: &HeaderName, value: &'static str) -> bool {
    headers
        .get(key)
        .is_some_and(|h| h.as_bytes().eq_ignore_ascii_case(value.as_bytes()))
}

/// Case-insensitive, allocation-free substring search — `value` is always a lowercase ASCII
/// literal at every call site, so a byte-window scan avoids `to_ascii_lowercase()`'s per-call
/// heap allocation on the WebSocket upgrade path.
fn header_contains(headers: &HeaderMap, key: &HeaderName, value: &'static str) -> bool {
    let Some(header) = headers.get(key) else {
        return false;
    };
    let haystack = header.as_bytes();
    let needle = value.as_bytes();
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

impl<S> crate::routing::extract::FromRequest<S> for WebSocketUpgrade<DefaultOnFailedUpgrade>
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request(req: hyper::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, _body) = req.into_parts();
        Self::from_request_parts(&mut parts, state)
    }
}

impl WebSocketUpgrade<DefaultOnFailedUpgrade> {
    /// Build a [`WebSocketUpgrade`] from request parts, validating the RFC 6455 handshake
    /// headers (or, for HTTP/2 with the `http2` feature enabled, the RFC 8441 extended-`CONNECT`
    /// bootstrap) and pulling the pending [`hyper::upgrade::OnUpgrade`] out of the extensions.
    ///
    /// # Errors
    ///
    /// Returns a rejection if this isn't a well-formed WebSocket upgrade request.
    pub fn from_request_parts<S>(parts: &mut Parts, _state: &S) -> Result<Self, Error> {
        #[cfg(feature = "http2")]
        if parts.version == hyper::Version::HTTP_2 {
            return Self::from_h2_request_parts(parts);
        }

        if parts.version > hyper::Version::HTTP_11 {
            return Err(Error::Rejection {
                status: StatusCode::UPGRADE_REQUIRED,
                message: "WebSocket upgrades require HTTP/1.1 (or HTTP/2 extended CONNECT, with the `http2` feature enabled)".to_string(),
            });
        }
        if parts.method != Method::GET {
            return Err(Error::Rejection {
                status: StatusCode::METHOD_NOT_ALLOWED,
                message: "Request method must be `GET`".to_string(),
            });
        }
        if !header_contains(&parts.headers, &header::CONNECTION, "upgrade") {
            return Err(Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: "`Connection` header did not include 'upgrade'".to_string(),
            });
        }
        if !header_eq(&parts.headers, &header::UPGRADE, "websocket") {
            return Err(Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: "`Upgrade` header did not include 'websocket'".to_string(),
            });
        }
        if !header_eq(&parts.headers, &header::SEC_WEBSOCKET_VERSION, "13") {
            return Err(Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: "`Sec-WebSocket-Version` header did not include '13'".to_string(),
            });
        }
        let sec_websocket_key = parts
            .headers
            .get(header::SEC_WEBSOCKET_KEY)
            .cloned()
            .ok_or_else(|| Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: "`Sec-WebSocket-Key` header missing".to_string(),
            })?;
        let on_upgrade = parts
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>()
            .ok_or_else(|| Error::Rejection {
                status: StatusCode::UPGRADE_REQUIRED,
                message: "Request couldn't be upgraded: no upgrade state was present".to_string(),
            })?;

        let sec_websocket_protocol = parse_sec_websocket_protocol(&parts.headers);
        let origin = parts.headers.get(header::ORIGIN).cloned();
        let deflate_offers = deflate::parse_offers(&parts.headers);

        Ok(Self {
            config: WebSocketConfig::default(),
            protocol: None,
            kind: UpgradeKind::Http1 { sec_websocket_key },
            on_upgrade,
            on_failed_upgrade: DefaultOnFailedUpgrade,
            sec_websocket_protocol,
            origin,
            deflate_offers,
            deflate_enabled: true,
            deflate_config: DeflateConfig::default(),
        })
    }

    /// The RFC 8441 bootstrap: an HTTP/2 extended `CONNECT` request (`:method: CONNECT`,
    /// `:protocol: websocket`). Unlike HTTP/1.1, there is no `Sec-WebSocket-Key`/`-Accept`
    /// handshake — HTTP/2 already requires a validated transport, so RFC 8441 §5 drops it.
    #[cfg(feature = "http2")]
    fn from_h2_request_parts(parts: &mut Parts) -> Result<Self, Error> {
        if parts.method != Method::CONNECT {
            return Err(Error::Rejection {
                status: StatusCode::UPGRADE_REQUIRED,
                message:
                    "WebSocket upgrades over HTTP/2 require the extended CONNECT method (RFC 8441)"
                        .to_string(),
            });
        }
        let is_websocket_protocol = parts
            .extensions
            .get::<hyper::ext::Protocol>()
            .is_some_and(|p| p.as_str().eq_ignore_ascii_case("websocket"));
        if !is_websocket_protocol {
            return Err(Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: "`:protocol` pseudo-header must be `websocket`".to_string(),
            });
        }
        if !header_eq(&parts.headers, &header::SEC_WEBSOCKET_VERSION, "13") {
            return Err(Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                message: "`Sec-WebSocket-Version` header did not include '13'".to_string(),
            });
        }
        let on_upgrade = parts
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>()
            .ok_or_else(|| Error::Rejection {
                status: StatusCode::UPGRADE_REQUIRED,
                message: "Request couldn't be upgraded: no upgrade state was present".to_string(),
            })?;

        let sec_websocket_protocol = parse_sec_websocket_protocol(&parts.headers);
        let origin = parts.headers.get(header::ORIGIN).cloned();
        let deflate_offers = deflate::parse_offers(&parts.headers);

        Ok(Self {
            config: WebSocketConfig::default(),
            protocol: None,
            kind: UpgradeKind::Http2,
            on_upgrade,
            on_failed_upgrade: DefaultOnFailedUpgrade,
            sec_websocket_protocol,
            origin,
            deflate_offers,
            deflate_enabled: true,
            deflate_config: DeflateConfig::default(),
        })
    }
}

fn parse_sec_websocket_protocol(headers: &HeaderMap) -> Vec<HeaderValue> {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .flat_map(|val| val.as_bytes().split(|&b| b == b','))
        .filter_map(|proto| HeaderValue::from_bytes(proto.trim_ascii()).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hyper::Request;

    /// Builds a well-formed WebSocket-upgrade `Parts`, with a placeholder
    /// `OnUpgrade` (this never drives a real upgrade in these tests, it only
    /// needs to satisfy `WebSocketUpgrade::from_request_parts`'s extraction).
    fn make_ws_parts() -> Parts {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/ws")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();
        let on_upgrade = hyper::upgrade::on(&mut req);
        let (mut parts, ()) = req.into_parts();
        let _ = parts.extensions.insert(on_upgrade);
        parts
    }

    #[test]
    fn rejects_http2_and_above() {
        let mut parts = make_ws_parts();
        parts.version = hyper::Version::HTTP_2;
        let err = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap_err();
        assert!(matches!(
            err,
            Error::Rejection {
                status: StatusCode::UPGRADE_REQUIRED,
                ..
            }
        ));
    }

    #[test]
    fn rejects_non_get_method() {
        let mut parts = make_ws_parts();
        parts.method = Method::POST;
        let err = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap_err();
        assert!(matches!(
            err,
            Error::Rejection {
                status: StatusCode::METHOD_NOT_ALLOWED,
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_connection_upgrade_token() {
        let mut parts = make_ws_parts();
        let _ = parts
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        let err = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap_err();
        assert!(matches!(
            err,
            Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                ..
            }
        ));
    }

    #[test]
    fn rejects_wrong_upgrade_header_value() {
        let mut parts = make_ws_parts();
        let _ = parts
            .headers
            .insert(header::UPGRADE, HeaderValue::from_static("h2c"));
        let err = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap_err();
        assert!(matches!(
            err,
            Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                ..
            }
        ));
    }

    #[test]
    fn rejects_wrong_sec_websocket_version() {
        let mut parts = make_ws_parts();
        let _ = parts
            .headers
            .insert(header::SEC_WEBSOCKET_VERSION, HeaderValue::from_static("8"));
        let err = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap_err();
        assert!(matches!(
            err,
            Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_sec_websocket_key() {
        let mut parts = make_ws_parts();
        let _ = parts.headers.remove(header::SEC_WEBSOCKET_KEY);
        let err = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap_err();
        assert!(matches!(
            err,
            Error::Rejection {
                status: StatusCode::BAD_REQUEST,
                ..
            }
        ));
    }

    #[test]
    fn rejects_when_no_upgrade_state_is_present() {
        // Built directly (not via `make_ws_parts`) so no `hyper::upgrade::on(&mut req)` was
        // ever called — there's nothing in extensions for `from_request_parts` to remove.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/ws")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();
        let (mut parts, ()) = req.into_parts();
        let err = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap_err();
        assert!(matches!(
            err,
            Error::Rejection {
                status: StatusCode::UPGRADE_REQUIRED,
                ..
            }
        ));
    }

    #[test]
    fn builder_methods_configure_the_underlying_websocket_config() {
        let mut parts = make_ws_parts();
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &())
            .unwrap()
            .read_buffer_size(1024)
            .write_buffer_size(2048)
            .max_write_buffer_size(4096)
            .max_message_size(8192)
            .max_frame_size(16384)
            .accept_unmasked_frames(true);

        assert_eq!(upgrade.config.read_buffer_size, 1024);
        assert_eq!(upgrade.config.write_buffer_size, 2048);
        assert_eq!(upgrade.config.max_write_buffer_size, 4096);
        assert_eq!(upgrade.config.max_message_size, Some(8192));
        assert_eq!(upgrade.config.max_frame_size, Some(16384));
        assert!(upgrade.config.accept_unmasked_frames);
    }

    #[test]
    fn protocols_selects_a_requested_subprotocol_the_server_also_supports() {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/ws")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .header(header::SEC_WEBSOCKET_PROTOCOL, "chat, superchat")
            .body(())
            .unwrap();
        let on_upgrade = hyper::upgrade::on(&mut req);
        let (mut parts, ()) = req.into_parts();
        let _ = parts.extensions.insert(on_upgrade);

        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap();
        let requested: Vec<_> = upgrade
            .requested_protocols()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(requested, vec!["chat", "superchat"]);

        let upgrade = upgrade.protocols(["superchat"]);
        assert_eq!(
            upgrade.selected_protocol().unwrap().to_str().unwrap(),
            "superchat"
        );
    }

    #[test]
    fn protocols_selects_none_when_nothing_matches() {
        let mut parts = make_ws_parts();
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &())
            .unwrap()
            .protocols(["some-protocol-the-client-never-asked-for"]);
        assert!(upgrade.selected_protocol().is_none());
    }

    #[test]
    fn origin_getter_reflects_the_request_header() {
        let mut parts = make_ws_parts();
        let _ = parts.headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(
            upgrade.origin().unwrap().to_str().unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn origin_getter_is_none_when_absent() {
        let mut parts = make_ws_parts();
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap();
        assert!(upgrade.origin().is_none());
    }

    #[test]
    fn websocket_upgrade_debug_does_not_panic() {
        let mut parts = make_ws_parts();
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap();
        assert!(format!("{upgrade:?}").contains("WebSocketUpgrade"));
    }

    #[test]
    fn on_failed_upgrade_swaps_the_callback_type_and_preserves_config() {
        let mut parts = make_ws_parts();
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &())
            .unwrap()
            .max_message_size(1234)
            .on_failed_upgrade(|_err: Error| {});
        assert_eq!(upgrade.config.max_message_size, Some(1234));
    }

    #[test]
    fn default_on_failed_upgrade_silently_ignores_the_error() {
        // Just proves `call` doesn't panic — this is the "silently ignore" default.
        DefaultOnFailedUpgrade.call(Error::Internal("boom".to_string()));
    }

    #[test]
    fn deflate_is_offered_by_default_and_can_be_disabled() {
        let mut parts = make_ws_parts();
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap();
        assert!(upgrade.deflate_enabled);
        let upgrade = upgrade.deflate(false);
        assert!(!upgrade.deflate_enabled);
    }

    #[test]
    fn parses_permessage_deflate_offer_from_request() {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/ws")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .header(
                header::SEC_WEBSOCKET_EXTENSIONS,
                "permessage-deflate; client_max_window_bits",
            )
            .body(())
            .unwrap();
        let on_upgrade = hyper::upgrade::on(&mut req);
        let (mut parts, ()) = req.into_parts();
        let _ = parts.extensions.insert(on_upgrade);

        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(upgrade.deflate_offers.len(), 1);
        let agreement = deflate::negotiate(&upgrade.deflate_offers, upgrade.deflate_config);
        assert!(agreement.is_some());
    }
}
