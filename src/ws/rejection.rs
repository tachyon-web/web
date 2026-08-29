//! WebSocket-specific rejections, matching `axum::extract::ws::rejection`.
//!
//! Each leaf here is a fixed-status, fixed-message unit struct — mirroring axum's own
//! `__define_rejection!`-generated shape exactly, since every WebSocket handshake failure
//! (unlike, say, a `Path<T>` deserialize failure) has message text that's always the same
//! regardless of the request that triggered it. [`WebSocketUpgradeRejection`] additionally
//! carries two variants axum has no equivalent for — [`HttpVersionNotSupported`] (this
//! crate's stricter HTTP-version gate ahead of the RFC 8441 bootstrap) and
//! [`ConnectionLimitReached`] (`Server::max_websocket_connections`, a budget axum's own
//! `WebSocketUpgrade` has no concept of) — both additive, so code matching on the axum-shared
//! variants still ports unchanged.

use crate::http::response::{IntoResponse, Response};
use hyper::StatusCode;

/// Defines a single WebSocket rejection leaf: a fixed-status, fixed-message unit struct.
macro_rules! ws_rejection {
    ($(#[$m:meta])* pub struct $name:ident => $status:ident, $body:literal) => {
        $(#[$m])*
        #[derive(Debug, Default, Clone, Copy)]
        #[non_exhaustive]
        pub struct $name;

        impl $name {
            /// The response body text used for this rejection.
            #[must_use]
            pub fn body_text(&self) -> String {
                $body.to_string()
            }

            /// The status code used for this rejection.
            #[must_use]
            pub const fn status(&self) -> StatusCode {
                StatusCode::$status
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($body)
            }
        }

        impl std::error::Error for $name {}

        impl IntoResponse for $name {
            fn into_response(self) -> Response {
                (StatusCode::$status, $body).into_response()
            }
        }
    };
}

/// Defines the composite rejection: an enum over every leaf, with
/// `IntoResponse`/`Display`/`From<Leaf>` all derived mechanically from the variant list.
macro_rules! ws_composite_rejection {
    ($(#[$m:meta])* pub enum $name:ident { $($variant:ident),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy)]
        #[non_exhaustive]
        pub enum $name {
            $(
                #[allow(missing_docs)]
                $variant($variant)
            ),+
        }

        impl $name {
            /// The response body text used for this rejection.
            #[must_use]
            pub fn body_text(&self) -> String {
                match self {
                    $(Self::$variant(inner) => inner.body_text()),+
                }
            }

            /// The status code used for this rejection.
            #[must_use]
            pub const fn status(&self) -> StatusCode {
                match self {
                    $(Self::$variant(inner) => inner.status()),+
                }
            }
        }

        impl IntoResponse for $name {
            fn into_response(self) -> Response {
                match self {
                    $(Self::$variant(inner) => inner.into_response()),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$variant(inner) => std::fmt::Display::fmt(inner, f)),+
                }
            }
        }

        impl std::error::Error for $name {}

        $(
            impl From<$variant> for $name {
                fn from(inner: $variant) -> Self {
                    Self::$variant(inner)
                }
            }
        )+
    };
}

ws_rejection! {
    /// The request method wasn't `GET` on an HTTP/1.1 handshake. Matches
    /// `axum::extract::ws::rejection::MethodNotGet`.
    pub struct MethodNotGet => METHOD_NOT_ALLOWED, "Request method must be `GET`"
}

ws_rejection! {
    /// The request method wasn't `CONNECT` on an RFC 8441 (HTTP/2) handshake. Matches
    /// `axum::extract::ws::rejection::MethodNotConnect`.
    pub struct MethodNotConnect => METHOD_NOT_ALLOWED, "Request method must be `CONNECT`"
}

ws_rejection! {
    /// The `Connection` header didn't include `upgrade`. Matches
    /// `axum::extract::ws::rejection::InvalidConnectionHeader`.
    pub struct InvalidConnectionHeader => BAD_REQUEST, "Connection header did not include 'upgrade'"
}

ws_rejection! {
    /// The `Upgrade` header didn't include `websocket`. Matches
    /// `axum::extract::ws::rejection::InvalidUpgradeHeader`.
    pub struct InvalidUpgradeHeader => BAD_REQUEST, "`Upgrade` header did not include 'websocket'"
}

ws_rejection! {
    /// The HTTP/2 extended-`CONNECT` `:protocol` pseudo-header wasn't `websocket`. Matches
    /// `axum::extract::ws::rejection::InvalidProtocolPseudoheader`.
    pub struct InvalidProtocolPseudoheader => BAD_REQUEST, "`:protocol` pseudo-header did not include 'websocket'"
}

ws_rejection! {
    /// `Sec-WebSocket-Version` wasn't `13`. Matches
    /// `axum::extract::ws::rejection::InvalidWebSocketVersionHeader`.
    pub struct InvalidWebSocketVersionHeader => BAD_REQUEST, "`Sec-WebSocket-Version` header did not include '13'"
}

ws_rejection! {
    /// `Sec-WebSocket-Key` was missing on an HTTP/1.1 handshake. Matches
    /// `axum::extract::ws::rejection::WebSocketKeyHeaderMissing`.
    pub struct WebSocketKeyHeaderMissing => BAD_REQUEST, "`Sec-WebSocket-Key` header missing"
}

ws_rejection! {
    /// There was no pending [`hyper::upgrade::OnUpgrade`] on the request — it can't be
    /// upgraded at all (e.g. it arrived over HTTP/1.0). Matches
    /// `axum::extract::ws::rejection::ConnectionNotUpgradable`.
    pub struct ConnectionNotUpgradable => UPGRADE_REQUIRED, "WebSocket request couldn't be upgraded since no upgrade state was present"
}

ws_rejection! {
    /// The request's HTTP version isn't supported for a WebSocket handshake.
    ///
    /// Neither HTTP/1.1 (the RFC 6455 bootstrap) nor, with the `http2` feature enabled, HTTP/2
    /// (the RFC 8441 extended-`CONNECT` bootstrap). Tachyon-only — axum has no equivalent,
    /// since axum treats every version above HTTP/1.1 as the HTTP/2 bootstrap unconditionally.
    pub struct HttpVersionNotSupported => UPGRADE_REQUIRED,
        "WebSocket upgrades require HTTP/1.1 (or HTTP/2 extended CONNECT, with the `http2` feature enabled)"
}

ws_rejection! {
    /// [`Server::max_websocket_connections`](crate::server::Server::max_websocket_connections)
    /// was reached. Tachyon-only — axum's `WebSocketUpgrade` has no built-in connection budget.
    pub struct ConnectionLimitReached => SERVICE_UNAVAILABLE, "WebSocket connection limit reached"
}

ws_composite_rejection! {
    /// Rejection for [`WebSocketUpgrade`](super::WebSocketUpgrade). Matches
    /// `axum::extract::ws::rejection::WebSocketUpgradeRejection`, plus two tachyon-only
    /// variants — see the module docs.
    pub enum WebSocketUpgradeRejection {
        MethodNotGet,
        MethodNotConnect,
        InvalidConnectionHeader,
        InvalidUpgradeHeader,
        InvalidProtocolPseudoheader,
        InvalidWebSocketVersionHeader,
        WebSocketKeyHeaderMissing,
        ConnectionNotUpgradable,
        HttpVersionNotSupported,
        ConnectionLimitReached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_rejection_status_and_body_match_its_into_response() {
        let rej = WebSocketKeyHeaderMissing;
        assert_eq!(rej.status(), StatusCode::BAD_REQUEST);
        assert_eq!(rej.body_text(), "`Sec-WebSocket-Key` header missing");
        assert_eq!(rej.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn composite_rejection_forwards_to_its_variant() {
        let rej = WebSocketUpgradeRejection::from(MethodNotGet);
        assert_eq!(rej.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(rej.body_text(), "Request method must be `GET`");
        assert_eq!(rej.to_string(), "Request method must be `GET`");
    }

    #[test]
    fn tachyon_only_variants_carry_their_own_status() {
        assert_eq!(
            WebSocketUpgradeRejection::from(HttpVersionNotSupported).status(),
            StatusCode::UPGRADE_REQUIRED
        );
        assert_eq!(
            WebSocketUpgradeRejection::from(ConnectionLimitReached).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
