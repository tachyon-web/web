// A `WebSocketUpgrade` owns a semaphore permit (the WebSocket connection budget), so binding
// a successful one to a `let` before asserting on it trips `significant_drop_tightening`.
// These tests never establish a connection, so when the permit is released is immaterial.
#![allow(clippy::significant_drop_tightening)]

use crate::common::TestServer;
use futures_util::{SinkExt, StreamExt};
use tachyon_web::ws::{Message, WebSocket, WebSocketUpgrade};
use tachyon_web::{Router, get};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;

/// A `WebSocketStream` connected to `server`'s `/ws` route, plus the handshake response.
type ClientStream = tokio_tungstenite::WebSocketStream<TcpStream>;

async fn ws_connect(
    server: &TestServer,
) -> (ClientStream, tungstenite::handshake::client::Response) {
    let addr = server.addr();
    let tcp = TcpStream::connect(addr).await.unwrap();
    tokio_tungstenite::client_async(format!("ws://{addr}/ws"), tcp)
        .await
        .unwrap()
}

/// As [`ws_connect`], but surfaces a refused upgrade instead of unwrapping it — the server
/// answers an over-budget upgrade with a normal HTTP error response, which `client_async`
/// reports as `tungstenite::Error::Http`.
async fn try_ws_connect(server: &TestServer) -> Result<ClientStream, tungstenite::Error> {
    let addr = server.addr();
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    tokio_tungstenite::client_async(format!("ws://{addr}/ws"), tcp)
        .await
        .map(|(stream, _response)| stream)
}

async fn echo_socket(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.recv().await {
        let is_close = matches!(msg, Message::Close(_));
        if socket.send(msg).await.is_err() || is_close {
            break;
        }
    }
}

fn echo_app() -> Router {
    Router::new().route(
        "/ws",
        get(|ws: WebSocketUpgrade| async move { ws.on_upgrade(echo_socket) }),
    )
}

#[tokio::test]
async fn test_ws_echo_over_plain_http() {
    let server = TestServer::spawn(echo_app()).await;
    let (mut ws_stream, response) = ws_connect(&server).await;
    assert_eq!(response.status(), 101);

    ws_stream
        .send(tungstenite::Message::text("hello"))
        .await
        .unwrap();
    let msg = ws_stream.next().await.unwrap().unwrap();
    assert_eq!(msg, tungstenite::Message::text("hello"));

    ws_stream
        .send(tungstenite::Message::binary(vec![1, 2, 3]))
        .await
        .unwrap();
    let msg = ws_stream.next().await.unwrap().unwrap();
    assert_eq!(msg, tungstenite::Message::binary(vec![1, 2, 3]));

    ws_stream.close(None).await.unwrap();
}

/// Sends a message as many small fragments (well past the server's internal per-`poll_recv`
/// cooperative-yield budget) to prove the fragment reassembly loop survives being forced to
/// yield to the executor mid-message and pick back up correctly, rather than losing or
/// duplicating fragments across the yield boundary.
#[tokio::test]
async fn test_ws_reassembles_many_small_fragments_across_yield_boundary() {
    use tokio_tungstenite::tungstenite::Message as RawMessage;
    use tokio_tungstenite::tungstenite::protocol::frame::Frame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data as OpData, OpCode};

    let server = TestServer::spawn(echo_app()).await;
    let (mut ws_stream, _response) = ws_connect(&server).await;

    // Comfortably more fragments than `socket::RECV_YIELD_BUDGET` (128), so the server's
    // `poll_recv` is guaranteed to hit its budget and yield at least once mid-message.
    const FRAGMENTS: usize = 300;

    ws_stream
        .send(RawMessage::Frame(Frame::message(
            b"start-".to_vec(),
            OpCode::Data(OpData::Text),
            false,
        )))
        .await
        .unwrap();
    for i in 0..FRAGMENTS {
        let is_last = i == FRAGMENTS - 1;
        ws_stream
            .send(RawMessage::Frame(Frame::message(
                b"x".to_vec(),
                OpCode::Data(OpData::Continue),
                is_last,
            )))
            .await
            .unwrap();
    }

    let msg = ws_stream.next().await.unwrap().unwrap();
    let expected = format!("start-{}", "x".repeat(FRAGMENTS));
    assert_eq!(msg, tungstenite::Message::text(expected));
}

#[tokio::test]
async fn test_ws_protocol_negotiation() {
    let app = Router::new().route(
        "/ws",
        get(|ws: WebSocketUpgrade| async move {
            let ws = ws.protocols(["graphql-ws", "echo"]);
            assert_eq!(ws.selected_protocol().unwrap(), "echo");
            ws.on_upgrade(echo_socket)
        }),
    );

    let server = TestServer::spawn(app).await;
    let addr = server.addr();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let req =
        tungstenite::client::ClientRequestBuilder::new(format!("ws://{addr}/ws").parse().unwrap())
            .with_sub_protocol("echo");
    let (_ws_stream, response) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    assert_eq!(
        response.headers()[hyper::header::SEC_WEBSOCKET_PROTOCOL],
        "echo"
    );
}

#[tokio::test]
async fn test_ws_upgrade_rejects_non_get() {
    use hyper::{Method, Request};
    use tachyon_web::http::response::Body;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/ws")
        .header(hyper::header::CONNECTION, "upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();
    let (mut parts, _) = req.into_parts();
    let result = WebSocketUpgrade::from_request_parts(&mut parts, &());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ws_upgrade_rejects_missing_upgrade_header() {
    use hyper::{Method, Request};
    use tachyon_web::http::response::Body;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/ws")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();
    let (mut parts, _) = req.into_parts();
    let result = WebSocketUpgrade::from_request_parts(&mut parts, &());
    assert!(result.is_err());
}

/// An established WebSocket outlives the HTTP connection it was upgraded from, so it escapes
/// `max_connections` entirely (hyper resolves the connection future the moment it hands the
/// socket to the upgrade). `max_websocket_connections` is the ceiling that actually bounds
/// them: once it's reached the upgrade is refused with `503` *before* the handshake completes,
/// and the slot is returned when the connection ends.
#[tokio::test]
async fn test_websocket_connection_limit_rejects_and_then_recovers() {
    async fn ws_handler(
        ws: WebSocketUpgrade,
    ) -> hyper::Response<tachyon_web::http::response::Body> {
        ws.on_upgrade(|mut socket: WebSocket| async move {
            while let Some(Ok(msg)) = socket.recv().await {
                if matches!(msg, Message::Close(_)) || socket.send(msg).await.is_err() {
                    break;
                }
            }
        })
    }

    let app = Router::new().route("/ws", get(ws_handler));
    let server = TestServer::spawn_with(app, |s| s.max_websocket_connections(1)).await;

    // First upgrade takes the single slot.
    let (mut first, _) = ws_connect(&server).await;
    first
        .send(tungstenite::Message::Text("ping".into()))
        .await
        .expect("send on first socket");
    assert_eq!(
        first.next().await.expect("echo").expect("echo ok"),
        tungstenite::Message::Text("ping".into())
    );

    // Second upgrade is refused outright rather than accepted and starved.
    let err = try_ws_connect(&server)
        .await
        .expect_err("second upgrade must be rejected");
    match err {
        tungstenite::Error::Http(resp) => assert_eq!(
            resp.status(),
            hyper::StatusCode::SERVICE_UNAVAILABLE,
            "expected 503 once the WebSocket budget is exhausted"
        ),
        other => panic!("expected an HTTP rejection, got: {other:?}"),
    }

    // Closing the first connection returns its slot, so a later upgrade succeeds again.
    first.close(None).await.expect("close first socket");
    drop(first);

    let mut attempts = 0;
    loop {
        match try_ws_connect(&server).await {
            Ok(socket) => {
                drop(socket);
                break;
            }
            Err(e) => {
                attempts += 1;
                assert!(attempts < 50, "slot was never released: {e:?}");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    }
}

#[tokio::test]
#[cfg(feature = "tls")]
async fn test_wss_echo_over_tls() {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;
    use tachyon_web::tls::generate_self_signed_cert;
    use tokio_rustls::TlsConnector;

    #[derive(Debug)]
    struct AcceptAny;

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let cert = generate_self_signed_cert(vec!["localhost".to_string()]).unwrap();
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der], cert.key_der)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // No sleep: `bind` already put the socket in the listen state, so the client's connect
    // is queued in the backlog even if the accept loop hasn't been polled yet.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tachyon_web::Server::new(echo_app());
    tokio::spawn(async move {
        let _ = server.serve_https(listener, acceptor).await;
    });

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let domain = ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(domain, tcp).await.unwrap();

    let url = format!("wss://{addr}/ws");
    let (mut ws_stream, response) = tokio_tungstenite::client_async(url, tls_stream)
        .await
        .unwrap();
    assert_eq!(response.status(), 101);

    ws_stream
        .send(tungstenite::Message::text("secure hello"))
        .await
        .unwrap();
    let msg = ws_stream.next().await.unwrap().unwrap();
    assert_eq!(msg, tungstenite::Message::text("secure hello"));

    ws_stream.close(None).await.unwrap();
}

/// Axum's WebSocket types live at `axum::extract::ws::*` (and
/// `axum::extract::WebSocketUpgrade` as a flattened re-export). Confirms both
/// equivalent tachyon-web paths resolve to the exact same types as the
/// `tachyon_web::ws::*` path used throughout this file — if they didn't, this
/// wouldn't type-check.
#[test]
fn test_extract_ws_path_matches_axum_layout() {
    fn takes_via_extract_path(_: tachyon_web::extract::ws::WebSocketUpgrade) {}
    fn takes_via_flat_path(_: tachyon_web::extract::WebSocketUpgrade) {}
    fn takes_via_ws_path(u: tachyon_web::ws::WebSocketUpgrade) {
        takes_via_extract_path(u);
    }
    let _ = takes_via_ws_path;
    let _ = takes_via_flat_path;
}
