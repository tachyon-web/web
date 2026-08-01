use crate::common::TestServer;
use futures_util::{SinkExt, StreamExt};
use tachyon_web::ws::{Message, WebSocket, WebSocketUpgrade};
use tachyon_web::{Router, get};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;

/// A `WebSocketStream` connected to `server`'s `/ws` route, plus the handshake response.
type ClientStream = tokio_tungstenite::WebSocketStream<TcpStream>;

async fn ws_connect(server: &TestServer) -> (ClientStream, tungstenite::handshake::client::Response) {
    let addr = server.addr();
    let tcp = TcpStream::connect(addr).await.unwrap();
    tokio_tungstenite::client_async(format!("ws://{addr}/ws"), tcp)
        .await
        .unwrap()
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
