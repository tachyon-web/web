//! HTTPS endpoints: certificate selection, published certificate metadata, redirects, and
//! TLS-specific limits.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tachyon_web::tls::{KeyAlgorithm, Tls};
use tachyon_web::{Error, Limits, Server, ServerInfo};
use tokio::net::TcpListener;

use crate::common::tls_client;

/// Accepts any certificate, but verifies handshake signatures and offers only `schemes` — the
/// shape of a pinning client, which checks the key itself rather than a CA chain.
#[derive(Debug)]
struct OfferOnly(Vec<SignatureScheme>);

impl ServerCertVerifier for OfferOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.clone()
    }
}

fn algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
}

/// The leaf certificate a client offering only `schemes` is served.
async fn served_leaf(addr: std::net::SocketAddr, schemes: Vec<SignatureScheme>) -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(OfferOnly(schemes)))
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake");
    tls.get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .expect("peer certificate")
        .to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

/// Starts `server` and waits until its endpoints have been published.
async fn start(server: Server) -> (ServerInfo, tokio::task::JoinHandle<Result<(), Error>>) {
    let info = server.info();
    let task = tokio::spawn(server.serve().into_future());
    for _ in 0..500 {
        if !info.endpoints().is_empty() {
            return (info, task);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the server published no endpoint");
}

/// Each client gets the first certificate, in configured order, it can verify — and what it
/// gets is exactly what `ServerInfo` publishes, fingerprint for fingerprint.
#[tokio::test]
async fn each_client_gets_the_first_certificate_it_can_verify() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let tls = Tls::new()
        .domains(["localhost"])
        .self_signed(KeyAlgorithm::EcdsaP256)
        .self_signed(KeyAlgorithm::MlDsa65)
        .self_signed(KeyAlgorithm::EcdsaP521);
    let (info, task) = start(Server::new(Router::new()).https(listener, tls)).await;

    let published = |alg| {
        info.certificates()
            .into_iter()
            .find(|cert| cert.algorithm == Some(alg))
            .expect("published certificate")
    };
    let cases = [
        (
            vec![
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::ML_DSA_65,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ],
            KeyAlgorithm::EcdsaP256,
        ),
        (vec![SignatureScheme::ML_DSA_65], KeyAlgorithm::MlDsa65),
        (
            vec![SignatureScheme::ECDSA_NISTP521_SHA512],
            KeyAlgorithm::EcdsaP521,
        ),
    ];
    for (offered, expected) in cases {
        let leaf = served_leaf(addr, offered).await;
        let cert = published(expected);
        assert_eq!(sha256(&leaf), cert.sha256, "{expected:?}");
        assert_eq!(cert.names, ["localhost"]);
        assert_eq!(
            cert.endpoints,
            [format!("https://localhost:{}", addr.port())]
        );
    }
    task.abort();
}

/// The TLS domains become the host allow-list, and the redirect listener only ever points
/// at one of them.
#[tokio::test]
async fn domains_bound_the_hosts_served_and_redirected_to() {
    let https = TcpListener::bind("127.0.0.1:0").await.expect("bind https");
    let redirect = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect");
    let (https_addr, redirect_addr) = (https.local_addr().unwrap(), redirect.local_addr().unwrap());
    let tls = Tls::new()
        .domains(["localhost"])
        .self_signed(KeyAlgorithm::EcdsaP384);
    let server = Server::new(Router::new().route("/", get(|| async { "ok" })))
        .https(https, tls)
        .redirect(redirect);
    let (_, task) = start(server).await;

    let by_name = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve("localhost", https_addr)
        .build()
        .unwrap();
    let ok = by_name
        .get(format!("https://localhost:{}/", https_addr.port()))
        .send()
        .await
        .expect("request");
    assert_eq!(ok.status(), 200);
    let misdirected = tls_client()
        .get(format!("https://{https_addr}/"))
        .header("host", "evil.example")
        .send()
        .await
        .expect("request");
    assert_eq!(misdirected.status(), 421);

    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let path = format!("/{:x}?q=1", rand::random::<u64>());
    let moved = no_follow
        .get(format!("http://{redirect_addr}{path}"))
        .header("host", "evil.example")
        .send()
        .await
        .expect("request");
    assert_eq!(moved.status(), 308);
    assert_eq!(
        moved.headers()["location"],
        format!("https://localhost:{}{path}", https_addr.port()).as_str()
    );
    task.abort();
}

/// `max_tls_handshakes` bounds handshakes in flight, not live connections: with one permit,
/// two clients holding open connections are both served.
#[tokio::test]
async fn the_handshake_permit_is_released_once_a_handshake_completes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("https://{}/", listener.local_addr().unwrap());
    let tls = Tls::new()
        .domains(["127.0.0.1"])
        .self_signed(KeyAlgorithm::EcdsaP256);
    let server = Server::new(Router::new().route("/", get(|| async { "ok" })))
        .limits(Limits::default().max_tls_handshakes(1))
        .https(listener, tls);
    let (_, task) = start(server).await;

    let clients = [tls_client(), tls_client()];
    for client in &clients {
        assert_eq!(
            client.get(&url).send().await.expect("request").status(),
            200
        );
    }
    task.abort();
}

/// Graceful shutdown stops every TLS-side transport — HTTPS, the redirect listener and, with
/// `http3`, the QUIC endpoint — and resolves `Ok` once their connections close.
#[tokio::test]
async fn graceful_shutdown_stops_every_tls_transport() {
    let https = TcpListener::bind("127.0.0.1:0").await.expect("bind https");
    let redirect = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect");
    let url = format!("https://{}/", https.local_addr().unwrap());
    let tls = Tls::new()
        .domains(["127.0.0.1"])
        .self_signed(KeyAlgorithm::EcdsaP256);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(
        Server::new(Router::new().route("/", get(|| async { "ok" })))
            .https(https, tls)
            .redirect(redirect)
            .serve()
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .into_future(),
    );

    let client = tls_client();
    assert_eq!(
        client.get(&url).send().await.expect("request").status(),
        200
    );
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server returns once its connections close")
        .unwrap()
        .expect("a graceful stop is not an error");
    assert!(client.get(&url).send().await.is_err());
}

/// A failed bind fails the start, and releases every listener bound before it.
#[tokio::test]
async fn a_failed_bind_fails_the_start_and_frees_the_other_ports() {
    let taken = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let free = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let free_addr = free.local_addr().unwrap();
    drop(free);

    let tls = Tls::new()
        .domains(["localhost"])
        .self_signed(KeyAlgorithm::EcdsaP256);
    let started = Server::new(Router::new())
        .redirect(free_addr)
        .https(taken.local_addr().unwrap(), tls)
        .serve()
        .await;
    assert!(matches!(started, Err(Error::Bind { .. })), "{started:?}");
    TcpListener::bind(free_addr)
        .await
        .expect("the redirect port was left bound");
}

/// Browsers only try HTTP/3 once told to: every HTTPS response advertises it.
#[cfg(feature = "http3")]
#[tokio::test]
async fn https_responses_advertise_http3() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let tls = Tls::new()
        .domains(["127.0.0.1"])
        .self_signed(KeyAlgorithm::EcdsaP256);
    let (info, task) =
        start(Server::new(Router::new().route("/", get(|| async { "ok" }))).https(listener, tls))
            .await;

    assert!(info.endpoints().iter().all(|endpoint| endpoint.http3));
    let response = tls_client()
        .get(format!("https://{addr}/"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        response.headers()["alt-svc"],
        format!("h3=\":{}\"; ma=86400", addr.port()).as_str()
    );
    task.abort();
}
