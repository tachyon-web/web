//! ACME / Let's Encrypt integration.

use bytes::Bytes;
use hyper::{Request, StatusCode};
use tachyon_web::http::response::Body;
use tachyon_web::routing::Router;
use tachyon_web::tls::acme::{
    AcmeError, AcmeManager, AcmeResolver, get_challenge, register_challenge, unregister_challenge,
};

#[tokio::test]
async fn test_challenge_register_and_retrieve() {
    let token = "basic-token-aaa".to_string();
    let auth = "basic-auth-bbb".to_string();

    register_challenge(token.clone(), auth.clone());
    assert_eq!(get_challenge(&token), Some(auth),);

    unregister_challenge(&token);
    assert_eq!(get_challenge(&token), None);
}

#[tokio::test]
async fn test_challenge_overwrite() {
    let token = "overwrite-tok".to_string();

    register_challenge(token.clone(), "first-auth".to_string());
    register_challenge(token.clone(), "second-auth".to_string());

    assert_eq!(
        get_challenge(&token),
        Some("second-auth".to_string()),
        "second registration must overwrite the first"
    );
    unregister_challenge(&token);
}

#[tokio::test]
async fn test_challenge_unregister_nonexistent_is_noop() {
    unregister_challenge("this-token-does-not-exist");
    assert_eq!(get_challenge("this-token-does-not-exist"), None);
}

#[tokio::test]
async fn test_challenge_isolation() {
    let token_a = "isolation-tok-a".to_string();
    let token_b = "isolation-tok-b".to_string();

    register_challenge(token_a.clone(), "auth-a".to_string());
    register_challenge(token_b.clone(), "auth-b".to_string());

    assert_eq!(get_challenge(&token_a), Some("auth-a".to_string()));
    assert_eq!(get_challenge(&token_b), Some("auth-b".to_string()));

    unregister_challenge(&token_a);

    assert_eq!(
        get_challenge(&token_a),
        None,
        "removing token_a must not affect token_b"
    );
    assert_eq!(
        get_challenge(&token_b),
        Some("auth-b".to_string()),
        "token_b must still be present after removing token_a"
    );

    unregister_challenge(&token_b);
}

#[tokio::test]
async fn test_concurrent_challenge_operations() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(50);

    for i in 0usize..50 {
        let counter = success_count.clone();
        handles.push(tokio::spawn(async move {
            let token = format!("concurrent-tok-{i}");
            let auth = format!("concurrent-auth-{i}");

            register_challenge(token.clone(), auth.clone());
            if get_challenge(&token) == Some(auth) {
                let _ = counter.fetch_add(1, Ordering::Relaxed);
            }
            unregister_challenge(&token);
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(
        success_count.load(Ordering::Relaxed),
        50,
        "all 50 concurrent challenge round-trips must succeed"
    );
}

#[tokio::test]
async fn test_router_intercepts_acme_challenge() {
    let token = "router-intercept-tok".to_string();
    let auth = "router-intercept-auth".to_string();
    register_challenge(token.clone(), auth.clone());

    let router = Router::new().with_state::<()>(());

    let req = Request::builder()
        .uri(format!(
            "http://localhost/.well-known/acme-challenge/{token}"
        ))
        .body(Body::empty())
        .unwrap();

    let resp = router.handle_request(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("text/plain"),
    );

    use http_body_util::BodyExt;
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body_bytes, Bytes::from(auth));

    unregister_challenge(&token);
}

#[tokio::test]
async fn test_router_challenge_not_registered_falls_through_to_404() {
    let router = Router::new().with_state::<()>(());

    let req = Request::builder()
        .uri("http://localhost/.well-known/acme-challenge/unregistered-token")
        .body(Body::empty())
        .unwrap();

    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_router_normal_routes_not_affected_by_acme() {
    use tachyon_web::get;

    async fn index() -> &'static str {
        "index"
    }

    let router = Router::new().route("/", get(index)).with_state::<()>(());

    let req = Request::builder()
        .uri("http://localhost/")
        .body(Body::empty())
        .unwrap();

    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_acme_challenge_served_over_http() {
    use reqwest::Client;
    use tachyon_web::{Server, get};
    use tokio::net::TcpListener;

    let token = "http-e2e-tok".to_string();
    let auth = "http-e2e-auth-xyz".to_string();
    register_challenge(token.clone(), auth.clone());

    async fn dummy() -> &'static str {
        "ok"
    }

    let app = Router::new()
        .route("/ping", get(dummy))
        .with_state::<()>(());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let _handle = tokio::spawn(async move {
        Server::new(app).serve_http(listener).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let url = format!("http://127.0.0.1:{port}/.well-known/acme-challenge/{token}");
    let resp = Client::new().get(&url).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .contains("text/plain")
    );
    assert_eq!(resp.text().await.unwrap(), auth);

    unregister_challenge(&token);
}

#[test]
fn test_acme_resolver_starts_without_cert() {
    let resolver = AcmeResolver::new();
    assert!(
        !resolver.has_certificate(),
        "newly created resolver must have no certificate"
    );
}

#[test]
fn test_acme_resolver_update_cert_makes_has_certificate_true() {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::sign::CertifiedKey;

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der =
        rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider.key_provider.load_private_key(key_der).unwrap();
    let certified_key = CertifiedKey::new(vec![cert_der], signing_key);

    let resolver = AcmeResolver::new();
    assert!(!resolver.has_certificate());

    resolver.update_cert(certified_key);
    assert!(
        resolver.has_certificate(),
        "resolver must report having a certificate after update_cert"
    );
}

#[test]
fn test_acme_manager_creates_cache_dir() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("nested").join("acme");
    assert!(!cache.exists());

    let _manager = AcmeManager::new(
        &cache,
        vec!["example.com".to_string()],
        "test@example.com".to_string(),
        true,
    );

    assert!(
        cache.exists(),
        "AcmeManager::new must create the cache directory"
    );
}

#[test]
fn test_acme_manager_resolver_is_arc() {
    let dir = tempfile::tempdir().unwrap();
    let manager = AcmeManager::new(
        dir.path(),
        vec!["example.com".to_string()],
        "a@b.com".to_string(),
        true,
    );

    let resolver1 = manager.resolver();
    let resolver2 = manager.resolver();

    assert!(
        std::sync::Arc::ptr_eq(&resolver1, &resolver2),
        "resolver() must return the same Arc instance on every call"
    );
}

#[test]
fn test_acme_error_display() {
    let cases: [(AcmeError, &str); 5] = [
        (
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied").into(),
            "I/O error",
        ),
        (
            serde_json::from_slice::<serde_json::Value>(b"{{invalid}}")
                .unwrap_err()
                .into(),
            "JSON error",
        ),
        (AcmeError::OrderInvalid, "rejected"),
        (AcmeError::MissingPrivateKey, "private key"),
        (
            AcmeError::CertParse("invalid DER".to_string()),
            "Certificate parse",
        ),
    ];

    for (err, expected) in cases {
        let msg = err.to_string();
        assert!(msg.contains(expected), "{msg} should mention {expected}");
    }

    assert!(
        AcmeError::TlsKeyLoad("bad key".to_string())
            .to_string()
            .contains("TLS signing key")
    );
}

#[tokio::test]
async fn test_challenge_empty_token_not_served() {
    let router = Router::new().with_state::<()>(());

    let req = Request::builder()
        .uri("http://localhost/.well-known/acme-challenge/")
        .body(Body::empty())
        .unwrap();

    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_challenge_path_prefix_not_intercepted_as_challenge() {
    use tachyon_web::get;

    async fn custom() -> &'static str {
        "custom"
    }
    let router = Router::new()
        .route("/.well-known/acme-challenge/custom", get(custom))
        .with_state::<()>(());

    register_challenge("other-token".to_string(), "other-auth".to_string());

    let req = Request::builder()
        .uri("http://localhost/.well-known/acme-challenge/custom")
        .body(Body::empty())
        .unwrap();

    // "custom" isn't in the challenge store, so it falls through to the registered route.
    let resp = router.handle_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    unregister_challenge("other-token");
}
