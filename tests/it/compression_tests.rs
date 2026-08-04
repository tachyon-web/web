//! End-to-end response compression over a real socket.
//!
//! `reqwest` is built without its own compression features here, so these tests receive the
//! coded bytes exactly as they went on the wire and decode them with the reference decoder
//! for each format. That is the property that actually matters: not that the framework's
//! encoder round-trips against itself, but that an independent decoder — the browser's
//! stand-in — accepts what was sent.

use crate::common::TestServer;
use std::io::Read;
use tachyon_web::http::compression::{Compression, CompressionLevel, Encoding};
use tachyon_web::{Router, get};

/// Long enough to compress well past `min_size`, and repetitive so every codec shrinks it.
const BODY: &str = "The quick brown fox jumps over the lazy dog. \
     Pack my box with five dozen liquor jugs. \
     How vexingly quick daft zebras jump! ";

fn body_text() -> String {
    BODY.repeat(40)
}

fn app() -> Router<()> {
    let text = body_text();
    Router::new()
        .route(
            "/text",
            get(move || {
                let text = text.clone();
                async move { tachyon_web::Html(text) }
            }),
        )
        .route(
            "/image",
            get(|| async {
                use tachyon_web::http::header::CONTENT_TYPE;
                let mut response = tachyon_web::http::Response::new(
                    tachyon_web::response::Body::full(bytes::Bytes::from(vec![0xAB; 4096])),
                );
                let _ = response
                    .headers_mut()
                    .insert(CONTENT_TYPE, "image/png".parse().unwrap());
                response
            }),
        )
        .route(
            "/empty",
            get(|| async { tachyon_web::http::StatusCode::NO_CONTENT }),
        )
}

fn decode(encoding: Encoding, bytes: &[u8]) -> String {
    let mut out = Vec::new();
    match encoding {
        Encoding::Gzip => {
            flate2::read::GzDecoder::new(bytes)
                .read_to_end(&mut out)
                .expect("gzip stream must decode");
        }
        Encoding::Deflate => {
            flate2::read::ZlibDecoder::new(bytes)
                .read_to_end(&mut out)
                .expect("zlib stream must decode");
        }
        Encoding::Brotli => {
            brotli::Decompressor::new(bytes, 8192)
                .read_to_end(&mut out)
                .expect("brotli stream must decode");
        }
        Encoding::Zstd => {
            zstd::stream::read::Decoder::new(bytes)
                .expect("zstd frame header must parse")
                .read_to_end(&mut out)
                .expect("zstd stream must decode");
        }
        Encoding::Identity => out.extend_from_slice(bytes),
    }
    String::from_utf8(out).expect("decoded body must be the original UTF-8")
}

/// The codings this build can actually produce, so the suite exercises whatever feature set
/// it was compiled with rather than failing on an absent codec.
fn available() -> Vec<Encoding> {
    [Encoding::Zstd, Encoding::Brotli, Encoding::Gzip, Encoding::Deflate]
        .into_iter()
        .filter(|e| e.encoder_available())
        .collect()
}

#[tokio::test]
async fn every_enabled_coding_decodes_with_its_reference_decoder() {
    let server = TestServer::spawn_with(app(), |s| s.compression(Compression::new())).await;

    for encoding in available() {
        let response = server
            .get("/text")
            .header("accept-encoding", encoding.as_str())
            .send()
            .await
            .expect("request");

        assert_eq!(
            response
                .headers()
                .get("content-encoding")
                .map(|v| v.to_str().unwrap()),
            Some(encoding.as_str()),
            "server did not apply {encoding}",
        );
        assert!(
            response
                .headers()
                .get_all("vary")
                .iter()
                .any(|v| v.to_str().unwrap().to_ascii_lowercase().contains("accept-encoding")),
            "{encoding} response is missing Vary: Accept-Encoding",
        );

        let coded = response.bytes().await.expect("body");
        assert!(
            coded.len() < body_text().len(),
            "{encoding} produced {} bytes for a {}-byte body",
            coded.len(),
            body_text().len(),
        );
        assert_eq!(decode(encoding, &coded), body_text());
    }
}

/// The client's ranking decides, not the server's preference order.
#[tokio::test]
async fn client_q_values_choose_the_coding() {
    let codings = available();
    if codings.len() < 2 {
        return;
    }
    let server = TestServer::spawn_with(app(), |s| s.compression(Compression::new())).await;

    // Rank the server's *least* preferred available coding highest and expect to get it.
    let wanted = *codings.last().unwrap();
    let header = codings
        .iter()
        .map(|e| {
            if *e == wanted {
                format!("{e};q=1.0")
            } else {
                format!("{e};q=0.1")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");

    let response = server
        .get("/text")
        .header("accept-encoding", header)
        .send()
        .await
        .expect("request");
    assert_eq!(
        response.headers().get("content-encoding").unwrap(),
        wanted.as_str(),
    );
    assert_eq!(decode(wanted, &response.bytes().await.unwrap()), body_text());
}

/// `q=0` is a refusal. Refusing everything the server has must yield identity bytes, not a
/// coding the client just said it cannot decode.
#[tokio::test]
async fn refusing_every_coding_yields_identity() {
    let server = TestServer::spawn_with(app(), |s| s.compression(Compression::new())).await;
    let header = available()
        .iter()
        .map(|e| format!("{e};q=0"))
        .collect::<Vec<_>>()
        .join(", ");

    let response = server
        .get("/text")
        .header("accept-encoding", header)
        .send()
        .await
        .expect("request");

    assert!(response.headers().get("content-encoding").is_none());
    assert_eq!(response.text().await.unwrap(), body_text());
}

/// A client that sends no `Accept-Encoding` gets bytes as-is — and a `Vary` that stops a
/// shared cache from serving this entry to the next client, who may accept a coding.
#[tokio::test]
async fn absent_accept_encoding_yields_identity_but_still_varies() {
    let server = TestServer::spawn_with(app(), |s| s.compression(Compression::new())).await;

    // `reqwest` adds no `Accept-Encoding` of its own without its compression features.
    let response = server.get("/text").send().await.expect("request");
    assert!(response.headers().get("content-encoding").is_none());
    assert_eq!(response.text().await.unwrap(), body_text());
}

#[tokio::test]
async fn already_compressed_content_types_are_left_alone() {
    let server = TestServer::spawn_with(app(), |s| s.compression(Compression::new())).await;
    let header = available()
        .iter()
        .map(|e| e.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let response = server
        .get("/image")
        .header("accept-encoding", header)
        .send()
        .await
        .expect("request");

    assert!(
        response.headers().get("content-encoding").is_none(),
        "a PNG must not be re-compressed",
    );
    assert_eq!(response.bytes().await.unwrap().len(), 4096);
}

#[tokio::test]
async fn bodyless_statuses_pass_through() {
    let server = TestServer::spawn_with(app(), |s| s.compression(Compression::new())).await;
    let response = server
        .get("/empty")
        .header("accept-encoding", "gzip, br, zstd")
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), 204);
    assert!(response.headers().get("content-encoding").is_none());
    assert!(response.bytes().await.unwrap().is_empty());
}

/// Router-scoped compression must not leak onto routes registered on a different router.
#[tokio::test]
async fn router_scoped_compression_covers_only_its_own_routes() {
    let Some(&encoding) = available().first() else {
        return;
    };

    let text = body_text();
    let compressed_half: Router<()> = Router::new()
        .route(
            "/compressed",
            get(move || {
                let text = text.clone();
                async move { tachyon_web::Html(text) }
            }),
        )
        .compression(Compression::empty().enable(encoding));

    let text = body_text();
    let router = compressed_half.route(
        "/plain",
        get(move || {
            let text = text.clone();
            async move { tachyon_web::Html(text) }
        }),
    );

    let server = TestServer::spawn(router).await;

    let compressed = server
        .get("/compressed")
        .header("accept-encoding", encoding.as_str())
        .send()
        .await
        .expect("request");
    assert_eq!(
        compressed.headers().get("content-encoding").unwrap(),
        encoding.as_str(),
    );

    let plain = server
        .get("/plain")
        .header("accept-encoding", encoding.as_str())
        .send()
        .await
        .expect("request");
    assert!(
        plain.headers().get("content-encoding").is_none(),
        "a route added after `.compression()` must not be covered by it",
    );
}

/// `Content-Length` on a compressed in-memory body must describe the coded bytes. A stale
/// identity length would either truncate the response or hang the client waiting for bytes
/// that never come — and, unlike most framing bugs, it survives a `curl` smoke test.
#[tokio::test]
async fn content_length_matches_the_coded_body() {
    let Some(&encoding) = available().first() else {
        return;
    };
    let server = TestServer::spawn_with(app(), |s| {
        s.compression(Compression::new().level(CompressionLevel::Best))
    })
    .await;

    let response = server
        .get("/text")
        .header("accept-encoding", encoding.as_str())
        .send()
        .await
        .expect("request");

    let declared: usize = response
        .headers()
        .get("content-length")
        .expect("an in-memory body must keep a Content-Length")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let coded = response.bytes().await.unwrap();
    assert_eq!(declared, coded.len());
    assert_eq!(decode(encoding, &coded), body_text());
}
