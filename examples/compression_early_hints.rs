//! Response compression and `103 Early Hints`, on one HTTPS server.
//!
//! ```sh
//! cargo run --example compression_early_hints --features compression-full,early-hints,cert-gen
//! ```
//!
//! Then, because both features only really show themselves over HTTP/2 with a browser-shaped
//! request:
//!
//! ```sh
//! # The 103, with its Link headers, arriving ~300 ms before the 200:
//! curl -k --http2 -i https://localhost:8443/ -H 'sec-fetch-mode: navigate'
//!
//! # Compression, negotiated per request:
//! curl -k --http2 -sv https://localhost:8443/api/report -H 'accept-encoding: zstd' -o /dev/null
//! curl -k --http2 -sv https://localhost:8443/api/report -H 'accept-encoding: gzip;q=1, zstd;q=0.1' -o /dev/null
//! ```
//!
//! The certificate is self-signed, hence `-k`. Both features need HTTPS for real: browsers
//! negotiate HTTP/2 only over TLS, and Chrome only advertises `zstd` on a secure origin.

use std::time::Duration;
use tachyon_web::http::compression::{Compression, CompressionLevel};
use tachyon_web::http::early_hints::{EarlyHints, EarlyHintsConfig, Link};
use tachyon_web::{Html, Router, Server, get};

/// The hints this page always needs, whatever the request. Declared on the route, so the
/// `Link` block is rendered once at startup and the 103 goes out before `index` is called.
fn static_hints() -> [Link; 3] {
    [
        Link::preload("/static/app.css").as_style(),
        Link::preload("/static/app.js").as_script(),
        Link::preconnect("https://cdn.example.com"),
    ]
}

/// Stands in for the database round trip that early hints exist to overlap. Without think
/// time here, a 103 buys nothing — which is worth seeing rather than reading.
async fn think() {
    tokio::time::sleep(Duration::from_millis(300)).await;
}

async fn index() -> Html<&'static str> {
    think().await;
    Html(
        r#"<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="/static/app.css">
    <script src="/static/app.js" defer></script>
  </head>
  <body><h1>Hello from Tachyon-Web</h1></body>
</html>"#,
    )
}

/// The imperative form: hints that depend on the request, sent from inside the handler.
///
/// `hints.send` returns immediately — awaiting it would serialise the hint against the very
/// work it is meant to overlap.
async fn product(hints: EarlyHints) -> Html<String> {
    hints.send([
        Link::preload("/static/product.css").as_style(),
        Link::preload("/static/hero.avif")
            .as_image()
            .imagesrcset("/static/hero-400.avif 400w, /static/hero-800.avif 800w"),
        Link::preload("/static/inter.woff2")
            .as_font()
            .mime_type("font/woff2")
            // Fonts are fetched in CORS mode even same-origin; without this the browser
            // fetches the file a second time and the preload is worse than useless.
            .crossorigin(tachyon_web::http::early_hints::CrossOrigin::Anonymous),
    ]);

    think().await;
    Html("<!doctype html><html><body><h1>A product</h1></body></html>".to_string())
}

/// Big enough and repetitive enough that every codec has something to work with.
async fn report() -> Html<String> {
    Html("<tr><td>a row of a report</td><td>with some numbers</td></tr>\n".repeat(500))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let app: Router = Router::new()
        .route("/", get(index).early_hints(static_hints()))
        .route("/product", get(product))
        .route("/api/report", get(report));

    let cert = tachyon_web::tls::generate_self_signed_cert(vec!["localhost".to_string()])?;

    println!("https://localhost:8443/  (self-signed — use curl -k)");

    Server::new(app)
        .compression(
            Compression::new()
                // Responses built per request: favour encode speed over the last few
                // percent of ratio.
                .level(CompressionLevel::Fastest),
        )
        // Moves HTTPS connections that negotiate h2 onto Tachyon's own HTTP/2 driver,
        // which is what can actually emit a 1xx. See `http::early_hints`.
        .early_hints(EarlyHintsConfig::new())
        .start_all("0.0.0.0:8443", None, cert.cert_pem, cert.key_pem)
        .await?;

    Ok(())
}
