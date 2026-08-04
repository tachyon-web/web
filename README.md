# Tachyon-Web

[![Crates.io](https://img.shields.io/crates/v/tachyon-web.svg)](https://crates.io/crates/tachyon-web)
[![Docs.rs](https://img.shields.io/docsrs/tachyon-web)](https://docs.rs/tachyon-web)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](#minimum-supported-rust-version)

A multi-protocol web framework for Rust, built on [`hyper`](https://crates.io/crates/hyper) and
[`s2n-quic`](https://crates.io/crates/s2n-quic): Axum's router and extractor API, per-core
`SO_REUSEPORT` workers, and HTTP/1.1, h2c, HTTP/2, HTTP/3, Let's Encrypt, Tor and I2P all
in one crate rather than five.

## ⚠️ Read this before depending on it

This is `0.0.x` — there has not been a release anyone should call stable.

Breaking changes can land in any release. Logical bugs are expected; nobody can honestly
claim otherwise about a project this young. What is guaranteed is narrower: the crate
compiles under `#![forbid(unsafe_code)]`, which is a compiler error rather than a promise,
so the memory-safety class of bugs is off the table. Resource-exhaustion and data-exposure
bugs are not — following best practice on input handling and request lifecycle lowers that
risk, it does not prove its absence.

If an outage or a security incident is unacceptable — payments, healthcare, anything
regulated, anything with an on-call rotation — use [`axum`](https://crates.io/crates/axum).
It has a maintaining team and years of production track record, and that is worth more than
anything on this page.

For side projects, internal tools, and prototypes, try it and report what broke.

## Quick start

```rust
use tachyon_web::{Router, Server, get};
use tachyon_web::http::response::Html;
use tokio::net::TcpListener;

async fn hello_world() -> Html<&'static str> {
    Html("<h1>Hello from Tachyon-Web!</h1>")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", get(hello_world));

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    Server::new(app).serve_http(listener).await?;
    Ok(())
}
```

Path/query/JSON extraction, middleware, shared state, static files, sync handlers and
serving over Tor/I2P each have an example in [`examples/`](examples/), run with
`cargo run --example <name>`. Some need extra features; the example file says which.

## Differences from Axum

The router, extractors (`Path`, `Query`, `Json`, `State`) and `IntoResponse` work as they do
in Axum, and the Cargo feature names and defaults match Axum's where the capability is
shared, so porting a handler or a `Cargo.toml` should be uneventful.

Middleware is the deliberate departure: Tachyon uses its own `.hoop()` rather than
`tower::Layer`, to avoid the overhead Tower's generic `Service` abstraction adds on the hot
path. The `tower` feature bridges `tower::Service`/`tower::Layer` back in when reusing an
existing `tower-http` layer is worth that cost, and also implements `tower::Service` for
`CompiledRouter` so `app.oneshot(req)` works.

On performance: routing allocates nothing for the common case (arity-0 handlers, no path
params), static files are served zero-copy from an in-memory cache, and workers are per-core
with `SO_REUSEPORT`. `benches/` measures against Axum and Actix-Web directly. Actix is still
ahead on the trivial-handler benchmark — roughly 320k (Actix-Web) vs 300k (Tachyon-Web) vs 280k (Axum) 
req/sec on the same hardware, see `benches/optimistic`.

## HTTPS

Throwaway self-signed certificate, for development:

```rust
use tachyon_web::{Router, Server, get, tls};

async fn hello() -> &'static str { "secure hello" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/", get(hello));

    let cert = tls::generate_self_signed_cert(vec!["localhost".to_string()])?;

    Server::new(app)
        .start_all(
            "0.0.0.0:443",
            Some("0.0.0.0:80"),  // optional HTTP -> HTTPS redirect
            cert.cert_pem,
            cert.key_pem,
        )
        .await?;
    Ok(())
}
```

`serve_all_acme` runs the whole Let's Encrypt lifecycle in-process — account registration,
the HTTP-01 challenge, disk caching, and renewal 30 days before expiry:

```rust
use tachyon_web::{Router, Server, get};

async fn hello() -> &'static str { "Hello, secure world!" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/", get(hello));

    Server::new(app)
        .serve_all_acme(
            "0.0.0.0:443",                          // HTTPS / HTTP/2 / HTTP/3
            "0.0.0.0:80",                           // HTTP redirect + ACME challenges
            vec!["example.com".to_string()],        // domains (must resolve to this server)
            "admin@example.com".to_string(),        // Let's Encrypt contact email
            "/var/cache/tachyon/certs",             // persistent cert cache (survives restarts)
            false,                                  // false = production LE, true = staging
        )
        .await?;
    Ok(())
}
```

## Tor and I2P

The same `Router` publishes as a Tor v3 hidden service (`Server::serve_tor`, on pure-Rust
`arti-client`/`tor-hsservice`) or an I2P eepsite (`Server::serve_i2p`, on an embedded
`libi2pd`) with no external daemon and no SAM/BOB bridge — optionally at the same time as a
clearnet listener, via `MultiServer`. See
[`examples/onion_i2p_server.rs`](examples/onion_i2p_server.rs).

`i2p` is the one feature that links C++ through an FFI shim (`tachyon-i2p`/`i2pd-sys`), so
it sits outside the crate's `#![forbid(unsafe_code)]` guarantee. Read the
`tachyon_web::server::i2p` module docs before using it for anything security-sensitive.

## WebSockets

```rust
use tachyon_web::ws::{WebSocket, WebSocketUpgrade};
use tachyon_web::http::Response;
use tachyon_web::http::response::Body;
use tachyon_web::{Router, get};

async fn handler(ws: WebSocketUpgrade) -> Response<Body> {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.recv().await {
        if socket.send(msg).await.is_err() {
            break;
        }
    }
}

let _app: Router<()> = Router::new().route("/ws", get(handler));
```

Requires the `ws` feature.

## Compression

`Accept-Encoding` negotiation and response coding for `zstd`, `br`, `gzip` and `deflate`,
applied to every transport at once:

```rust
use tachyon_web::{Router, Server};
use tachyon_web::http::compression::{Compression, CompressionLevel};

Server::new(app)
    .compression(
        Compression::new()                      // every codec this build has, zstd first
            .level(CompressionLevel::Fastest),  // encode speed, for per-request bodies
    )
    .serve_http(listener)
    .await?;
```

Or scoped to one router with `Router::compression(..)`. The codec feature names match
`tower-http`'s (`compression-gzip`, `compression-br`, …, `compression-full`), so migrating
from a `CompressionLayer` is a `Cargo.toml` search-and-replace.

Negotiation is RFC 9110 §12.5.3: q-values are honoured, `q=0` is a refusal rather than a low
ranking, and `*` resolves as a wildcard. Beyond that it does the things a compression layer
is usually expected to do and usually doesn't: `Vary: Accept-Encoding` is appended even to
the responses it leaves uncompressed, strong `ETag`s are weakened because a coded body is a
different representation, `Cache-Control: no-transform` is honoured, `Content-Length` is
rewritten to the coded length, output that came out larger than the input is discarded in
favour of the original, and zstd's window is clamped to the 8 MiB every browser decoder caps
at — the usual way to ship a `Content-Encoding: zstd` that works in `curl` and fails in
Chrome. See the [`http::compression`] module docs for the full list of what is never
compressed.

`ServeDir` picks up pre-compressed `.zst` sidecars alongside the `.br` and `.gz` it already
served, and negotiates among the ones each asset actually has.

## 103 Early Hints

[RFC 8297]. An informational response sent *during* handler think-time, telling the browser
what to fetch before the HTML exists:

```rust
use tachyon_web::{Html, Router, Server, get};
use tachyon_web::http::early_hints::{EarlyHints, EarlyHintsConfig, Link};

async fn page(hints: EarlyHints) -> Html<String> {
    hints.send([
        Link::preload("/static/app.css").as_style(),
        Link::preconnect("https://cdn.example.com"),
    ]);                          // returns immediately, nothing to await

    let data = load().await;     // the think-time this exists to overlap
    Html(render(&data))
}

let app: Router = Router::new().route("/", get(page));

Server::new(app)
    .early_hints(EarlyHintsConfig::new())
    .serve_https_config(listener, tls_config)
    .await?;
```

There is also a declarative form — `get(page).early_hints([..])` on a route, or
`Router::early_hints([..])` — which renders the `Link` block once at startup and sends it
before the handler is even called.

This is the one feature here that cannot be a middleware in any framework built on
`Service<Request> -> Response`: an informational response is a *second* response, and that
signature returns one. `hyper` refuses a 1xx status outright and never calls `h2`'s
`send_informational`, so enabling `early-hints` moves HTTPS connections that negotiate `h2`
onto Tachyon's own `h2`-based driver. HTTP/3 needs no such thing — Tachyon already owns that
dispatch loop.

Hints go out over HTTP/2-over-TLS and HTTP/3. HTTP/1.1, h2c, Tor and I2P hand handlers a
no-op handle instead, so a handler never needs a fallback path. By default only requests
carrying `Sec-Fetch-Mode: navigate` are hinted, which is both what browsers act on and what
keeps an unexpected 1xx away from clients that mishandle one. The native HTTP/2 driver does
not support RFC 8441 WebSockets-over-HTTP/2; no browser uses them, but read
[`http::early_hints`] before enabling it if a non-browser client of yours does.

[RFC 8297]: https://www.rfc-editor.org/rfc/rfc8297
[`http::compression`]: https://docs.rs/tachyon-web/latest/tachyon_web/http/compression/
[`http::early_hints`]: https://docs.rs/tachyon-web/latest/tachyon_web/http/early_hints/

## Feature flags

Flags shared with Axum keep Axum's name and default:

| Flag | Default | Enables |
|---|---|---|
| `http1` | on | hyper's `http1` support |
| `http2` | on | hyper's `http2` support |
| `json` | on | the `Json` extractor/response type, and `serde_json` |
| `matched-path` | on | capturing each request's router path, and the `MatchedPath` extractor |
| `original-uri` | on | capturing each request's original URI, and the `OriginalUri` extractor |
| `form` | on | the `Form` extractor |
| `query` | on | the `Query` extractor |
| `cookies` | | request `Cookie` parsing and the `Cookies` extractor/`IntoResponseParts` jar (matching `axum-extra`'s `CookieJar`), and the `cookie` dependency |
| `tower-log` | on | `tower`'s own `log` feature; no effect without `tower` |
| `ws` | | WebSocket support (RFC 6455) |
| `compression-gzip` | | `gzip` response compression |
| `compression-deflate` | | `deflate` response compression |
| `compression-br` | | Brotli response compression |
| `compression-zstd` | | Zstandard response compression |
| `compression-full` | | all four codings above |

Tachyon's own additions default off, the way Axum treats its extras:

| Flag | Default | Enables |
|---|---|---|
| `tls` | | TLS via `rustls` + `aws-lc-rs` |
| `cert-gen` | | self-signed certificate generation (`tls::generate_self_signed_cert`); needs `tls` |
| `http3` | | HTTP/3 over QUIC via `s2n-quic`; needs `tls` |
| `lets-encrypt` | | automatic Let's Encrypt certificate management; needs `tls`, `cert-gen` |
| `sse` | | Server-Sent Events (`response::sse::{Event, Sse, KeepAlive}`) |
| `early-hints` | | `103 Early Hints` (RFC 8297), plus the native HTTP/2 driver that emits them; needs `tls` |
| `tower` | | `tower::Service`/`tower::Layer` interop, plus `tower::Service` for `CompiledRouter` |
| `fips` | | enforce FIPS-mode cryptography at startup; refuses to start otherwise |
| `tor` | | Tor v3 `.onion` support (`Server::serve_tor`/`serve_onion`) via `arti-client` |
| `i2p` | | I2P `.b32.i2p` support (`Server::serve_i2p`/`serve_i2p_config`) via an embedded `libi2pd`. Links `unsafe` FFI — see [Tor and I2P](#tor-and-i2p) |

At least one of `http1`/`http2` must stay enabled; disabling both is a `compile_error!`.

### HTTP/2 over cleartext (h2c)

With `http2` on, `Server::serve_http` speaks HTTP/2 over plain TCP with no TLS and no ALPN:
the server peeks at each connection's first bytes and switches to the HTTP/2 stack if it
sees the client preface, falling back to HTTP/1.1 otherwise. Browsers won't use it — they
only negotiate HTTP/2 via TLS ALPN — but `curl --http2-prior-knowledge`, gRPC clients, and
service meshes that terminate TLS upstream will.

## Minimum supported Rust version

Rust 1.92, edition 2024. MSRV bumps are not breaking changes while the crate is pre-1.0.

## Acknowledgements

[Axum](https://github.com/tokio-rs/axum) is why the API looks the way it does — `Router`,
extractors, `IntoResponse`. Where this README says "matches Axum", it means someone checked.
[Actix Web](https://github.com/actix/actix-web) is where the performance approach comes from:
per-core `SO_REUSEPORT` workers, thread-local buffer reuse, and treating a per-request
allocation as a cost worth counting. [Salvo](https://github.com/salvo-rs/salvo) is the reason
TLS, HTTP/3, and certificate management are built in rather than assembled by every user.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
