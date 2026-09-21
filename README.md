# Tachyon-Web

[![Crates.io](https://img.shields.io/crates/v/tachyon-web.svg)](https://crates.io/crates/tachyon-web)
[![Docs.rs](https://img.shields.io/docsrs/tachyon-web)](https://docs.rs/tachyon-web)
[![License](https://img.shields.io/badge/license-0BSD-8da0cb.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](#minimum-supported-rust-version)

A multi-protocol web framework for Rust, built on [`hyper`](https://crates.io/crates/hyper) and
[`s2n-quic`](https://crates.io/crates/s2n-quic): Axum's router and extractor API, and HTTP/1.1,
h2c, HTTP/2, HTTP/3, Let's Encrypt, Tor and I2P all
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

```rust,no_run
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

## HTTPS

Throwaway self-signed certificate, for development:

```rust,no_run
use tachyon_web::{Router, Server, get, tls};

async fn hello() -> &'static str { "secure hello" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/", get(hello));

    let cert = tls::generate_self_signed_cert(vec!["localhost".to_string()])?;

    Server::new(app)
        .start_all(
            "0.0.0.0:443",
            Some("0.0.0.0:80"), // optional HTTP -> HTTPS redirect
            cert.cert_pem,
            cert.key_pem,
        )
        .await?;
    Ok(())
}
```

`serve_all_acme` runs the whole Let's Encrypt lifecycle in-process — account registration,
the HTTP-01 challenge, disk caching, and renewal 30 days before expiry:

```rust,no_run
use tachyon_web::{Router, Server, get};

async fn hello() -> &'static str { "Hello, secure world!" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/", get(hello));

    Server::new(app)
        .serve_all_acme(
            "0.0.0.0:443",                   // HTTPS / HTTP/2 / HTTP/3
            "0.0.0.0:80",                    // HTTP redirect + ACME challenges
            vec!["example.com".to_string()], // domains (must resolve to this server)
            "admin@example.com".to_string(), // Let's Encrypt contact email
            "/var/cache/tachyon/certs",      // persistent cert cache (survives restarts)
            false,                           // false = production LE, true = staging
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
| `tower-log` | on | `tower`'s own `log` feature |
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
| `fips` | | enforce FIPS-mode cryptography at startup; refuses to start otherwise; needs `tls` |
| `tor` | | Tor v3 `.onion` support (`Server::serve_tor`/`serve_onion`) via `arti-client` |
| `i2p` | | I2P `.b32.i2p` support (`Server::serve_i2p`/`serve_i2p_config`) via an embedded `libi2pd`. Links `unsafe` FFI — see [Tor and I2P](#tor-and-i2p) |

At least one of `http1`/`http2` must stay enabled; disabling both is a `compile_error!`.

### HTTP/2 over cleartext (h2c)

With `http2` on, `Server::serve_http` speaks HTTP/2 over plain TCP with no TLS and no ALPN:
the server peeks at each connection's first bytes and switches to the HTTP/2 stack if it
sees the client preface, falling back to HTTP/1.1 otherwise. Browsers won't use it — they
only negotiate HTTP/2 via TLS ALPN — but `curl --http2-prior-knowledge`, gRPC clients, and
service meshes that terminate TLS upstream will.

## Acknowledgements

[Axum](https://github.com/tokio-rs/axum) is why the API looks the way it does — `Router`,
extractors, `IntoResponse`. Where this README says "matches Axum", it means someone checked.
[Actix Web](https://github.com/actix/actix-web) inspired treating a per-request allocation as
a cost worth counting. [Salvo](https://github.com/salvo-rs/salvo) is the reason
TLS, HTTP/3, and certificate management are built in rather than assembled by every user.

## License

Licensed under the [0BSD license](https://github.com/hacer-bark/cargo-unikernel/blob/main/LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate shall be licensed as above, without any additional terms or conditions.
