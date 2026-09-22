# Tachyon-Web

[![Crates.io](https://img.shields.io/crates/v/tachyon-web.svg)](https://crates.io/crates/tachyon-web)
[![Docs.rs](https://img.shields.io/docsrs/tachyon-web)](https://docs.rs/tachyon-web)
[![License](https://img.shields.io/badge/license-0BSD-8da0cb.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](#minimum-supported-rust-version)

Tachyon-Web is a literal drop-in replacement for serving an [Axum](https://github.com/tokio-rs/axum)
app: write the app against `axum` exactly as you already would, and change one line to serve
it — `tachyon_web::Server` in place of `axum::serve`. `Router`, extractors, responses,
middleware and Tower integration all stay Axum's own types; nothing about the app changes.

What Tachyon adds is everything *around* the app: the transport layer. Native TLS 1.3, HTTP/3,
Let's Encrypt, and — because "protective" here means more than TLS — first-class Tor `.onion`
and I2P `.i2p` hidden-service serving, with the same hardened connection handling underneath
every one of them. One crate instead of an Axum app plus a reverse proxy plus a certbot cron job
plus a separate onion-service setup.

## Why "Tachyon"

Not speed — a tachyon is a hypothetical particle that has never been observed, by design faster
than the fastest thing that could ever catch it. That's the property being named here: traffic
this crate serves over Tor or I2P is architecturally hard to pin to a physical origin. Nothing
in this project claims to outrun anyone; it claims to be difficult to catch.

## ⚠️ Still `0.0.x`

Breaking changes can land in any release — nothing here should be called stable yet. Tachyon
leans on audited, widely-deployed crates for the parts that matter most (`axum` for the app
layer, `rustls`/`aws-lc-rs` for TLS, `arti-client` for Tor) rather than reimplementing them, and
compiles under `#![forbid(unsafe_code)]`, so it isn't starting from zero — but a young
integration layer around mature pieces is still a young integration layer. Try it, expect API
changes across `0.0.x` releases, and report what broke.

**Tachyon-Web is an independent project.** It is not affiliated with, endorsed by, or
associated with the Axum project, Tokio, the Tor Project, I2P, or any other project it
interoperates with. "Drop-in replacement" describes API compatibility, not a relationship with
their maintainers.

## Quick start

The app is written against `axum` directly, same as any other Axum app:

```rust,no_run
use axum::{Router, routing::get};
use axum::response::Html;
use tokio::net::TcpListener;

async fn hello_world() -> Html<&'static str> {
    Html("<h1>Hello from Axum!</h1>")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", get(hello_world));

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    tachyon_web::Server::new(app).serve_http(listener).await?;
    Ok(())
}
```

Everything above the last line is plain `axum` — nothing to migrate. The one line that changes
going to production is the serve call: `axum::serve(listener, app)` becomes
`tachyon_web::Server::new(app).serve_http(listener)`, which brings hardened connection handling
(read/handshake timeouts, per-connection body/stream limits, Slowloris and
flow-control-exhaustion mitigations) shared across every transport below, instead of
hand-rolling it per protocol.

Run any example with `cargo run --example <name>`; each file's header comment lists the
features it needs and the commands to exercise it.

| Example | Shows |
|---|---|
| [`hello_world.rs`](examples/hello_world.rs) | path/query/JSON extraction, custom status codes |
| [`hardened_server.rs`](examples/hardened_server.rs) | host allow-listing, reverse-proxy trust, response hardening, DoS limits — with `curl` commands for each rejection |
| [`self_signed_https.rs`](examples/self_signed_https.rs) | HTTPS + HTTP/3 + a redirect listener on unprivileged ports, and a `TlsPolicy` |
| [`lets_encrypt.rs`](examples/lets_encrypt.rs) | production certificates issued and renewed in-process |
| [`onion_i2p_server.rs`](examples/onion_i2p_server.rs) | the same app served over Tor and I2P at once |

## HTTPS

Throwaway self-signed certificate, for development:

```rust,no_run
use axum::{Router, routing::get};
use tachyon_web::tls;

async fn hello() -> &'static str { "secure hello" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/", get(hello));

    let cert = tls::generate_self_signed_cert(vec!["localhost".to_string()])?;

    tachyon_web::Server::new(app)
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
use axum::{Router, routing::get};

async fn hello() -> &'static str { "Hello, secure world!" }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/", get(hello));

    tachyon_web::Server::new(app)
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
| `tower-log` | on | `tower`'s own `log` feature |
| `tracing` | on | Axum's own `tracing` feature (distinct from Tachyon's `telemetry`, below) |
| `ws` | | WebSocket support (RFC 6455) |
| `multipart` | | the `Multipart` extractor |
| `macros` | | Axum's `#[debug_handler]` and friends |

Tachyon's own additions default off, the way Axum treats its extras:

| Flag | Default | Enables |
|---|---|---|
| `tls` | | TLS 1.3 via `rustls` + `aws-lc-rs` |
| `tls12-legacy` | | additionally offer TLS 1.2 as a fallback. Without it no listener negotiates anything below TLS 1.3, and no `TlsPolicy` carries a TLS 1.2 cipher suite. Enable only to serve clients that have no TLS 1.3; needs `tls` |
| `cert-gen` | | self-signed certificate generation (`tls::generate_self_signed_cert`); needs `tls` |
| `http3` | | HTTP/3 over QUIC via [`tachyon-quic`](https://crates.io/crates/tachyon-quic) (built on `s2n-quic`); needs `tls` |
| `lets-encrypt` | | automatic Let's Encrypt certificate management; needs `tls`, `cert-gen` |
| `fips` | | use AWS-LC's FIPS 140-3 Level 1 software module in approved mode and enforce the restricted TLS policy; needs `tls` |
| `cnsa` | | strict controlled-client CNSA 2.0 profile: FIPS mode, TLS 1.3, AES-256-GCM-SHA384, ML-KEM-1024, ML-DSA-87 self-signed certificates, and no resumption; mutually exclusive with `lets-encrypt` |
| `telemetry` | | opt in to transport-layer `tracing` events; off by default so the layer emits no logs |
| `tor` | | Tor v3 `.onion` support (`Server::serve_tor`/`serve_onion`) via `arti-client` |
| `i2p` | | I2P `.b32.i2p` support (`Server::serve_i2p`/`serve_i2p_config`) via an embedded `libi2pd`. Links `unsafe` FFI — see [Tor and I2P](#tor-and-i2p) |

At least one of `http1`/`http2` must stay enabled; disabling both is a `compile_error!`.

## Minimum supported Rust version

Rust **1.92**. Raising it is a breaking change, announced in the release notes; while the crate
is `0.0.x` that still means a patch release can carry one.

## Acknowledgements

[Axum](https://github.com/tokio-rs/axum) *is* the application layer here — `Router`,
extractors, responses, and middleware come from it directly, unmodified. See
[`NOTICE.md`](NOTICE.md) for the required MIT attribution. [Salvo](https://github.com/salvo-rs/salvo)
is the reason TLS, HTTP/3, and certificate management are built in rather than assembled by
every user.

## License

Licensed under the [0BSD license](LICENSE).

Tachyon-Web's own code is 0BSD; it is built directly on [Axum](https://github.com/tokio-rs/axum),
used under the MIT license — see [`NOTICE.md`](NOTICE.md) for the full attribution required by
that license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate shall be licensed as above, without any additional terms or conditions.
