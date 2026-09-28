# Tachyon-Web

[![Crates.io](https://img.shields.io/crates/v/tachyon-web.svg)](https://crates.io/crates/tachyon-web)
[![Docs.rs](https://img.shields.io/docsrs/tachyon-web)](https://docs.rs/tachyon-web)
[![License](https://img.shields.io/badge/license-0BSD-8da0cb.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](#minimum-supported-rust-version)

Tachyon-Web serves an [Axum](https://github.com/tokio-rs/axum) app. Write the app against your
own `axum` 0.8 dependency exactly as you already would — `Router`, extractors, middleware and Tower
all stay Axum's — and hand it to `tachyon_web::Server` instead of `axum::serve`.

What Tachyon adds is everything *around* the app: the transport layer. TLS 1.3 with several
certificates per endpoint (Let's Encrypt, self-signed ECDSA and ML-DSA, or your own), HTTP/3,
in-process ACME, and first-class Tor `.onion` and I2P `.i2p` publishing — all under one set of
limits, one security policy and one graceful shutdown. One crate instead of an Axum app plus a
reverse proxy plus a certbot cron job plus a separate onion-service setup.

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
interoperates with. "Serves an Axum app" describes compatibility, not a relationship with
their maintainers.

## Quick start

```toml
[dependencies]
axum = "0.8"
tachyon-web = "0.0.3"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
```

```rust,no_run
use axum::{Router, response::Html, routing::get};
use tachyon_web::Server;

async fn hello() -> Html<&'static str> {
    Html("<h1>Hello from Axum!</h1>")
}

#[tokio::main]
async fn main() -> Result<(), tachyon_web::Error> {
    let app = Router::new().route("/", get(hello));

    Server::new(app)
        .http("0.0.0.0:8080")
        .serve()
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
```

Every connection gets read, handshake and write-stall timeouts, body and concurrency limits,
Slowloris and HTTP/2 flow-control mitigations, host allow-listing and forwarding-header hygiene —
identically on every transport. `Limits::max_body_size` is also applied as the app's
`DefaultBodyLimit`, so extractors and the wire agree on one number.

## One rule for every transport

Add transports, then `serve()`:

| Method | Serves | Feature |
|---|---|---|
| `.http(bind)` | HTTP/1.1 (+ h2c when allowed) | *(always)* |
| `.https(bind, tls)` | HTTP/1.1 + HTTP/2 over TLS, + HTTP/3 on the same port with `http3` | `tls` |
| `.redirect(bind)` | `308` to HTTPS, and ACME HTTP-01 answers | `tls` |
| `.onion(config)` | a Tor v3 onion service | `tor` |
| `.i2p(config)` | an I2P eepsite | `i2p` |

`bind` is an address string, a `SocketAddr`, or a `TcpListener` you already bound. The whole
configuration is checked, every clearnet listener bound and its certificates loaded before the
first request is served; a mistake fails the start, never a silent default. Onion and I2P
certificates load once their address is published, since it is one of their names.

## HTTPS with several certificates

A `Tls` set holds any mix of Let's Encrypt, self-signed and provided certificates. Each handshake
gets the first one, in the order added, that the client can verify:

```rust,no_run
use axum::{Router, routing::get};
use tachyon_web::tls::{Acme, KeyAlgorithm, Tls};
use tachyon_web::{Server, ServerInfo};

async fn pins(info: ServerInfo) -> String {
    info.certificates()
        .iter()
        .map(|cert| format!("{:?} {}\n", cert.algorithm, cert.sha256_hex()))
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), tachyon_web::Error> {
    let tls = Tls::new()
        .domains(["example.com"])
        .store("/var/lib/tachyon/tls") // keys persist, so pins stay valid
        .acme(Acme::lets_encrypt().contact("admin@example.com")) // browsers: CA-trusted P-256
        .self_signed(KeyAlgorithm::MlDsa87) // clients that offer ML-DSA
        .self_signed(KeyAlgorithm::EcdsaP521); // pinning clients that offer only P-521

    Server::new(Router::new().route("/.well-known/pins", get(pins)))
        .https("0.0.0.0:443", tls)
        .redirect("0.0.0.0:80")
        .serve()
        .await
}
```

TLS lets a client say which *algorithms* it verifies, not which *trust anchor* it wants — so a
browser that verifies P-521 would get a pinned P-521 certificate placed before the CA-issued one,
and reject it. Put what browsers must see first. Chrome does not verify P-521 at all, and no
browser verifies ML-DSA yet; those are for clients you control. See
[`examples/multi_cert.rs`](examples/multi_cert.rs).

## What the app can see

Handlers take a `ServerInfo` argument: every endpoint the server has published — including
`.onion` and `.b32.i2p` addresses, as soon as each network publishes them — and every certificate
it serves, with its chain, PEM, SHA-256 of the certificate and of its public key, algorithm,
issuer, names, expiry and the endpoints using it. Render mirror links, publish pins, or bind the
fingerprints into an attestation report. A `.onion` or `.b32.i2p` address is listed as soon as
it is known, with a `Reachability` saying whether its network confirms it reachable yet;
`Server::info()` returns the same handle for code outside a handler.

## Tor and I2P

The same app publishes as a Tor v3 onion service (on pure-Rust `arti-client`) or an I2P eepsite
(on an embedded `libi2pd`) with no external daemon and no SAM/BOB bridge — alongside clearnet
listeners, and each with its own optional `Tls` set. See
[`examples/onion_i2p_server.rs`](examples/onion_i2p_server.rs).

`i2p` is the one feature that links C++ through an FFI shim (`tachyon-i2p`/`i2pd-sys`), so it sits
outside the crate's `#![forbid(unsafe_code)]` guarantee. Read the `tachyon_web::i2p` module
docs before using it for anything security-sensitive.

## Examples

Run any example with `cargo run --example <name>`; each file's header lists the features it needs
and the commands to exercise it.

| Example | Shows |
|---|---|
| [`hello_world.rs`](examples/hello_world.rs) | path/query/JSON extraction, graceful shutdown |
| [`hardened_server.rs`](examples/hardened_server.rs) | host allow-listing, reverse-proxy trust, response hardening, limits — with `curl` commands for each rejection |
| [`self_signed_https.rs`](examples/self_signed_https.rs) | HTTPS + HTTP/3 + redirect with two self-signed algorithms |
| [`lets_encrypt.rs`](examples/lets_encrypt.rs) | production certificates issued and renewed in-process |
| [`multi_cert.rs`](examples/multi_cert.rs) | Let's Encrypt + ML-DSA + pinned P-521 on one endpoint, fingerprints published |
| [`onion_i2p_server.rs`](examples/onion_i2p_server.rs) | clearnet, Tor and I2P at once, with mirror links rendered from `ServerInfo` |

## Feature flags

Axum's own features (`json`, `ws`, `macros`, …) belong on your `axum` dependency. Tachyon's:

| Flag | Default | Enables |
|---|---|---|
| `http1` | on | HTTP/1.1 |
| `http2` | on | HTTP/2 over TLS, and h2c when `SecurityPolicy::allow_h2c` is set |
| `tracing` | on | transport-layer `tracing` events; nothing is emitted without a subscriber |
| `tls` | | TLS 1.3 via `rustls` + `aws-lc-rs`, and self-signed ECDSA / ML-DSA certificates |
| `tls12-legacy` | | additionally offer TLS 1.2, for clients without 1.3 |
| `http3` | | HTTP/3 over QUIC beside every HTTPS endpoint, via [`tachyon-quic`](https://crates.io/crates/tachyon-quic) |
| `acme` | | in-process ACME (Let's Encrypt, or any RFC 8555 CA) issuance and renewal |
| `fips` | | AWS-LC's FIPS 140-3 Level 1 module in approved mode, and the restricted TLS policy |
| `cnsa` | | the CNSA 2.0 profile: `fips`, TLS 1.3 AES-256-GCM, ML-KEM-1024, ML-DSA-87 only, no resumption; excludes `acme` |
| `tor` | | Tor v3 onion services via `arti-client` |
| `i2p` | | I2P eepsites via an embedded `libi2pd`. Links `unsafe` FFI — see [Tor and I2P](#tor-and-i2p) |

At least one of `http1`/`http2` must stay enabled; disabling both is a `compile_error!`.

## Minimum supported Rust version

Rust **1.92**. Raising it is a breaking change, announced in the release notes; while the crate
is `0.0.x` that still means a patch release can carry one.

## Acknowledgements

[Axum](https://github.com/tokio-rs/axum) *is* the application layer here — `Router`,
extractors, responses, and middleware come from your own `axum` dependency, unmodified. See
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
