# Tachyon-Web

[![Crates.io](https://img.shields.io/crates/v/tachyon-web.svg)](https://crates.io/crates/tachyon-web)
[![Docs.rs](https://img.shields.io/docsrs/tachyon-web)](https://docs.rs/tachyon-web)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](#minimum-supported-rust-version)

> ## ⚠️ Pre-release software — read before depending on this
>
> Tachyon-Web is **pre-1.0, and pre-0.1** (`0.0.x`) — it hasn't had a single
> "somehow stable" release yet. That means:
>
> - **Breaking changes can land in any release** while we're still at `0.0.x`.
> - **Logical bugs are expected to exist.** We cannot guarantee this crate is
>   free of them — no team can honestly claim that about a project this size,
>   least of all a young one. What we *can* guarantee: every line compiles
>   under `#![forbid(unsafe_code)]` (a hard compiler error if violated, not a
>   promise), and the code follows established best practices for input
>   handling, resource limits, and request lifecycle management throughout.
>   That makes the *memory-safety* class of bugs (buffer overflows, use-after-free,
>   data races) essentially off the table, and meaningfully lowers — but does
>   **not** eliminate — the risk of things like resource-exhaustion (DoS) bugs
>   or accidental data exposure. Best practices reduce risk; they don't prove
>   its absence, especially in a project this young.
> - **This is not (yet) a mainstream, battle-tested crate.** If you're building
>   something where an outage or a security incident is unacceptable — payments,
>   healthcare, anything regulated, anything with a real on-call rotation — use
>   [`axum`](https://crates.io/crates/axum) instead. It's maintained by a real
>   team, it's been in production at scale for years, and that track record is
>   worth more than anything on this page.
>
> **Where Tachyon-Web *does* fit:** side projects, internal tools, prototypes,
> and anyone enthusiastic about a framework that pairs Axum's API with more
> aggressive performance work and some genuinely nice quality-of-life defaults.
> If that's you — for a non-critical workload, or just to kick the tires — we'd
> genuinely love for you to try it and tell us what broke. A crate like this
> only gets to grow up into something people can rely on if people are willing
> to use it early and report back. We're not going to pretend we're something
> we're not, but we're also not going to pretend adoption doesn't matter.

A high-performance, multi-protocol web framework for Rust, built natively on
[`hyper`](https://docs.rs/hyper) and [`s2n-quic`](https://docs.rs/s2n-quic).

Tachyon-Web in one sentence: **Axum's API and safety story, Actix's performance
instincts, and Salvo's "batteries-included" approach to the stuff every real
deployment eventually needs** — HTTP/1.1, HTTP/2 (including cleartext h2c),
HTTP/3, and fully automatic Let's Encrypt certificate management, all built in
rather than assembled from five separate crates.

## Why Tachyon-Web

- **Axum's API, kept.** `Router`, `.route()`, and typed extractors (`Path`,
  `Query`, `Json`, `State`) work the way you already expect, and the Cargo
  feature flags are deliberately named and defaulted to match Axum's own (see
  [Feature flags](#feature-flags)) — porting a handler over should feel like
  nothing changed. The one deliberate departure is middleware: Tachyon-Web uses
  its own native `.hoop()` middleware instead of `tower::Layer`, to avoid the
  overhead Tower's generic `Service` abstraction introduces on the hot path.
  Tower middleware/services remain available as an opt-in bridge (the `tower`
  feature) for when reusing an existing `tower-http` layer is worth more than
  that overhead.
- **Actix-tier performance, without giving up safety.** Per-core
  `SO_REUSEPORT` worker threads, allocation-free routing for the common case
  (arity-0 handlers, no path params), zero-copy static file serving with an
  in-memory cache, and lock-free hot paths — all with `#![forbid(unsafe_code)]`
  enforced crate-wide. We benchmark directly against Axum and Actix-Web (see
  `benches/`) and treat any regression against either as a bug.
  - This is a live, working effort, not a settled claim — we still track a
    concrete, measured gap against Actix (currently ~340k vs ~300k req/sec on
    identical hardware for the same trivial handler, see `benches/optimistic`).
    We'd rather be honest about an open gap than assert we're "fast" and leave
    it at that.
- **Salvo-style batteries included.** Starting an HTTPS server is one call.
  Automatic Let's Encrypt provisioning, renewal, and zero-downtime hot-swap
  are built in — no external CLI tools, shell scripts, or cron jobs. HTTP/1.1,
  HTTP/2 (cleartext or over TLS), and HTTP/3 (QUIC) are handled by the same
  `Router` and the same handlers; you choose which protocols to serve at the
  `Server` call site, not at the routing layer.
- **Native `.onion` and `.i2p` support, no sidecar processes.** Publish the
  same `Router` directly as a Tor v3 hidden service (`Server::serve_onion`,
  built on pure-Rust `arti-client`/`tor-hsservice` — no external `tor` daemon)
  or an I2P eepsite (`Server::serve_i2p`, built on an embedded `libi2pd` — no
  external `i2pd` process, no SAM/BOB bridge), including simultaneously
  alongside your regular clearnet listener. See
  [`examples/onion_i2p_server.rs`](examples/onion_i2p_server.rs) and the
  `tor`/`i2p` feature flags below.

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

More complete examples (path/query/JSON extraction, middleware, shared state,
static file serving, sync handlers, serving over Tor/I2P) live in
[`examples/`](examples/) and run with `cargo run --example <name>` (some,
like `onion_i2p_server`, need extra feature flags — see the example file).

## HTTPS, in one call

For development, generate a throwaway self-signed certificate:

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

For production, `serve_all_acme` handles the entire Let's Encrypt lifecycle —
account registration, the HTTP-01 challenge flow, disk caching, and renewal
30 days before expiry — with no separate tooling:

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

## Feature flags

Every flag below is real and load-bearing — it's either compiled into a
default build right now, or it gates actual code and dependencies that
disappear when it's off. If a flag is listed, flipping it does something.

Where a capability also exists in Axum, we kept Axum's own flag name and
default so porting a `Cargo.toml` over is a non-event:

| Flag | Default | Enables |
|---|---|---|
| `http1` | ✅ | Enables hyper's `http1` support |
| `http2` | ✅ | Enables hyper's `http2` support. Over plain TCP this is cleartext HTTP/2 ("h2c" — `serve_http` detects the connection preface, no ALPN/TLS needed); over TLS it's negotiated via ALPN. **Note:** Axum ships `http2` off by default — Tachyon ships it on, since h2c-with-zero-config is a deliberate differentiator |
| `json` | ✅ | Enables the `Json` extractor/response type (and the `serde_json` dependency) |
| `matched-path` | ✅ | Enables capturing of every request's router path and the `MatchedPath` extractor |
| `original-uri` | ✅ | Enables capturing of every request's original URI and the `OriginalUri` extractor |
| `form` | ✅ | Enables the `Form` extractor |
| `query` | ✅ | Enables the `Query` extractor |
| `cookies` | ✅ | Enables request `Cookie` parsing and the `Cookies` extractor/`IntoResponseParts` jar (matching `axum-extra`'s `CookieJar`), and the `cookie` dependency it needs |
| `tower-log` | ✅ | Enables `tower`'s own `log` feature — only has an effect together with the `tower` feature below |
| `ws` |  | WebSocket support (RFC 6455) |

Tachyon's own additions, beyond anything Axum has — matching how Axum treats
its own extras like `ws`, these default off too:

| Flag | Default | Enables |
|---|---|---|
| `tls` |  | TLS via `rustls` + `aws-lc-rs` |
| `cert-gen` |  | Self-signed certificate generation (`tls::generate_self_signed_cert`); requires `tls` |
| `http3` |  | HTTP/3 over QUIC via `s2n-quic`; requires `tls` |
| `lets-encrypt` |  | Fully automatic Let's Encrypt certificate management; requires `tls`, `cert-gen` |
| `sse` |  | Server-Sent Events (`response::sse::{Event, Sse, KeepAlive}`) |
| `tower` |  | Bridge `tower::Service`/`tower::Layer` (e.g. existing `tower-http` layers) into the router — also implements `tower::Service` for `CompiledRouter` so `app.oneshot(req)` works |
| `fips` |  | Enforce FIPS-mode cryptography at startup; refuses to start otherwise |
| `tor` |  | Native Tor v3 `.onion` hidden-service support (`Server::serve_tor`/`serve_onion`), via pure-Rust `arti-client`/`tor-hsservice` — no external `tor` daemon |
| `i2p` |  | Native I2P `.b32.i2p` eepsite support (`Server::serve_i2p`/`serve_i2p_config`), via an embedded `libi2pd` router — no external `i2pd` process. **Note:** unlike every other feature in this crate, `i2p` links C++ code through an FFI shim (`tachyon-i2p`/`i2pd-sys`), so it does not sit behind the crate's `#![forbid(unsafe_code)]` guarantee — see `tachyon_web::server::i2p` module docs before using it for anything security-sensitive |

At least one of `http1`/`http2` must stay enabled (there's a friendly
`compile_error!` if you disable both — a server with no protocol support isn't
meaningful). Enable only what you need, e.g. HTTP/1.1 + HTTP/2 + TLS with
everything else off:

```toml
tachyon-web = { version = "0.0.1", default-features = false, features = ["http1", "http2", "tls"] }
```

Or the smallest possible build — HTTP/1.1 cleartext only, no JSON/Form/Query/
MatchedPath/OriginalUri, no TLS, no crypto deps at all:

```toml
tachyon-web = { version = "0.0.1", default-features = false, features = ["http1"] }
```

### HTTP/2 over cleartext (h2c)

With the (default) `http2` feature, `Server::serve_http` transparently speaks
HTTP/2 over plain, unencrypted TCP — no TLS, no ALPN. This is "h2c" / "HTTP/2
with prior knowledge": the server peeks at each connection's first bytes and
switches to an HTTP/2 stack if it sees the HTTP/2 client preface, falling back
to HTTP/1.1 otherwise. Browsers don't support it (they only ever negotiate
HTTP/2 via TLS ALPN), but plenty of non-browser clients do — `curl
--http2-prior-knowledge`, gRPC clients, and internal service meshes where TLS
is terminated upstream (a load balancer, a sidecar) and re-encrypting hop-by-hop
would be redundant.

## Minimum supported Rust version

Rust **1.92**, edition 2024. Bumping the MSRV is not considered a breaking
change while the crate is pre-1.0.

## Acknowledgements

Tachyon-Web didn't arrive at its design in a vacuum — it's a deliberate
synthesis of ideas we admired in three existing frameworks, and it wouldn't
look the way it does without them:

- **[Axum](https://github.com/tokio-rs/axum)** is the project's main
  inspiration and the reason the API looks the way it does. `Router`,
  extractors, `IntoResponse`, the whole ergonomic shape of writing a handler —
  we didn't invent that, Axum did, and did it well enough that reimplementing
  it natively (rather than just depending on it) still felt worth doing. Any
  time this README says "matches Axum," it means we went and checked, not that
  we assumed.
- **[Actix Web](https://github.com/actix/actix-web)** is where most of our
  performance instincts come from. Per-core `SO_REUSEPORT` worker threads,
  thread-local buffer reuse, and a healthy respect for what a per-request
  allocation actually costs at hundreds of thousands of requests per second —
  these are lessons the Actix team learned and published (in code, in
  benchmarks, in years of TechEmpower results) well before we came along to
  learn from them.
- **[Salvo](https://github.com/salvo-rs/salvo)** shaped our thinking on
  quality of life: that a web framework can just *handle* TLS, HTTP/3, and
  Let's Encrypt certificate management as first-class, built-in features,
  instead of making every user assemble that themselves from five different
  crates. That "batteries included, not bolted on" instinct is directly
  downstream of seeing Salvo do it first.

Thank you to the maintainers and contributors of all three projects — for
the code, the design decisions, and the prior art. We're grateful, and we
mean it.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
