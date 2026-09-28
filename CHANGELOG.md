# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, a minor bump (`0.x`) is where breaking changes land; patch releases stay
compatible. While the crate is `0.0.x`, every release may break.

## Unreleased

A rewrite around real Axum: Tachyon is now the transport layer only, and the app is written
against your own `axum` 0.8 dependency.

### Changed

- **Breaking:** `Server::new` takes an `axum::Router`. The built-in routing, extractors and
  WebSocket layer are removed; use Axum's.
- **Breaking:** transports are added with `.http`, `.https`, `.redirect`, `.onion` and `.i2p`,
  then `serve()`, replacing `with_http`/`with_https`/`with_h3`/`with_onion`/`with_i2p` and
  `MultiServer`. The whole configuration is validated and bound before the first request.
- **Breaking:** HTTPS is configured with a `Tls` set holding any mix of ACME, self-signed and
  provided certificates, replacing `RustlsConfig` and raw `rustls::ServerConfig`.
- **Breaking:** HTTP/3 runs on `tachyon-quic` instead of `s2n-quic`/`h3`.
- **Breaking:** the `lets-encrypt` and `cert-gen` features are replaced by `acme` (any RFC 8555
  CA); self-signed certificate generation is part of `tls`.
- **Breaking:** the `json`, `form`, `query`, `cookies`, `sse`, `ws`, `matched-path`,
  `original-uri`, `tower` and `tower-log` features are removed; enable them on `axum`.
- `fips` now implies `tls`.
- License changed from `MIT OR Apache-2.0` to `0BSD`.

### Added

- `ServerInfo`: published endpoints (including `.onion` and `.b32.i2p` addresses with their
  `Reachability`) and served certificates with fingerprints, available to handlers and via
  `Server::info()`.
- Self-signed ML-DSA and ECDSA certificates via `KeyAlgorithm`, with persistent keys through
  `Tls::store`.
- `TlsPolicy` key-exchange and cipher selection (`KeyExchange`, `Cipher`), including ML-KEM
  hybrids.
- `SecurityPolicy`, including opt-in h2c via `allow_h2c`.
- `tracing` feature (default) for transport-layer events.
- `tls12-legacy` feature to additionally offer TLS 1.2.
- `cnsa` feature for the CNSA 2.0 profile.
