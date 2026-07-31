//! Single aggregated parity-test binary.
//!
//! Each suite here used to be its own `tests/*.rs` file. Every one of them links the same
//! heavy dependency set (`tachyon-web` built with `tls`, `http2`, `cert-gen`, `tower`, `ws`,
//! `sse`, plus `axum` for the golden-response comparison), so five separate files meant
//! paying that link cost five times over. Folding them into modules of one binary keeps the
//! suite boundaries while linking once.

mod edge_cases;
mod extractors;
mod nesting_and_matched_path;
mod routing_basics;
mod sse;
