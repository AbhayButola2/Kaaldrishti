//! telemetry-kernel — Kaaladrishti telemetry source and transport
//!
//! This crate implements the `TelemetrySource` trait and the `SyntheticTelemetrySource`
//! concrete implementation, plus the protobuf-over-UDS transport to the Go engine.
//!
//! # Safety
//!
//! `#![forbid(unsafe_code)]` is enforced at the crate root. Any future unsafe
//! boundary (e.g., real eBPF) must live in its own isolated crate with a written
//! justification — never in this crate.
//!
//! # Architecture
//!
//! ```text
//! TelemetrySource (trait)
//!   └── SyntheticTelemetrySource (impl) ──► TelemetryEvent (protobuf)
//!                                                  │
//!                                                  ▼
//!                                         UdsTransport (length-prefixed)
//!                                                  │
//!                                                  ▼
//!                                    Unix Domain Socket → Go engine
//! ```
//!
//! # Extension Points
//!
//! - `source::ebpf_stub` — feature-gated future eBPF source stub (not functional,
//!   compiles to nothing without `--features ebpf`).

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
// Allow clippy::module_name_repetitions for idiomatic Rust module naming.
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod model;
pub mod source;
pub mod transport;

/// Re-export generated protobuf types for consumers.
#[allow(missing_docs)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/kaaladrishti.v1.rs"));
}
