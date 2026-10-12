//! Future eBPF telemetry source stub.
//!
//! This module is compiled ONLY when `--features ebpf` is passed to cargo.
//! In the default build it compiles to nothing.
//!
//! # Why This Stub Exists
//!
//! The eBPF source is the intended long-term replacement for the synthetic source,
//! providing real OS-level telemetry via Linux kernel probes. It is excluded from
//! Phases 1-11 because:
//!
//! 1. Requires kernel headers and a privileged build environment.
//! 2. Would require `unsafe` code for the eBPF FFI boundary — which must live in
//!    its own isolated crate, not here (this crate is `#![forbid(unsafe_code)]`).
//! 3. Out of scope for the academic prototype.
//!
//! # Extension Design
//!
//! When implementing the real eBPF source:
//! 1. Create a separate crate (`crates/ebpf-sensor/`) with its own `#[allow(unsafe_code)]`
//!    and a written justification in `Cargo.toml`.
//! 2. That crate implements `TelemetrySource` and emits the same `TelemetryEvent`
//!    protobuf messages over UDS.
//! 3. This stub file can be deleted or replaced with a thin re-export.
//!
//! # Safety
//!
//! No unsafe code is permitted in this stub or this crate. `#![forbid(unsafe_code)]`
//! at the crate root enforces this at compile time.

// TODO(phase-future): Implement EBPFTelemetrySource in a separate crate.
// See docs/architecture/deferred_work.md for the full extension plan.

use crate::error::Result;
use crate::model::TelemetryEvent;
use crate::source::TelemetrySource;
use async_trait::async_trait;

/// Unimplemented stub for the future eBPF telemetry source.
///
/// Calling any method on this type will panic with a clear message directing
/// the developer to the deferred work documentation.
///
/// # PROTOTYPE NOTE
///
/// This type is a compile-time extension point only. It is never instantiated
/// in Phases 1-11.
pub struct FutureEBPFTelemetrySource {
    _private: (),
}

impl FutureEBPFTelemetrySource {
    /// Attempting to construct this source will panic.
    ///
    /// # Panics
    ///
    /// Always panics with a message directing to the deferred work docs.
    pub fn new() -> Self {
        panic!(
            "FutureEBPFTelemetrySource is not implemented. \
             See docs/architecture/deferred_work.md for the eBPF extension plan."
        );
    }
}

#[async_trait]
impl TelemetrySource for FutureEBPFTelemetrySource {
    async fn start(&mut self) -> Result<()> {
        unimplemented!("FutureEBPFTelemetrySource: see docs/architecture/deferred_work.md")
    }

    async fn next_event(&mut self) -> Result<TelemetryEvent> {
        unimplemented!("FutureEBPFTelemetrySource: see docs/architecture/deferred_work.md")
    }

    async fn shutdown(&mut self) -> Result<()> {
        unimplemented!("FutureEBPFTelemetrySource: see docs/architecture/deferred_work.md")
    }

    fn source_id(&self) -> &str {
        "ebpf-stub-unimplemented"
    }
}
