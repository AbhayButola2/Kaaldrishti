//! TelemetrySource trait and source implementations.
//!
//! # Extension Points
//!
//! - `SyntheticTelemetrySource`: the only concrete implementation in Phases 1-11.
//! - `ebpf_stub`: feature-gated future eBPF sensor stub (compiled out by default).
//!
//! To add a new source:
//! 1. Implement `TelemetrySource` in a new module.
//! 2. Register it in `cmd/engine/main.go`'s Rust config — no changes to this module needed.

pub mod synthetic;
pub mod live_network;

// Future eBPF source stub — compiled out unless `--features ebpf` is passed.
// This module contains no runnable code; it is a documented extension point.
// Any real eBPF implementation must live in its own isolated crate with a
// written justification for the unsafe boundary. #![forbid(unsafe_code)] in
// this crate prevents any unsafe code here regardless.
#[cfg(feature = "ebpf")]
pub mod ebpf_stub;

use async_trait::async_trait;

use crate::error::Result;
use crate::model::TelemetryEvent;

/// The core abstraction for a telemetry event source.
///
/// Implementors produce a stream of `TelemetryEvent`s. The transport layer
/// reads from this trait and serializes events to the Go engine via UDS.
///
/// # Lifecycle
///
/// 1. `start()` — initialize any resources, begin generating/receiving events.
/// 2. `next_event()` — called in a loop by the transport driver; blocks until
///    an event is available or the source is shut down.
/// 3. `shutdown()` — signal the source to stop; subsequent `next_event()` calls
///    must return `Err(TelemetryError::SourceShutdown)`.
///
/// # Error Handling
///
/// All methods return `Result<_>`. No implementation may panic on any I/O or
/// parse path. A `SourceShutdown` error is the expected terminal condition.
#[async_trait]
pub trait TelemetrySource: Send + Sync + 'static {
    /// Initialize the source. Called once before the first `next_event()`.
    async fn start(&mut self) -> Result<()>;

    /// Return the next event. Blocks until an event is available.
    /// Returns `Err(TelemetryError::SourceShutdown)` when the source is done.
    async fn next_event(&mut self) -> Result<TelemetryEvent>;

    /// Signal the source to stop generating events.
    async fn shutdown(&mut self) -> Result<()>;

    /// Return a human-readable identifier for this source (used in logs).
    fn source_id(&self) -> &str;
}
