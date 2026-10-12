//! kaalform — Agent Execution Firewall for Kaaladrishti
//!
//! Kaalform is the companion runtime-security enforcement layer that implements:
//!
//! - **Pillar 4: Cryptographic Tool-Manifest Signing & Verification**
//!   Every MCP tool must carry a cryptographically signed manifest (Ed25519).
//!   Kaalform verifies the signature against the platform's trusted public keys
//!   before allowing the tool call to proceed. Unsigned or tampered manifests
//!   are rejected and result in a `ManifestViolation` provenance event.
//!
//! - **Pillar 5: Context-to-Action Provenance Firewall**
//!   Kaalform tracks the declared intent (system prompt / AgentPlan) and the
//!   actual MCP tool calls made, computing a cosine drift score in real time.
//!   When the drift score exceeds the configured threshold, Kaalform:
//!     1. Emits an `AuthorizationReceipt` with DENIED status.
//!     2. Refuses to forward the tool call to the downstream MCP server.
//!     3. Streams a `TelemetryEvent` (GraphDelta containing ContextArtifact,
//!        MemoryEntry, AgentPlan, Action, and AuthorizationReceipt nodes) to
//!        the Kaaladrishti Go engine for SOC analysis.
//!
//! ## Architecture
//!
//! ```text
//! AI Agent / LLM Workflow
//!      │
//!      │  POST /mcp/v1/call  (JSON)
//!      ▼
//! ┌─────────────────────────────────────────────┐
//! │            KAALFORM MCP GATEWAY             │
//! │                                             │
//! │  [Pillar 4: ManifestVerifier]               │
//! │   verify Ed25519 signature on tool manifest │
//! │                                             │
//! │  [Pillar 5: ProvenanceFirewall]             │
//! │   compute context drift score (cosine)      │
//! │   gate by threshold; issue AuthReceipt      │
//! │                                             │
//! │  [ProvenanceEmitter]                        │
//! │   encode GraphDelta → TelemetryEvent        │
//! │   stream to Kaaladrishti engine over TCP    │
//! └──────┬───────────────────────┬──────────────┘
//!        │ DENIED                │ ALLOWED
//!        ▼                       ▼
//!   Returns 403             Upstream MCP Server
//!   to agent                (actual tool execution)
//! ```
//!
//! ## Safety
//!
//! `#![forbid(unsafe_code)]` is enforced. The Ed25519 cryptography uses
//! `ed25519-dalek`, which has been audited and is pure Rust.
//!
//! ## Extension Points
//!
//! - `verifier::ManifestVerifier` — add new key-management backends (KMS, HSM)
//!   by implementing the `KeyStore` trait.
//! - `provenance::ProvenanceFirewall` — extend the drift model by replacing the
//!   cosine scorer with a neural embedding model (Pillar 5 v2).

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod emitter;
pub mod error;
pub mod gateway;
pub mod manifest;
pub mod provenance;
pub mod verifier;

/// Re-export generated Protobuf types.
#[allow(missing_docs)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/kaaladrishti.v1.rs"));
}
