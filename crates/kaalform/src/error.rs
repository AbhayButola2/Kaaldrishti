//! Kaalform error types.
//!
//! All error paths return `Result<_, KaalformError>`.
//! No `unwrap()` or `panic!()` is permitted in non-test code.

use thiserror::Error;

/// The unified error type for the kaalform crate.
#[derive(Debug, Error)]
pub enum KaalformError {
    /// I/O error from the TCP emitter or HTTP gateway.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protobuf encoding failure.
    #[error("protobuf encode error: {0}")]
    Protobuf(#[from] prost::EncodeError),

    /// Ed25519 signature verification failed (Pillar 4).
    #[error("manifest signature verification failed: {0}")]
    ManifestVerificationFailed(String),

    /// The tool manifest is missing required fields (Pillar 4).
    #[error("invalid tool manifest: {0}")]
    InvalidManifest(String),

    /// The tool manifest is not registered / unknown tool ID (Pillar 4).
    #[error("unknown tool in manifest: {tool_id}")]
    UnknownTool { tool_id: String },

    /// The signing key is not trusted (Pillar 4).
    #[error("untrusted signing key: {fingerprint}")]
    UntrustedKey { fingerprint: String },

    /// Context drift exceeded the configured threshold (Pillar 5).
    #[error("provenance drift too high: score={score:.3}, threshold={threshold:.3}, workflow_id={workflow_id}")]
    DriftExceeded {
        workflow_id: String,
        score: f64,
        threshold: f64,
    },

    /// The authorization receipt was denied by the policy engine (Pillar 5).
    #[error("authorization denied: {reason}")]
    AuthorizationDenied { reason: String },

    /// Serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// The connection to the upstream MCP server failed.
    #[error("upstream MCP error: {0}")]
    UpstreamMcp(String),

    /// The connection to the Kaaladrishti engine failed.
    #[error("Kaaladrishti emitter error: {0}")]
    EmitterConnection(String),
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, KaalformError>;
