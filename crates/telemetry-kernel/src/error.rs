//! Error types for the telemetry-kernel crate.
//!
//! All I/O and parse paths return `Result<_, TelemetryError>`. No `unwrap()`
//! or `panic!()` is permitted on any non-test code path.

use std::fmt;

/// The unified error type for the telemetry-kernel crate.
#[derive(Debug)]
pub enum TelemetryError {
    /// I/O error from the UDS transport or file system.
    Io(std::io::Error),

    /// Protobuf encoding or decoding failure.
    Protobuf(prost::EncodeError),

    /// Protobuf decoding failure.
    ProtobufDecode(prost::DecodeError),

    /// A telemetry event failed schema validation.
    Validation(String),

    /// The UDS connection was closed by the remote end.
    ConnectionClosed,

    /// Configuration error (e.g., invalid socket path or missing env var).
    Config(String),

    /// The source has been shut down and should not be polled further.
    SourceShutdown,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelemetryError::Io(e) => write!(f, "I/O error: {e}"),
            TelemetryError::Protobuf(e) => write!(f, "protobuf encode error: {e}"),
            TelemetryError::ProtobufDecode(e) => write!(f, "protobuf decode error: {e}"),
            TelemetryError::Validation(msg) => write!(f, "validation error: {msg}"),
            TelemetryError::ConnectionClosed => write!(f, "UDS connection closed by remote"),
            TelemetryError::Config(msg) => write!(f, "configuration error: {msg}"),
            TelemetryError::SourceShutdown => write!(f, "telemetry source has been shut down"),
        }
    }
}

impl std::error::Error for TelemetryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TelemetryError::Io(e) => Some(e),
            TelemetryError::Protobuf(e) => Some(e),
            TelemetryError::ProtobufDecode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TelemetryError {
    fn from(e: std::io::Error) -> Self {
        TelemetryError::Io(e)
    }
}

impl From<prost::EncodeError> for TelemetryError {
    fn from(e: prost::EncodeError) -> Self {
        TelemetryError::Protobuf(e)
    }
}

impl From<prost::DecodeError> for TelemetryError {
    fn from(e: prost::DecodeError) -> Self {
        TelemetryError::ProtobufDecode(e)
    }
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, TelemetryError>;
