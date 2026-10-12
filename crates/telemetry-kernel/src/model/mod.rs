//! Typed domain model for telemetry events.
//!
//! The types here mirror the protobuf `TelemetryEvent` message exactly.
//! Any divergence between these types and the proto schema is a bug.
//! The `From` implementations convert domain types → proto types for
//! serialization; the reverse direction is used in tests and in the
//! Go stub receiver for deserialization validation.
//!
//! # Design Rationale
//!
//! We maintain a separate domain model (rather than using prost-generated
//! types directly) because:
//! 1. Prost types carry `Option<>` for every message field, which is
//!    ergonomically noisy for a crate that constructs many events.
//! 2. Domain types enforce invariants (e.g., non-empty `event_id`) at
//!    construction time, before serialization.
//! 3. This separation makes it possible to swap prost for a different
//!    serialization backend (e.g., flatbuffers) without touching the
//!    source or transport layers.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::error::{Result, TelemetryError};
use crate::proto;

/// The schema version embedded in every TelemetryEvent.
/// Must match the protobuf package version: `kaaladrishti.v1`.
pub const SCHEMA_VERSION: &str = "kaaladrishti.v1";

/// A validated, typed telemetry event ready for serialization.
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    /// Globally unique event identifier (UUIDv4).
    pub event_id: String,
    /// Unix epoch milliseconds at event creation.
    pub timestamp_ms: i64,
    /// Source identifier (host, sensor, or synthetic generator label).
    pub source_id: String,
    /// Typed event payload.
    pub payload: EventPayload,
}

impl TelemetryEvent {
    /// Create a new event with a fresh UUIDv4 and current timestamp.
    ///
    /// # Errors
    /// Returns `TelemetryError::Validation` if `source_id` is empty.
    pub fn new(source_id: impl Into<String>, payload: EventPayload) -> Result<Self> {
        let source_id = source_id.into();
        if source_id.is_empty() {
            return Err(TelemetryError::Validation(
                "source_id must not be empty".to_string(),
            ));
        }
        Ok(Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp_ms: now_ms(),
            source_id,
            payload,
        })
    }

    /// Convert this domain event to the protobuf wire type.
    #[must_use]
    pub fn to_proto(&self) -> proto::TelemetryEvent {
        proto::TelemetryEvent {
            event_id: self.event_id.clone(),
            timestamp_ms: self.timestamp_ms,
            source_id: self.source_id.clone(),
            schema_version: SCHEMA_VERSION.to_string(),
            payload: Some(self.payload.to_proto_payload()),
        }
    }

    /// Reconstruct a domain event from a protobuf wire type.
    ///
    /// # Errors
    /// Returns `TelemetryError::Validation` if required fields are missing or invalid.
    pub fn from_proto(p: proto::TelemetryEvent) -> Result<Self> {
        if p.event_id.is_empty() {
            return Err(TelemetryError::Validation("event_id is empty".into()));
        }
        if p.source_id.is_empty() {
            return Err(TelemetryError::Validation("source_id is empty".into()));
        }
        let payload_proto = p
            .payload
            .ok_or_else(|| TelemetryError::Validation("payload is missing".into()))?;
        Ok(Self {
            event_id: p.event_id,
            timestamp_ms: p.timestamp_ms,
            source_id: p.source_id,
            payload: EventPayload::from_proto_payload(payload_proto)?,
        })
    }
}

/// The typed payload variants mirroring the proto `oneof payload`.
#[derive(Debug, Clone)]
pub enum EventPayload {
    Process(ProcessEvent),
    Network(NetworkEvent),
    Identity(IdentityEvent),
    File(FileEvent),
    Registry(RegistryEvent),
}

impl EventPayload {
    fn to_proto_payload(&self) -> proto::telemetry_event::Payload {
        match self {
            EventPayload::Process(e) => {
                proto::telemetry_event::Payload::ProcessEvent(e.to_proto())
            }
            EventPayload::Network(e) => {
                proto::telemetry_event::Payload::NetworkEvent(e.to_proto())
            }
            EventPayload::Identity(e) => {
                proto::telemetry_event::Payload::IdentityEvent(e.to_proto())
            }
            EventPayload::File(e) => proto::telemetry_event::Payload::FileEvent(e.to_proto()),
            EventPayload::Registry(e) => {
                proto::telemetry_event::Payload::RegistryEvent(e.to_proto())
            }
        }
    }

    fn from_proto_payload(p: proto::telemetry_event::Payload) -> Result<Self> {
        match p {
            proto::telemetry_event::Payload::ProcessEvent(e) => {
                Ok(EventPayload::Process(ProcessEvent::from_proto(e)?))
            }
            proto::telemetry_event::Payload::NetworkEvent(e) => {
                Ok(EventPayload::Network(NetworkEvent::from_proto(e)?))
            }
            proto::telemetry_event::Payload::IdentityEvent(e) => {
                Ok(EventPayload::Identity(IdentityEvent::from_proto(e)?))
            }
            proto::telemetry_event::Payload::FileEvent(e) => {
                Ok(EventPayload::File(FileEvent::from_proto(e)?))
            }
            proto::telemetry_event::Payload::RegistryEvent(e) => {
                Ok(EventPayload::Registry(RegistryEvent::from_proto(e)?))
            }
        }
    }
}

/// Process lifecycle event.
#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub process_id: String,
    pub parent_pid: String,
    pub image_path: String,
    pub command_line: String,
    pub user_id: String,
    pub host_id: String,
    pub action: ProcessAction,
}

/// Process action enum mirroring proto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAction {
    Spawn,
    Terminate,
    LoadModule,
}

impl ProcessEvent {
    fn to_proto(&self) -> proto::ProcessEvent {
        proto::ProcessEvent {
            process_id: self.process_id.clone(),
            parent_pid: self.parent_pid.clone(),
            image_path: self.image_path.clone(),
            command_line: self.command_line.clone(),
            user_id: self.user_id.clone(),
            host_id: self.host_id.clone(),
            action: match self.action {
                ProcessAction::Spawn => proto::process_event::ProcessAction::Spawn as i32,
                ProcessAction::Terminate => {
                    proto::process_event::ProcessAction::Terminate as i32
                }
                ProcessAction::LoadModule => {
                    proto::process_event::ProcessAction::LoadModule as i32
                }
            },
        }
    }

    fn from_proto(p: proto::ProcessEvent) -> Result<Self> {
        if p.process_id.is_empty() {
            return Err(TelemetryError::Validation("ProcessEvent.process_id empty".into()));
        }
        let action = match proto::process_event::ProcessAction::try_from(p.action) {
            Ok(proto::process_event::ProcessAction::Spawn) => ProcessAction::Spawn,
            Ok(proto::process_event::ProcessAction::Terminate) => ProcessAction::Terminate,
            Ok(proto::process_event::ProcessAction::LoadModule) => ProcessAction::LoadModule,
            _ => {
                return Err(TelemetryError::Validation(
                    format!("unknown ProcessAction value: {}", p.action),
                ))
            }
        };
        Ok(Self {
            process_id: p.process_id,
            parent_pid: p.parent_pid,
            image_path: p.image_path,
            command_line: p.command_line,
            user_id: p.user_id,
            host_id: p.host_id,
            action,
        })
    }
}

/// Network connection event.
#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub process_id: String,
    pub host_id: String,
    pub src_ip: String,
    pub src_port: i32,
    pub dst_ip: String,
    pub dst_port: i32,
    pub protocol: String,
    pub direction: NetworkDirection,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
}

/// Network direction enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkDirection {
    Outbound,
    Inbound,
}

impl NetworkEvent {
    fn to_proto(&self) -> proto::NetworkEvent {
        proto::NetworkEvent {
            process_id: self.process_id.clone(),
            host_id: self.host_id.clone(),
            src_ip: self.src_ip.clone(),
            src_port: self.src_port,
            dst_ip: self.dst_ip.clone(),
            dst_port: self.dst_port,
            protocol: self.protocol.clone(),
            direction: match self.direction {
                NetworkDirection::Outbound => {
                    proto::network_event::NetworkDirection::Outbound as i32
                }
                NetworkDirection::Inbound => {
                    proto::network_event::NetworkDirection::Inbound as i32
                }
            },
            bytes_sent: self.bytes_sent,
            bytes_recv: self.bytes_recv,
        }
    }

    fn from_proto(p: proto::NetworkEvent) -> Result<Self> {
        let direction = match proto::network_event::NetworkDirection::try_from(p.direction) {
            Ok(proto::network_event::NetworkDirection::Outbound) => NetworkDirection::Outbound,
            Ok(proto::network_event::NetworkDirection::Inbound) => NetworkDirection::Inbound,
            _ => NetworkDirection::Outbound, // default for unspecified
        };
        Ok(Self {
            process_id: p.process_id,
            host_id: p.host_id,
            src_ip: p.src_ip,
            src_port: p.src_port,
            dst_ip: p.dst_ip,
            dst_port: p.dst_port,
            protocol: p.protocol,
            direction,
            bytes_sent: p.bytes_sent,
            bytes_recv: p.bytes_recv,
        })
    }
}

/// Identity / authentication event.
#[derive(Debug, Clone)]
pub struct IdentityEvent {
    pub principal_id: String,
    pub credential_id: String,
    pub host_id: String,
    pub target_resource: String,
    pub action: IdentityAction,
    pub success: bool,
}

/// Identity action enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAction {
    Login,
    Logout,
    PrivilegeEscalation,
    RoleAssumption,
    CredentialUse,
    AuthFailure,
}

impl IdentityEvent {
    fn to_proto(&self) -> proto::IdentityEvent {
        proto::IdentityEvent {
            principal_id: self.principal_id.clone(),
            credential_id: self.credential_id.clone(),
            host_id: self.host_id.clone(),
            target_resource: self.target_resource.clone(),
            action: match self.action {
                IdentityAction::Login => proto::identity_event::IdentityAction::Login as i32,
                IdentityAction::Logout => proto::identity_event::IdentityAction::Logout as i32,
                IdentityAction::PrivilegeEscalation => {
                    proto::identity_event::IdentityAction::PrivilegeEscalation as i32
                }
                IdentityAction::RoleAssumption => {
                    proto::identity_event::IdentityAction::RoleAssumption as i32
                }
                IdentityAction::CredentialUse => {
                    proto::identity_event::IdentityAction::CredentialUse as i32
                }
                IdentityAction::AuthFailure => {
                    proto::identity_event::IdentityAction::AuthFailure as i32
                }
            },
            success: self.success,
        }
    }

    fn from_proto(p: proto::IdentityEvent) -> Result<Self> {
        if p.principal_id.is_empty() {
            return Err(TelemetryError::Validation(
                "IdentityEvent.principal_id empty".into(),
            ));
        }
        let action = match proto::identity_event::IdentityAction::try_from(p.action) {
            Ok(proto::identity_event::IdentityAction::Login) => IdentityAction::Login,
            Ok(proto::identity_event::IdentityAction::Logout) => IdentityAction::Logout,
            Ok(proto::identity_event::IdentityAction::PrivilegeEscalation) => {
                IdentityAction::PrivilegeEscalation
            }
            Ok(proto::identity_event::IdentityAction::RoleAssumption) => {
                IdentityAction::RoleAssumption
            }
            Ok(proto::identity_event::IdentityAction::CredentialUse) => {
                IdentityAction::CredentialUse
            }
            Ok(proto::identity_event::IdentityAction::AuthFailure) => IdentityAction::AuthFailure,
            _ => {
                return Err(TelemetryError::Validation(
                    format!("unknown IdentityAction value: {}", p.action),
                ))
            }
        };
        Ok(Self {
            principal_id: p.principal_id,
            credential_id: p.credential_id,
            host_id: p.host_id,
            target_resource: p.target_resource,
            action,
            success: p.success,
        })
    }
}

/// File system event.
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub process_id: String,
    pub host_id: String,
    pub file_path: String,
    pub user_id: String,
    pub action: FileAction,
    pub bytes: i64,
}

/// File action enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAction {
    Read,
    Write,
    Delete,
    Rename,
}

impl FileEvent {
    fn to_proto(&self) -> proto::FileEvent {
        proto::FileEvent {
            process_id: self.process_id.clone(),
            host_id: self.host_id.clone(),
            file_path: self.file_path.clone(),
            user_id: self.user_id.clone(),
            action: match self.action {
                FileAction::Read => proto::file_event::FileAction::Read as i32,
                FileAction::Write => proto::file_event::FileAction::Write as i32,
                FileAction::Delete => proto::file_event::FileAction::Delete as i32,
                FileAction::Rename => proto::file_event::FileAction::Rename as i32,
            },
            bytes: self.bytes,
        }
    }

    fn from_proto(p: proto::FileEvent) -> Result<Self> {
        let action = match proto::file_event::FileAction::try_from(p.action) {
            Ok(proto::file_event::FileAction::Read) => FileAction::Read,
            Ok(proto::file_event::FileAction::Write) => FileAction::Write,
            Ok(proto::file_event::FileAction::Delete) => FileAction::Delete,
            Ok(proto::file_event::FileAction::Rename) => FileAction::Rename,
            _ => {
                return Err(TelemetryError::Validation(
                    format!("unknown FileAction value: {}", p.action),
                ))
            }
        };
        Ok(Self {
            process_id: p.process_id,
            host_id: p.host_id,
            file_path: p.file_path,
            user_id: p.user_id,
            action,
            bytes: p.bytes,
        })
    }
}

/// Windows registry event.
///
/// Note: RegistryKey is an extension beyond the synopsis's explicit node list.
/// See docs/architecture/graph_schema.md for the transparency note.
#[derive(Debug, Clone)]
pub struct RegistryEvent {
    pub process_id: String,
    pub host_id: String,
    pub key_path: String,
    pub value_name: String,
    pub action: RegistryAction,
}

/// Registry action enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryAction {
    Read,
    Write,
    Delete,
    Create,
}

impl RegistryEvent {
    fn to_proto(&self) -> proto::RegistryEvent {
        proto::RegistryEvent {
            process_id: self.process_id.clone(),
            host_id: self.host_id.clone(),
            key_path: self.key_path.clone(),
            value_name: self.value_name.clone(),
            action: match self.action {
                RegistryAction::Read => proto::registry_event::RegistryAction::Read as i32,
                RegistryAction::Write => proto::registry_event::RegistryAction::Write as i32,
                RegistryAction::Delete => proto::registry_event::RegistryAction::Delete as i32,
                RegistryAction::Create => proto::registry_event::RegistryAction::Create as i32,
            },
        }
    }

    fn from_proto(p: proto::RegistryEvent) -> Result<Self> {
        let action = match proto::registry_event::RegistryAction::try_from(p.action) {
            Ok(proto::registry_event::RegistryAction::Read) => RegistryAction::Read,
            Ok(proto::registry_event::RegistryAction::Write) => RegistryAction::Write,
            Ok(proto::registry_event::RegistryAction::Delete) => RegistryAction::Delete,
            Ok(proto::registry_event::RegistryAction::Create) => RegistryAction::Create,
            _ => {
                return Err(TelemetryError::Validation(
                    format!("unknown RegistryAction value: {}", p.action),
                ))
            }
        };
        Ok(Self {
            process_id: p.process_id,
            host_id: p.host_id,
            key_path: p.key_path,
            value_name: p.value_name,
            action,
        })
    }
}

/// Returns the current time as Unix epoch milliseconds.
///
/// Uses `SystemTime::now()` which is monotonic on all supported platforms.
/// Returns 0 on the (practically impossible) error of time being before UNIX_EPOCH.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_roundtrip_process() {
        let event = TelemetryEvent::new(
            "test-source",
            EventPayload::Process(ProcessEvent {
                process_id: "1234".into(),
                parent_pid: "1".into(),
                image_path: "/usr/bin/bash".into(),
                command_line: "bash -c 'whoami'".into(),
                user_id: "alice".into(),
                host_id: "host-001".into(),
                action: ProcessAction::Spawn,
            }),
        )
        .expect("event creation should succeed");

        let proto = event.to_proto();
        let roundtrip = TelemetryEvent::from_proto(proto).expect("roundtrip should succeed");

        assert_eq!(event.event_id, roundtrip.event_id);
        assert_eq!(event.source_id, roundtrip.source_id);
        if let (EventPayload::Process(a), EventPayload::Process(b)) =
            (&event.payload, &roundtrip.payload)
        {
            assert_eq!(a.process_id, b.process_id);
            assert_eq!(a.action, b.action);
        } else {
            panic!("payload mismatch after roundtrip");
        }
    }

    #[test]
    fn test_event_rejects_empty_source_id() {
        let result = TelemetryEvent::new(
            "",
            EventPayload::Process(ProcessEvent {
                process_id: "1".into(),
                parent_pid: "0".into(),
                image_path: "/bin/sh".into(),
                command_line: "sh".into(),
                user_id: "root".into(),
                host_id: "h1".into(),
                action: ProcessAction::Spawn,
            }),
        );
        assert!(result.is_err(), "empty source_id should be rejected");
    }

    #[test]
    fn test_event_roundtrip_identity() {
        let event = TelemetryEvent::new(
            "synthetic-gen-1",
            EventPayload::Identity(IdentityEvent {
                principal_id: "alice@corp.com".into(),
                credential_id: "token-abc".into(),
                host_id: "dc-01".into(),
                target_resource: "\\\\fileserver\\crown-jewel".into(),
                action: IdentityAction::PrivilegeEscalation,
                success: true,
            }),
        )
        .expect("event creation should succeed");

        let proto = event.to_proto();
        let roundtrip = TelemetryEvent::from_proto(proto).expect("roundtrip should succeed");

        if let (EventPayload::Identity(a), EventPayload::Identity(b)) =
            (&event.payload, &roundtrip.payload)
        {
            assert_eq!(a.action, b.action);
            assert_eq!(a.success, b.success);
        } else {
            panic!("payload mismatch after roundtrip");
        }
    }
}
