//! SyntheticTelemetrySource — configurable synthetic enterprise telemetry generator.
//!
//! Generates a realistic mix of process, network, identity, file, and registry
//! events representing normal enterprise activity, plus periodic anomaly injections
//! (lateral movement, privilege escalation, unusual data access) for testing the
//! ML and governance pipelines.
//!
//! # Design
//!
//! The synthetic source maintains a small pool of simulated principals, hosts,
//! and processes. Each tick, it randomly selects an event type and generates a
//! plausible event, occasionally injecting anomalous sequences.
//!
//! This is NOT a realistic enterprise simulation — it is a functional prototype
//! sufficient to exercise every code path in the pipeline.
//!
//! # PROTOTYPE NOTE
//!
//! The entity pools and anomaly rates are hardcoded constants suitable for
//! development and testing. A production telemetry source would read from real
//! OS sensors (via the eBPF stub extension point).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::prelude::*;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info};

use crate::error::{Result, TelemetryError};
use crate::model::{
    EventPayload, FileAction, FileEvent, IdentityAction, IdentityEvent, NetworkDirection,
    NetworkEvent, ProcessAction, ProcessEvent, RegistryAction, RegistryEvent, TelemetryEvent,
};
use crate::source::TelemetrySource;

// ---------------------------------------------------------------------------
// Synthetic entity pools (prototype constants)
// ---------------------------------------------------------------------------

const PRINCIPALS: &[&str] = &[
    "alice@corp.internal",
    "bob@corp.internal",
    "svc-deploy@corp.internal",
    "svc-backup@corp.internal",
    "charlie@corp.internal",
];

const CREDENTIALS: &[&str] = &[
    "token-alice-001",
    "token-bob-002",
    "cert-svc-deploy",
    "cert-svc-backup",
    "token-charlie-003",
];

const HOSTS: &[&str] = &[
    "workstation-alice-01",
    "workstation-bob-02",
    "server-dc-01",
    "server-fileserver-01",
    "server-backup-01",
];

const PROCESSES: &[&str] = &[
    "explorer.exe",
    "powershell.exe",
    "cmd.exe",
    "svchost.exe",
    "lsass.exe",
    "python.exe",
    "bash",
    "ssh",
];

const DST_IPS: &[&str] = &[
    "10.0.0.10",
    "10.0.0.20",
    "192.168.1.100",
    "8.8.8.8",          // External DNS — potentially suspicious
    "185.220.101.1",    // Tor exit node range — suspicious
];

const CROWN_JEWEL_PATHS: &[&str] = &[
    r"\\fileserver\crown-jewel\hr-data.xlsx",
    r"\\fileserver\crown-jewel\financial-q4.pdf",
    r"C:\secrets\db_credentials.txt",
];

const REGISTRY_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the synthetic telemetry source.
#[derive(Debug, Clone)]
pub struct SyntheticConfig {
    /// How many milliseconds to wait between events.
    /// Default: 200ms (5 events/sec).
    pub event_interval_ms: u64,

    /// Probability [0.0, 1.0] of generating an anomalous event on any given tick.
    /// Default: 0.05 (5% anomaly rate).
    pub anomaly_probability: f64,

    /// Source identifier embedded in every event.
    pub source_id: String,

    /// Maximum number of events to generate before shutting down.
    /// `None` means run indefinitely.
    pub max_events: Option<u64>,
}

impl Default for SyntheticConfig {
    fn default() -> Self {
        Self {
            event_interval_ms: 200,
            anomaly_probability: 0.05,
            source_id: "synthetic-telemetry-gen-1".to_string(),
            max_events: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SyntheticTelemetrySource
// ---------------------------------------------------------------------------

/// Generates synthetic enterprise telemetry events for development and testing.
///
/// This is the only concrete `TelemetrySource` implementation in Phases 1-11.
/// See `source::ebpf_stub` for the future eBPF extension point.
pub struct SyntheticTelemetrySource {
    config: SyntheticConfig,
    rng: StdRng,
    events_generated: u64,
    running: bool,
}

impl SyntheticTelemetrySource {
    /// Create a new synthetic source with the given configuration.
    #[must_use]
    pub fn new(config: SyntheticConfig) -> Self {
        Self {
            rng: StdRng::from_entropy(),
            config,
            events_generated: 0,
            running: false,
        }
    }

    /// Create a source with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SyntheticConfig::default())
    }

    /// Generate one synthetic telemetry event. May be normal or anomalous.
    fn generate_event(&mut self) -> Result<TelemetryEvent> {
        let source_id = self.config.source_id.clone();
        let anomalous = self.rng.gen_bool(self.config.anomaly_probability);

        let payload = if anomalous {
            self.generate_anomalous_payload()
        } else {
            self.generate_normal_payload()
        };

        let event = TelemetryEvent::new(source_id, payload)?;
        debug!(
            event_id = %event.event_id,
            anomalous = anomalous,
            "generated synthetic event"
        );
        Ok(event)
    }

    /// Generate a normal (baseline) event payload.
    fn generate_normal_payload(&mut self) -> EventPayload {
        // Weighted selection: process events are most common in real telemetry.
        let choice = self.rng.gen_range(0..10u8);
        match choice {
            0..=3 => self.generate_process_event(false),
            4..=6 => self.generate_network_event(false),
            7 => self.generate_identity_event(false),
            8 => self.generate_file_event(false),
            _ => self.generate_registry_event(false),
        }
    }

    /// Generate an anomalous event payload (lateral movement, priv-esc, etc.).
    fn generate_anomalous_payload(&mut self) -> EventPayload {
        let choice = self.rng.gen_range(0..4u8);
        match choice {
            0 => self.generate_identity_event(true),  // Privilege escalation
            1 => self.generate_network_event(true),   // External / suspicious dst
            2 => self.generate_file_event(true),       // Crown jewel access
            _ => self.generate_process_event(true),    // Suspicious process
        }
    }

    fn pick<'a>(&mut self, items: &'a [&'static str]) -> &'a str {
        items.choose(&mut self.rng).copied().unwrap_or("unknown")
    }

    fn generate_process_event(&mut self, anomalous: bool) -> EventPayload {
        let image = if anomalous {
            // Suspicious: spawning powershell from a service process
            "powershell.exe"
        } else {
            self.pick(PROCESSES)
        };
        let action = if anomalous {
            ProcessAction::Spawn
        } else {
            *[ProcessAction::Spawn, ProcessAction::Terminate, ProcessAction::LoadModule]
                .choose(&mut self.rng)
                .unwrap()
        };
        EventPayload::Process(ProcessEvent {
            process_id: self.rng.gen_range(1000u32..9999).to_string(),
            parent_pid: self.rng.gen_range(1u32..999).to_string(),
            image_path: format!("C:\\Windows\\System32\\{image}"),
            command_line: format!("{image} -EncodedCommand BASE64STUFF"),
            user_id: self.pick(PRINCIPALS).to_string(),
            host_id: self.pick(HOSTS).to_string(),
            action,
        })
    }

    fn generate_network_event(&mut self, anomalous: bool) -> EventPayload {
        let dst_ip = if anomalous {
            // External/suspicious destinations
            self.pick(&DST_IPS[3..])
        } else {
            self.pick(&DST_IPS[..3])
        };
        EventPayload::Network(NetworkEvent {
            process_id: self.rng.gen_range(1000u32..9999).to_string(),
            host_id: self.pick(HOSTS).to_string(),
            src_ip: "10.0.0.50".to_string(),
            src_port: self.rng.gen_range(1024..65535),
            dst_ip: dst_ip.to_string(),
            dst_port: if anomalous { 4444 } else { 443 }, // 4444 = common C2 port
            protocol: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            bytes_sent: self.rng.gen_range(100..1_000_000),
            bytes_recv: self.rng.gen_range(100..10_000),
        })
    }

    fn generate_identity_event(&mut self, anomalous: bool) -> EventPayload {
        let action = if anomalous {
            // Anomalous: privilege escalation or role assumption
            *[IdentityAction::PrivilegeEscalation, IdentityAction::RoleAssumption]
                .choose(&mut self.rng)
                .unwrap()
        } else {
            *[IdentityAction::Login, IdentityAction::CredentialUse, IdentityAction::Logout]
                .choose(&mut self.rng)
                .unwrap()
        };
        let principal_idx = self.rng.gen_range(0..PRINCIPALS.len());
        EventPayload::Identity(IdentityEvent {
            principal_id: PRINCIPALS[principal_idx].to_string(),
            credential_id: CREDENTIALS[principal_idx].to_string(),
            host_id: self.pick(HOSTS).to_string(),
            target_resource: if anomalous {
                r"\\fileserver\admin$".to_string()
            } else {
                r"\\fileserver\shared".to_string()
            },
            action,
            success: !anomalous || self.rng.gen_bool(0.7),
        })
    }

    fn generate_file_event(&mut self, anomalous: bool) -> EventPayload {
        let file_path = if anomalous {
            self.pick(CROWN_JEWEL_PATHS).to_string()
        } else {
            format!(
                r"\\fileserver\shared\document-{}.docx",
                self.rng.gen_range(1..999u32)
            )
        };
        EventPayload::File(FileEvent {
            process_id: self.rng.gen_range(1000u32..9999).to_string(),
            host_id: self.pick(HOSTS).to_string(),
            file_path,
            user_id: self.pick(PRINCIPALS).to_string(),
            action: if anomalous {
                FileAction::Read
            } else {
                *[FileAction::Read, FileAction::Write].choose(&mut self.rng).unwrap()
            },
            bytes: self.rng.gen_range(1024..10_000_000),
        })
    }

    fn generate_registry_event(&mut self, _anomalous: bool) -> EventPayload {
        EventPayload::Registry(RegistryEvent {
            process_id: self.rng.gen_range(1000u32..9999).to_string(),
            host_id: self.pick(HOSTS).to_string(),
            key_path: self.pick(REGISTRY_KEYS).to_string(),
            value_name: "DefaultUserName".to_string(),
            action: *[RegistryAction::Read, RegistryAction::Write]
                .choose(&mut self.rng)
                .unwrap(),
        })
    }
}

#[async_trait]
impl TelemetrySource for SyntheticTelemetrySource {
    async fn start(&mut self) -> Result<()> {
        info!(source_id = %self.config.source_id, "synthetic telemetry source starting");
        self.running = true;
        Ok(())
    }

    async fn next_event(&mut self) -> Result<TelemetryEvent> {
        if !self.running {
            return Err(TelemetryError::SourceShutdown);
        }
        if let Some(max) = self.config.max_events {
            if self.events_generated >= max {
                self.running = false;
                return Err(TelemetryError::SourceShutdown);
            }
        }

        // Simulate event rate by sleeping between events.
        sleep(Duration::from_millis(self.config.event_interval_ms)).await;

        let event = self.generate_event()?;
        self.events_generated += 1;
        Ok(event)
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!(source_id = %self.config.source_id, events_generated = self.events_generated, "synthetic telemetry source shutting down");
        self.running = false;
        Ok(())
    }

    fn source_id(&self) -> &str {
        &self.config.source_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_synthetic_source_produces_events() {
        let mut source = SyntheticTelemetrySource::new(SyntheticConfig {
            event_interval_ms: 0, // No delay in tests
            anomaly_probability: 0.5,
            source_id: "test-source".to_string(),
            max_events: Some(10),
        });

        source.start().await.expect("start should succeed");

        let mut count = 0;
        loop {
            match source.next_event().await {
                Ok(event) => {
                    assert!(!event.event_id.is_empty(), "event_id must not be empty");
                    assert_eq!(event.source_id, "test-source");
                    count += 1;
                }
                Err(TelemetryError::SourceShutdown) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert_eq!(count, 10, "should produce exactly max_events events");
    }

    #[tokio::test]
    async fn test_events_have_valid_schema_version() {
        let mut source = SyntheticTelemetrySource::new(SyntheticConfig {
            event_interval_ms: 0,
            anomaly_probability: 0.0,
            source_id: "test-v".to_string(),
            max_events: Some(3),
        });
        source.start().await.unwrap();

        while let Ok(event) = source.next_event().await {
            let proto = event.to_proto();
            assert_eq!(proto.schema_version, crate::model::SCHEMA_VERSION);
        }
    }

    #[tokio::test]
    async fn test_shutdown_prevents_further_events() {
        let mut source = SyntheticTelemetrySource::new(SyntheticConfig {
            event_interval_ms: 0,
            anomaly_probability: 0.0,
            source_id: "test-shutdown".to_string(),
            max_events: None,
        });
        source.start().await.unwrap();
        // Get one event
        let _e = source.next_event().await.unwrap();
        // Shut down
        source.shutdown().await.unwrap();
        // Next call must return SourceShutdown
        match source.next_event().await {
            Err(TelemetryError::SourceShutdown) => {}
            other => panic!("expected SourceShutdown, got: {other:?}"),
        }
    }
}
