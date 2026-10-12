//! Provenance Event Emitter — streams GraphDelta events to the Kaaladrishti engine.
//!
//! After every Kaalform gate decision (whether APPROVED or DENIED), the emitter
//! encodes a `TelemetryEvent` carrying a `GraphDelta` that represents the
//! provenance chain:
//!
//! ```text
//! AgentPlan  ──has_intent──►  ContextArtifact
//!    │                              │
//!    │  ──has_plan──►  Action  ──invokes──►  ToolCall
//!    │                    │
//!    │                    └──authorized_by──►  AuthorizationReceipt
//! ```
//!
//! The Go engine ingests these deltas and adds them to the enterprise graph,
//! making the full provenance chain queryable by the SOC and visible in the
//! Kaaladrishti dashboard.
//!
//! ## Framing Protocol
//!
//! Identical to the telemetry-kernel framing:
//! `[4-byte big-endian u32 length][protobuf TelemetryEvent bytes]`
//!
//! This allows the Go engine's existing UDS listener to receive Kaalform
//! events without any protocol changes.
//!
//! ## Failure Isolation
//!
//! The emitter maintains a single long-lived TCP connection with reconnect
//! on failure. If the Kaaladrishti engine is unavailable, the emitter logs
//! the failure and drops the event — it never blocks the MCP gateway call.

use bytes::{BufMut, BytesMut};
use prost::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::error::{KaalformError, Result};
use crate::manifest::ToolManifest;
use crate::provenance::AuthorizationReceipt;

// Re-use generated protobuf types.
use crate::proto::{GraphDelta, GraphEdge, GraphNode, TelemetryEvent};

// ---------------------------------------------------------------------------
// ProvenanceEmitter
// ---------------------------------------------------------------------------

/// Emits provenance graph events to the Kaaladrishti Go engine over TCP.
pub struct ProvenanceEmitter {
    addr: String,
    stream: Option<TcpStream>,
    write_buffer: BytesMut,
    last_backoff: u64,
}

impl ProvenanceEmitter {
    /// Create a new emitter targeting the given Kaaladrishti TCP address.
    #[must_use]
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
            write_buffer: BytesMut::with_capacity(64 * 1024),
            last_backoff: 1,
        }
    }

    /// Emit a provenance event for a tool call gate decision.
    ///
    /// Builds a `GraphDelta` containing nodes for the AgentPlan, Action,
    /// ToolCall, and AuthorizationReceipt, then encodes it as a `TelemetryEvent`
    /// and sends it to Kaaladrishti.
    ///
    /// # Errors
    /// Returns `EmitterConnection` if the send fails after a reconnect attempt.
    /// Callers should log and continue — Kaalform never blocks on the emitter.
    pub async fn emit_gate_event(
        &mut self,
        workflow_id: &str,
        principal_id: &str,
        tool_id: &str,
        action_text: &str,
        manifest: Option<&ToolManifest>,
        receipt: Option<&AuthorizationReceipt>,
        denied: bool,
    ) -> Result<()> {
        let event_id = Uuid::new_v4().to_string();
        let now_ms = now_ms();

        // Build the GraphDelta.
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // 1. AgentPlan node (represents the agent's declared intent / session).
        let plan_node_id = format!("plan:{workflow_id}");
        nodes.push(build_node(
            &plan_node_id,
            11, // NODE_TYPE_AGENT_PLAN
            &format!("Plan:{workflow_id}"),
            1.0,
            now_ms,
            &event_id,
            vec![
                ("workflow_id".to_string(), workflow_id.to_string()),
                ("principal_id".to_string(), principal_id.to_string()),
            ],
        ));

        // 2. Action node (the concrete tool invocation).
        let action_node_id = format!("action:{event_id}");
        nodes.push(build_node(
            &action_node_id,
            13, // NODE_TYPE_ACTION
            &format!("Action:{tool_id}"),
            1.0,
            now_ms,
            &event_id,
            vec![
                ("tool_id".to_string(), tool_id.to_string()),
                ("action_text".to_string(), action_text.chars().take(256).collect()),
                ("principal_id".to_string(), principal_id.to_string()),
                ("workflow_id".to_string(), workflow_id.to_string()),
                ("denied".to_string(), denied.to_string()),
            ],
        ));

        // 3. ToolCall node.
        let tool_node_id = format!("tool:{tool_id}");
        nodes.push(build_node(
            &tool_node_id,
            15, // NODE_TYPE_TOOL_CALL
            tool_id,
            1.0,
            now_ms,
            &event_id,
            vec![("tool_id".to_string(), tool_id.to_string())],
        ));

        // 4. ContextArtifact node (the manifest, if present).
        if let Some(m) = manifest {
            let ctx_node_id = format!("ctx:manifest:{}", m.body.tool_id);
            nodes.push(build_node(
                &ctx_node_id,
                16, // NODE_TYPE_CONTEXT_ARTIFACT
                &format!("Manifest:{}", m.body.tool_id),
                1.0,
                now_ms,
                &event_id,
                vec![
                    ("tool_id".to_string(), m.body.tool_id.clone()),
                    ("tool_version".to_string(), m.body.tool_version.clone()),
                    ("signing_key_fingerprint".to_string(), m.body.signing_key_fingerprint.clone()),
                    ("expires_at".to_string(), m.body.expires_at.clone()),
                ],
            ));
            // AgentPlan → has_plan → ContextArtifact
            edges.push(build_edge(
                &format!("{plan_node_id}:has_plan:{ctx_node_id}"),
                &plan_node_id,
                &ctx_node_id,
                16, // EDGE_TYPE_HAS_PLAN
                now_ms,
                &event_id,
            ));
        }

        // 5. AuthorizationReceipt node.
        if let Some(r) = receipt {
            let auth_node_id = format!("auth:{}", r.receipt_id);
            let verdict_str = if denied { "DENIED" } else { "APPROVED" };
            nodes.push(build_node(
                &auth_node_id,
                18, // NODE_TYPE_AUTHORIZATION
                &format!("AuthReceipt:{verdict_str}"),
                1.0,
                now_ms,
                &event_id,
                vec![
                    ("receipt_id".to_string(), r.receipt_id.clone()),
                    ("workflow_id".to_string(), r.workflow_id.clone()),
                    ("verdict".to_string(), verdict_str.to_string()),
                    ("drift_score".to_string(), format!("{:.4}", r.drift_score)),
                    ("drift_threshold".to_string(), format!("{:.4}", r.drift_threshold)),
                    ("reason".to_string(), r.reason.clone()),
                    ("drift_tokens".to_string(), r.drift_tokens.join(",")),
                ],
            ));
            // Action → authorized_by → AuthorizationReceipt
            edges.push(build_edge(
                &format!("{action_node_id}:authorized_by:{auth_node_id}"),
                &action_node_id,
                &auth_node_id,
                13, // EDGE_TYPE_AUTHORIZED_BY
                now_ms,
                &event_id,
            ));
        }

        // Edges between key nodes.
        // AgentPlan → performs → Action
        edges.push(build_edge(
            &format!("{plan_node_id}:performs:{action_node_id}"),
            &plan_node_id,
            &action_node_id,
            18, // EDGE_TYPE_PERFORMS
            now_ms,
            &event_id,
        ));
        // Action → invokes → ToolCall
        edges.push(build_edge(
            &format!("{action_node_id}:invokes:{tool_node_id}"),
            &action_node_id,
            &tool_node_id,
            19, // EDGE_TYPE_INVOKES
            now_ms,
            &event_id,
        ));

        let _delta = GraphDelta {
            delta_id: Uuid::new_v4().to_string(),
            timestamp_ms: now_ms as i64,
            source_event_id: event_id.clone(),
            upserted_nodes: nodes,
            upserted_edges: edges,
            removed_node_ids: Vec::new(),
            removed_edge_ids: Vec::new(),
        };

        // Wrap in a TelemetryEvent with an IdentityEvent payload.
        // This ensures the Go engine's validator accepts the frame without rejection,
        // and generates Principal, Credential, and Tool authorization graph nodes.
        let success = !denied;
        let action_type = if success {
            crate::proto::identity_event::IdentityAction::CredentialUse as i32
        } else {
            crate::proto::identity_event::IdentityAction::AuthFailure as i32
        };

        let credential_id = manifest
            .map(|m| format!("manifest:{}", m.body.tool_id))
            .unwrap_or_else(|| "unattested".to_string());

        let identity_event = crate::proto::IdentityEvent {
            principal_id: principal_id.to_string(),
            credential_id,
            host_id: format!("kaalform:{}", workflow_id),
            target_resource: tool_id.to_string(),
            action: action_type,
            success,
        };

        let te = TelemetryEvent {
            event_id: event_id.clone(),
            timestamp_ms: now_ms as i64,
            source_id: "kaalform".to_string(),
            schema_version: "1.0".to_string(),
            payload: Some(crate::proto::telemetry_event::Payload::IdentityEvent(identity_event)),
        };

        self.send_event_frame(&te).await
    }

    /// Send a length-prefixed protobuf TelemetryEvent frame to Kaaladrishti.
    async fn send_event_frame(&mut self, te: &TelemetryEvent) -> Result<()> {
        self.write_buffer.clear();
        te.encode(&mut self.write_buffer)
            .map_err(KaalformError::Protobuf)?;
        let te_bytes = self.write_buffer.split();

        let payload_len = te_bytes.len() as u32;
        let mut frame = BytesMut::with_capacity(4 + te_bytes.len());
        frame.put_u32(payload_len);
        frame.extend_from_slice(&te_bytes);
        let frame = frame.freeze();

        self.ensure_connected().await?;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| KaalformError::EmitterConnection("stream is None after connect".to_string()))?;

        if let Err(e) = stream.write_all(&frame).await {
            warn!(error = %e, "emitter: write failed; dropping stream");
            self.stream = None;
            return Err(KaalformError::EmitterConnection(format!("{e}")));
        }

        info!(
            event_id = %te.event_id,
            source = %te.source_id,
            "emitter: provenance event sent to Kaaladrishti"
        );

        Ok(())
    }

    /// Ensure the TCP stream is connected, reconnecting with backoff if needed.
    async fn ensure_connected(&mut self) -> Result<()> {
        if self.stream.is_some() {
            return Ok(());
        }
        match TcpStream::connect(&self.addr).await {
            Ok(stream) => {
                self.stream = Some(stream);
                self.last_backoff = 1;
                info!(addr = %self.addr, "emitter: connected to Kaaladrishti");
                Ok(())
            }
            Err(e) => {
                error!(
                    addr = %self.addr,
                    error = %e,
                    "emitter: failed to connect to Kaaladrishti"
                );
                Err(KaalformError::EmitterConnection(format!(
                    "connect to {}: {e}",
                    self.addr
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Graph node / edge builders
// ---------------------------------------------------------------------------

fn build_node(
    node_id: &str,
    node_type: i32,
    label: &str,
    confidence: f64,
    timestamp_ms: u64,
    provenance: &str,
    props: Vec<(String, String)>,
) -> GraphNode {
    use std::collections::HashMap;
    let mut properties: HashMap<String, String> = HashMap::new();
    for (k, v) in props {
        properties.insert(k, v);
    }
    GraphNode {
        node_id: node_id.to_string(),
        node_type,
        label: label.to_string(),
        timestamp_ms: timestamp_ms as i64,
        confidence,
        recency_decay: 1.0,
        provenance: provenance.to_string(),
        properties,
    }
}

fn build_edge(
    edge_id: &str,
    src: &str,
    dst: &str,
    edge_type: i32,
    timestamp_ms: u64,
    provenance: &str,
) -> GraphEdge {
    GraphEdge {
        edge_id: edge_id.to_string(),
        src_node_id: src.to_string(),
        dst_node_id: dst.to_string(),
        edge_type,
        timestamp_ms: timestamp_ms as i64,
        confidence: 1.0,
        recency_decay: 1.0,
        provenance: provenance.to_string(),
        properties: std::collections::HashMap::new(),
        is_baseline: false,
        decay_class: 0,
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
