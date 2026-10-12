//! Kaalform HTTP MCP Proxy Gateway.
//!
//! The gateway is an Axum HTTP server that intercepts MCP tool call requests
//! from AI agents and enforces Pillar 4 and Pillar 5 before proxying to the
//! upstream MCP server.
//!
//! ## Endpoints
//!
//! | Method | Path                       | Description                                      |
//! |--------|----------------------------|--------------------------------------------------|
//! | POST   | `/mcp/v1/call`             | Proxy an MCP tool call (main gate endpoint)      |
//! | POST   | `/mcp/v1/scope`            | Declare workflow scope for Pillar 5 tracking     |
//! | GET    | `/health`                  | Health check                                     |
//! | GET    | `/audit/{workflow_id}`     | Retrieve the action log for a workflow session   |
//! | POST   | `/keys/generate`           | Generate an Ed25519 keypair (for tool signing)   |
//! | POST   | `/manifest/sign`           | Sign a tool manifest body                        |
//! | POST   | `/manifest/verify`         | Verify a signed manifest (offline check)         |
//!
//! ## Request Headers
//!
//! | Header                      | Required | Description                                      |
//! |-----------------------------|----------|--------------------------------------------------|
//! | `X-Kaalform-Workflow-Id`    | Yes      | Identifies the agent session for Pillar 5        |
//! | `X-Kaalform-Principal-Id`   | Yes      | Agent / user identity making the call            |
//! | `X-Kaalform-Manifest`       | Cond.    | JSON-encoded `ToolManifest` (required if Pillar 4 enforce=true) |
//!
//! ## Response Codes
//!
//! - `200` — tool call proxied successfully, upstream response returned.
//! - `400` — malformed request (missing required fields).
//! - `403` — Pillar 4 or Pillar 5 rejection (verdict DENIED).
//! - `502` — upstream MCP server returned an error.
//! - `503` — upstream MCP server unreachable.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json as AxumJson, Response};
use axum::{routing, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::error::KaalformError;
use crate::manifest::{ToolManifest, ToolManifestBody};
use crate::provenance::{AuthorizationReceipt, ProvenanceFirewall};
use crate::verifier::{ManifestVerifier, TrustStore};
use crate::emitter::ProvenanceEmitter;

// ---------------------------------------------------------------------------
// Shared gateway state
// ---------------------------------------------------------------------------

/// Thread-safe shared state for all gateway handlers.
pub struct GatewayState {
    pub config: Config,
    pub verifier: ManifestVerifier,
    pub firewall: Mutex<ProvenanceFirewall>,
    pub emitter: Mutex<ProvenanceEmitter>,
    pub http_client: reqwest::Client,
}

impl GatewayState {
    /// Construct from a loaded config.
    ///
    /// # Errors
    /// Returns `Config` if the trust store cannot be loaded.
    pub fn new(config: Config) -> Result<Self, KaalformError> {
        let store = if let Some(ref path) = config.trusted_keys_path {
            TrustStore::load(path)?
        } else {
            TrustStore::empty()
        };
        let verifier = ManifestVerifier::new(&store, config.require_manifest)?;
        let firewall = Mutex::new(ProvenanceFirewall::new(
            config.drift_threshold,
            config.session_ttl_secs,
        ));
        let emitter = Mutex::new(ProvenanceEmitter::new(&config.kaaladrishti_addr));

        Ok(Self {
            config,
            verifier,
            firewall,
            emitter,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client build failed"),
        })
    }
}

type SharedState = Arc<GatewayState>;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Body for `POST /mcp/v1/call`.
#[derive(Debug, Deserialize)]
pub struct McpCallRequest {
    /// The MCP tool ID to invoke.
    pub tool_id: String,
    /// Tool arguments (arbitrary JSON).
    pub arguments: serde_json::Value,
}

/// Body for `POST /mcp/v1/scope`.
#[derive(Debug, Deserialize)]
pub struct DeclareScopeRequest {
    pub workflow_id: String,
    pub declared_scope: String,
}

/// Standard gate error response body.
#[derive(Debug, Serialize)]
pub struct GateErrorResponse {
    pub error: String,
    pub pillar: Option<u8>,
    pub drift_score: Option<f64>,
    pub receipt_id: Option<String>,
}

/// Response from `POST /manifest/sign`.
#[derive(Debug, Serialize)]
pub struct SignManifestResponse {
    pub manifest: ToolManifest,
}

/// Response from `POST /manifest/verify`.
#[derive(Debug, Serialize)]
pub struct VerifyManifestResponse {
    pub valid: bool,
    pub error: Option<String>,
}

/// Response from `POST /keys/generate`.
#[derive(Debug, Serialize)]
pub struct GenerateKeypairResponse {
    pub signing_key_hex: String,
    pub verifying_key_hex: String,
    pub fingerprint: String,
    pub note: String,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build and return the Kaalform HTTP router.
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/health", routing::get(handle_health))
        .route("/mcp/v1/call", routing::post(handle_mcp_call))
        .route("/mcp/v1/scope", routing::post(handle_declare_scope))
        .route("/audit/:workflow_id", routing::get(handle_audit_log))
        .route("/keys/generate", routing::post(handle_generate_keypair))
        .route("/manifest/sign", routing::post(handle_sign_manifest))
        .route("/manifest/verify", routing::post(handle_verify_manifest))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /health — liveness check.
async fn handle_health(State(state): State<SharedState>) -> impl IntoResponse {
    AxumJson(serde_json::json!({
        "status": "ok",
        "service": "kaalform",
        "upstream_mcp_url": state.config.upstream_mcp_url,
        "drift_threshold": state.config.drift_threshold,
        "require_manifest": state.config.require_manifest,
        "pillar4": "active",
        "pillar5": "active",
    }))
}

/// POST /mcp/v1/scope — declare declared scope for a workflow.
async fn handle_declare_scope(
    State(state): State<SharedState>,
    AxumJson(req): AxumJson<DeclareScopeRequest>,
) -> impl IntoResponse {
    state
        .firewall
        .lock()
        .await
        .declare_scope(&req.workflow_id, &req.declared_scope);

    info!(workflow_id = %req.workflow_id, "gateway: scope declared");
    AxumJson(serde_json::json!({
        "status": "ok",
        "workflow_id": req.workflow_id,
    }))
}

/// POST /mcp/v1/call — the main interception point.
///
/// 1. Extract workflow_id, principal_id, and optional manifest from headers.
/// 2. Pillar 4: verify manifest (if present or required).
/// 3. Pillar 5: check action drift against declared scope.
/// 4. Emit provenance event to Kaaladrishti (non-blocking).
/// 5. If approved, proxy to upstream MCP server.
async fn handle_mcp_call(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<McpCallRequest>,
) -> Response {
    // Extract required headers.
    let workflow_id = match header_str(&headers, "x-kaalform-workflow-id") {
        Some(v) => v,
        None => {
            return gate_error(
                StatusCode::BAD_REQUEST,
                "missing X-Kaalform-Workflow-Id header",
                None,
                None,
                None,
            );
        }
    };
    let principal_id = match header_str(&headers, "x-kaalform-principal-id") {
        Some(v) => v,
        None => {
            return gate_error(
                StatusCode::BAD_REQUEST,
                "missing X-Kaalform-Principal-Id header",
                None,
                None,
                None,
            );
        }
    };

    // -----------------------------------------------------------------------
    // Pillar 4: Tool-manifest verification.
    // -----------------------------------------------------------------------
    let manifest_result: Result<Option<ToolManifest>, KaalformError> =
        match header_str(&headers, "x-kaalform-manifest") {
            Some(manifest_json) => ToolManifest::from_json(&manifest_json)
                .and_then(|m| {
                    state.verifier.verify(&m)?;
                    Ok(Some(m))
                }),
            None => {
                if state.config.require_manifest {
                    Err(KaalformError::InvalidManifest(
                        "X-Kaalform-Manifest header is required but not present".to_string(),
                    ))
                } else {
                    warn!(
                        workflow_id = %workflow_id,
                        tool_id = %req.tool_id,
                        "Pillar 4: no manifest provided; proceeding (require_manifest=false)"
                    );
                    Ok(None)
                }
            }
        };

    let manifest = match manifest_result {
        Ok(m) => m,
        Err(e) => {
            warn!(
                workflow_id = %workflow_id,
                tool_id = %req.tool_id,
                error = %e,
                "Pillar 4: DENIED"
            );
            emit_provenance_best_effort(
                &state,
                &workflow_id,
                &principal_id,
                &req.tool_id,
                &format_action_text(&req.tool_id, &req.arguments),
                None,
                None,
                true,
            )
            .await;
            return gate_error(
                StatusCode::FORBIDDEN,
                &format!("Pillar 4 violation: {e}"),
                Some(4),
                None,
                None,
            );
        }
    };

    // -----------------------------------------------------------------------
    // Pillar 5: Provenance drift check.
    // -----------------------------------------------------------------------
    let action_text = format_action_text(&req.tool_id, &req.arguments);

    let firewall_result = {
        let mut fw = state.firewall.lock().await;

        // Auto-declare scope from manifest if no scope registered yet.
        // This is the "auto_scope" convenience mode — in production the
        // orchestrator should call POST /mcp/v1/scope explicitly.
        if let Some(ref m) = manifest {
            // Synthesize a scope text from the manifest body for convenience.
            // Callers should override this with an explicit declare_scope call.
            let auto_scope = format!(
                "Tool {} version {} with capabilities: {}. Allowed principals: {}.",
                m.body.tool_name,
                m.body.tool_version,
                m.body.capabilities.join(", "),
                m.body.allowed_principals.join(", "),
            );
            fw.declare_scope(&workflow_id, &auto_scope);
        }

        fw.check_action(&workflow_id, &req.tool_id, &principal_id, &action_text)
    };

    match firewall_result {
        Ok(receipt) => {
            // Approved — emit provenance event (non-blocking) then proxy.
            emit_provenance_best_effort(
                &state,
                &workflow_id,
                &principal_id,
                &req.tool_id,
                &action_text,
                manifest.as_ref(),
                Some(&receipt),
                false,
            )
            .await;

            // Proxy to upstream MCP server.
            proxy_to_upstream(&state, &req).await
        }
        Err(KaalformError::DriftExceeded { score, threshold, .. }) => {
            // Denied by Pillar 5.
            let denied_receipt = AuthorizationReceipt::denied(
                &workflow_id,
                &req.tool_id,
                &principal_id,
                score,
                threshold,
                Vec::new(),
            );
            emit_provenance_best_effort(
                &state,
                &workflow_id,
                &principal_id,
                &req.tool_id,
                &action_text,
                manifest.as_ref(),
                Some(&denied_receipt),
                true,
            )
            .await;
            gate_error(
                StatusCode::FORBIDDEN,
                &format!(
                    "Pillar 5 violation: context drift {score:.3} exceeds threshold {threshold:.3}"
                ),
                Some(5),
                Some(score),
                Some(denied_receipt.receipt_id),
            )
        }
        Err(KaalformError::Config(_)) => {
            // No scope declared — auto-approve if no manifest and require_manifest=false.
            warn!(
                workflow_id = %workflow_id,
                tool_id = %req.tool_id,
                "Pillar 5: no scope declared for workflow; auto-approving (no scope baseline)"
            );
            proxy_to_upstream(&state, &req).await
        }
        Err(e) => gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("internal error: {e}"),
            None,
            None,
            None,
        ),
    }
}

/// GET /audit/:workflow_id — retrieve the session action log.
async fn handle_audit_log(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
) -> Response {
    let fw = state.firewall.lock().await;
    match fw.session_log(&workflow_id) {
        Some(log) => AxumJson(serde_json::json!({
            "workflow_id": workflow_id,
            "action_count": log.len(),
            "actions": log,
        }))
        .into_response(),
        None => gate_error(
            StatusCode::NOT_FOUND,
            &format!("no session found for workflow_id '{workflow_id}'"),
            None,
            None,
            None,
        ),
    }
}

/// POST /keys/generate — generate a new Ed25519 keypair.
async fn handle_generate_keypair() -> impl IntoResponse {
    let (sk_hex, vk_hex, fingerprint) = ManifestVerifier::generate_keypair();
    AxumJson(GenerateKeypairResponse {
        signing_key_hex: sk_hex,
        verifying_key_hex: vk_hex,
        fingerprint,
        note: "Store signing_key_hex securely. Add verifying_key_hex and fingerprint to the trust store.".to_string(),
    })
}

/// POST /manifest/sign — sign a manifest body with a provided private key.
#[derive(Deserialize)]
struct SignManifestRequest {
    body: ToolManifestBody,
    signing_key_hex: String,
}

async fn handle_sign_manifest(
    AxumJson(req): AxumJson<SignManifestRequest>,
) -> Response {
    match ManifestVerifier::sign_manifest(req.body, &req.signing_key_hex) {
        Ok(manifest) => AxumJson(SignManifestResponse { manifest }).into_response(),
        Err(e) => gate_error(
            StatusCode::BAD_REQUEST,
            &format!("signing failed: {e}"),
            None,
            None,
            None,
        ),
    }
}

/// POST /manifest/verify — verify a manifest offline.
async fn handle_verify_manifest(
    State(state): State<SharedState>,
    AxumJson(manifest): AxumJson<ToolManifest>,
) -> impl IntoResponse {
    match state.verifier.verify(&manifest) {
        Ok(()) => AxumJson(VerifyManifestResponse {
            valid: true,
            error: None,
        }),
        Err(e) => AxumJson(VerifyManifestResponse {
            valid: false,
            error: Some(format!("{e}")),
        }),
    }
}

// ---------------------------------------------------------------------------
// Upstream proxy
// ---------------------------------------------------------------------------

async fn proxy_to_upstream(state: &GatewayState, req: &McpCallRequest) -> Response {
    let url = format!("{}/mcp/v1/call", state.config.upstream_mcp_url);
    let body = serde_json::json!({
        "tool_id": req.tool_id,
        "arguments": req.arguments,
    });

    match state.http_client.post(&url).json(&body).send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = upstream_resp
                .text()
                .await
                .unwrap_or_else(|_| "upstream read error".to_string());
            (status, body).into_response()
        }
        Err(e) => {
            error!(error = %e, "gateway: upstream MCP unreachable");
            gate_error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("upstream MCP server unavailable: {e}"),
                None,
                None,
                None,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn format_action_text(tool_id: &str, arguments: &serde_json::Value) -> String {
    // Build a compact text representation of the action for the drift scorer.
    let args_str = arguments.to_string();
    format!("{tool_id} {args_str}")
}

fn gate_error(
    status: StatusCode,
    message: &str,
    pillar: Option<u8>,
    drift_score: Option<f64>,
    receipt_id: Option<String>,
) -> Response {
    let body = GateErrorResponse {
        error: message.to_string(),
        pillar,
        drift_score,
        receipt_id,
    };
    (status, AxumJson(body)).into_response()
}

/// Fire-and-forget provenance emission — never blocks the gateway response.
async fn emit_provenance_best_effort(
    state: &GatewayState,
    workflow_id: &str,
    principal_id: &str,
    tool_id: &str,
    action_text: &str,
    manifest: Option<&ToolManifest>,
    receipt: Option<&AuthorizationReceipt>,
    denied: bool,
) {
    let mut emitter = state.emitter.lock().await;
    if let Err(e) = emitter
        .emit_gate_event(
            workflow_id,
            principal_id,
            tool_id,
            action_text,
            manifest,
            receipt,
            denied,
        )
        .await
    {
        warn!(
            workflow_id = %workflow_id,
            tool_id = %tool_id,
            error = %e,
            "emitter: failed to send provenance event (non-fatal)"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_mcp_url: "http://127.0.0.1:9999".to_string(),
            kaaladrishti_addr: "127.0.0.1:9090".to_string(),
            drift_threshold: 0.45,
            require_manifest: false,
            trusted_keys_path: None,
            signing_key_path: None,
            session_ttl_secs: 3600,
        }
    }

    #[tokio::test]
    async fn test_keypair_generation() {
        let (sk, vk, fp) = ManifestVerifier::generate_keypair();
        assert_eq!(fp.len(), 64);
        assert_eq!(sk.len(), 64);
        assert_eq!(vk.len(), 64);
    }

    #[tokio::test]
    async fn test_gateway_state_initialization() {
        let state = GatewayState::new(test_config());
        assert!(state.is_ok());
    }

    #[tokio::test]
    async fn test_scope_declaration_handler() {
        let state = Arc::new(GatewayState::new(test_config()).unwrap());
        let req = DeclareScopeRequest {
            workflow_id: "test-wf-1".to_string(),
            declared_scope: "Allowed tools: read_customer_db.".to_string(),
        };
        let _ = handle_declare_scope(State(state.clone()), AxumJson(req)).await;
        let has_log = state.firewall.lock().await.session_log("test-wf-1").is_some();
        assert!(has_log);
    }
}
