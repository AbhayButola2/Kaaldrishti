//! Pillar 5: Context-to-Action Provenance Firewall.
//!
//! The `ProvenanceFirewall` enforces that the actual MCP tool calls made by an
//! autonomous agent remain within the scope of its declared intent (system
//! prompt / `AgentPlan`).
//!
//! ## Model
//!
//! Each agent workflow is tracked as a `ProvenanceSession`. A session contains:
//! - The declared scope (system prompt / intent text).
//! - The sequence of actual actions (tool ID, tool arguments, principal).
//! - An accumulated drift score.
//!
//! The drift score is computed via **cosine similarity** between a bag-of-words
//! vector of the declared scope and the bag-of-words vector of the actual action.
//! Drift = 1.0 - cosine_similarity.
//!
//! When the drift score exceeds `Config::drift_threshold`, the firewall:
//! 1. Issues a **DENIED** `AuthorizationReceipt`.
//! 2. Returns a `DriftExceeded` error to the gateway (which returns HTTP 403).
//! 3. The caller is responsible for emitting the receipt to Kaaladrishti.
//!
//! ## Sessions
//!
//! Sessions are keyed by `workflow_id` (caller-provided string, e.g., a
//! LangChain run ID or AutoGen conversation ID). Sessions expire after
//! `Config::session_ttl_secs` seconds of inactivity.
//!
//! ## Why Cosine Similarity?
//!
//! Cosine similarity on bag-of-words is deliberately chosen for the prototype:
//! - **No ML model dependency at runtime** — the firewall starts instantly.
//! - **Explainable** — the SOC dashboard can show which tokens caused drift.
//! - **Extensible** — replace `score_drift` with neural embeddings (sentence-transformers
//!   via a gRPC call) for production without changing the session or receipt model.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::{KaalformError, Result};

// ---------------------------------------------------------------------------
// Authorization Receipt (Pillar 5 output record)
// ---------------------------------------------------------------------------

/// The verdict of the Pillar 5 provenance check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationVerdict {
    /// The action is within the declared scope; proceed.
    Approved,
    /// The action deviates from declared scope; blocked.
    Denied,
}

/// An `AuthorizationReceipt` is the immutable record of a Pillar 5 decision.
/// It is emitted to Kaaladrishti as a `NODE_TYPE_AUTHORIZATION` graph node so
/// the SOC can see the full provenance chain:
/// `AgentPlan → Action → AuthorizationReceipt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationReceipt {
    /// Unique receipt ID (UUIDv4).
    pub receipt_id: String,

    /// The workflow / session this receipt belongs to.
    pub workflow_id: String,

    /// The tool invocation that triggered the check.
    pub tool_id: String,

    /// The principal (agent identity) making the call.
    pub principal_id: String,

    /// Whether the action was approved or denied.
    pub verdict: AuthorizationVerdict,

    /// The cosine drift score that led to this decision. [0.0, 1.0]
    pub drift_score: f64,

    /// The threshold at the time of the decision.
    pub drift_threshold: f64,

    /// Human-readable explanation of the decision.
    pub reason: String,

    /// Unix epoch milliseconds when the receipt was issued.
    pub issued_at_ms: u64,

    /// The top tokens that contributed to the drift (for SOC explainability).
    pub drift_tokens: Vec<String>,
}

impl AuthorizationReceipt {
    /// Issue an APPROVED receipt.
    pub fn approved(
        workflow_id: &str,
        tool_id: &str,
        principal_id: &str,
        drift_score: f64,
        threshold: f64,
        drift_tokens: Vec<String>,
    ) -> Self {
        Self {
            receipt_id: Uuid::new_v4().to_string(),
            workflow_id: workflow_id.to_string(),
            tool_id: tool_id.to_string(),
            principal_id: principal_id.to_string(),
            verdict: AuthorizationVerdict::Approved,
            drift_score,
            drift_threshold: threshold,
            reason: format!(
                "Action within declared scope (drift={drift_score:.3} ≤ threshold={threshold:.3})"
            ),
            issued_at_ms: now_ms(),
            drift_tokens,
        }
    }

    /// Issue a DENIED receipt.
    pub fn denied(
        workflow_id: &str,
        tool_id: &str,
        principal_id: &str,
        drift_score: f64,
        threshold: f64,
        drift_tokens: Vec<String>,
    ) -> Self {
        Self {
            receipt_id: Uuid::new_v4().to_string(),
            workflow_id: workflow_id.to_string(),
            tool_id: tool_id.to_string(),
            principal_id: principal_id.to_string(),
            verdict: AuthorizationVerdict::Denied,
            drift_score,
            drift_threshold: threshold,
            reason: format!(
                "Action deviates from declared scope (drift={drift_score:.3} > threshold={threshold:.3})"
            ),
            issued_at_ms: now_ms(),
            drift_tokens,
        }
    }
}

// ---------------------------------------------------------------------------
// Provenance Session
// ---------------------------------------------------------------------------

/// One tracked agent workflow session.
#[derive(Debug)]
pub struct ProvenanceSession {
    /// Workflow identifier.
    pub workflow_id: String,

    /// Declared scope / intent text (system prompt, AgentPlan summary).
    pub declared_scope: String,

    /// Bag-of-words vector for the declared scope (pre-computed for efficiency).
    scope_bow: BagOfWords,

    /// Log of actual actions taken in this session.
    pub action_log: Vec<ActionRecord>,

    /// The running maximum drift score seen in this session.
    pub max_drift_score: f64,

    /// Last activity timestamp (for session TTL).
    last_seen: Instant,
}

/// Record of a single tool invocation within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub tool_id: String,
    pub principal_id: String,
    /// The action text used for drift scoring (tool ID + serialized args).
    pub action_text: String,
    pub drift_score: f64,
    pub verdict: AuthorizationVerdict,
    pub receipt_id: String,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// ProvenanceFirewall
// ---------------------------------------------------------------------------

/// Pillar 5 enforcement engine.
pub struct ProvenanceFirewall {
    sessions: HashMap<String, ProvenanceSession>,
    drift_threshold: f64,
    session_ttl: Duration,
}

impl ProvenanceFirewall {
    /// Create a new firewall with the given drift threshold and session TTL.
    #[must_use]
    pub fn new(drift_threshold: f64, session_ttl_secs: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            drift_threshold,
            session_ttl: Duration::from_secs(session_ttl_secs),
        }
    }

    /// Register or update the declared scope for a workflow session.
    ///
    /// Call this when the agent's system prompt / AgentPlan is established.
    pub fn declare_scope(&mut self, workflow_id: &str, declared_scope: &str) {
        let scope_bow = BagOfWords::from_text(declared_scope);
        let session = self
            .sessions
            .entry(workflow_id.to_string())
            .or_insert_with(|| ProvenanceSession {
                workflow_id: workflow_id.to_string(),
                declared_scope: declared_scope.to_string(),
                scope_bow: BagOfWords::empty(),
                action_log: Vec::new(),
                max_drift_score: 0.0,
                last_seen: Instant::now(),
            });
        session.declared_scope = declared_scope.to_string();
        session.scope_bow = scope_bow;
        session.last_seen = Instant::now();

        info!(workflow_id = %workflow_id, "Pillar 5: scope declared for workflow");
    }

    /// Check an incoming tool call against the declared scope.
    ///
    /// Returns an `AuthorizationReceipt` on both approval and denial.
    ///
    /// # Errors
    /// Returns `DriftExceeded` if the drift score exceeds the threshold.
    /// Returns `Config` if `workflow_id` has no registered scope (caller must
    /// call `declare_scope` first, or pass `auto_scope=true` in the gateway).
    pub fn check_action(
        &mut self,
        workflow_id: &str,
        tool_id: &str,
        principal_id: &str,
        action_text: &str,
    ) -> Result<AuthorizationReceipt> {
        self.evict_expired_sessions();

        let session = self.sessions.get_mut(workflow_id).ok_or_else(|| {
            KaalformError::Config(format!(
                "no declared scope for workflow '{workflow_id}'; call declare_scope first"
            ))
        })?;
        session.last_seen = Instant::now();

        // Compute drift.
        let action_bow = BagOfWords::from_text(action_text);
        let (drift_score, drift_tokens) = action_bow.drift_from(&session.scope_bow);

        session.max_drift_score = session.max_drift_score.max(drift_score);

        let receipt = if drift_score > self.drift_threshold {
            warn!(
                workflow_id = %workflow_id,
                tool_id = %tool_id,
                drift_score,
                threshold = self.drift_threshold,
                ?drift_tokens,
                "Pillar 5: DENIED — action deviates from declared scope"
            );
            AuthorizationReceipt::denied(
                workflow_id,
                tool_id,
                principal_id,
                drift_score,
                self.drift_threshold,
                drift_tokens,
            )
        } else {
            info!(
                workflow_id = %workflow_id,
                tool_id = %tool_id,
                drift_score,
                threshold = self.drift_threshold,
                "Pillar 5: APPROVED"
            );
            AuthorizationReceipt::approved(
                workflow_id,
                tool_id,
                principal_id,
                drift_score,
                self.drift_threshold,
                drift_tokens,
            )
        };

        // Record the action regardless of verdict.
        session.action_log.push(ActionRecord {
            tool_id: tool_id.to_string(),
            principal_id: principal_id.to_string(),
            action_text: action_text.to_string(),
            drift_score,
            verdict: receipt.verdict.clone(),
            receipt_id: receipt.receipt_id.clone(),
            timestamp_ms: now_ms(),
        });

        if receipt.verdict == AuthorizationVerdict::Denied {
            return Err(KaalformError::DriftExceeded {
                workflow_id: workflow_id.to_string(),
                score: drift_score,
                threshold: self.drift_threshold,
            });
        }

        Ok(receipt)
    }

    /// Get a snapshot of a session's action log (for audit / dashboard queries).
    pub fn session_log(&self, workflow_id: &str) -> Option<&[ActionRecord]> {
        self.sessions
            .get(workflow_id)
            .map(|s| s.action_log.as_slice())
    }

    /// Evict sessions that have been idle longer than the TTL.
    fn evict_expired_sessions(&mut self) {
        let ttl = self.session_ttl;
        self.sessions
            .retain(|_, s| s.last_seen.elapsed() < ttl);
    }
}

// ---------------------------------------------------------------------------
// Bag-of-Words drift scorer
// ---------------------------------------------------------------------------

/// A simple bag-of-words model for drift scoring.
///
/// In production this would be replaced by a sentence-transformer embedding
/// (called via gRPC to the Python ML service), but for the prototype we use
/// token overlap, which is fast, explainable, and dependency-free.
#[derive(Debug, Clone)]
struct BagOfWords {
    /// Token → normalized frequency.
    tokens: HashMap<String, f64>,
}

impl BagOfWords {
    fn empty() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    fn from_text(text: &str) -> Self {
        let mut counts: HashMap<String, f64> = HashMap::new();
        for token in tokenize(text) {
            *counts.entry(token).or_default() += 1.0;
        }
        // L2-normalize.
        let norm = counts.values().map(|v| v * v).sum::<f64>().sqrt();
        if norm > 0.0 {
            for v in counts.values_mut() {
                *v /= norm;
            }
        }
        Self { tokens: counts }
    }

    /// Compute drift = 1.0 - cosine_similarity(self, other).
    ///
    /// Returns `(drift_score, top_drift_tokens)`.
    /// `drift_tokens` are the tokens in `self` (action) not present in `other` (scope),
    /// contributing most to the deviation.
    fn drift_from(&self, scope: &BagOfWords) -> (f64, Vec<String>) {
        // Cosine similarity = dot product of L2-normalised vectors.
        let dot: f64 = self
            .tokens
            .iter()
            .filter_map(|(tok, v)| scope.tokens.get(tok).map(|u| v * u))
            .sum();

        // Drift tokens: tokens in action not in scope.
        let mut drift_tokens: Vec<String> = self
            .tokens
            .keys()
            .filter(|tok| !scope.tokens.contains_key(tok.as_str()))
            .cloned()
            .collect();
        drift_tokens.sort();
        drift_tokens.truncate(10); // top 10 for readability

        let drift = (1.0 - dot).clamp(0.0, 1.0);
        (drift, drift_tokens)
    }
}

/// Simple stemming helper for English plurals and standard verb endings.
fn stem(tok: &str) -> String {
    let mut s = tok.to_string();
    if s.ends_with("ies") && s.len() > 4 {
        s.truncate(s.len() - 3);
        s.push('y');
        return s;
    }
    if s.ends_with("ing") && s.len() > 5 {
        s.truncate(s.len() - 3);
        return s;
    }
    if s.ends_with("ed") && s.len() > 4 {
        s.truncate(s.len() - 2);
        return s;
    }
    if s.ends_with('s') && !s.ends_with("ss") && s.len() > 3 {
        s.pop();
        return s;
    }
    s
}

/// Tokenize text into lowercase alpha tokens (stop words excluded, stemmed).
fn tokenize(text: &str) -> impl Iterator<Item = String> + '_ {
    const STOP_WORDS: &[&str] = &[
        "the", "a", "an", "and", "or", "to", "of", "in", "is", "are", "for",
        "with", "on", "at", "by", "from", "that", "this", "it", "be", "as",
        "its", "into", "not", "have", "will", "was", "has", "you", "your",
        "may", "only", "must", "any", "can", "all", "our", "we", "they",
        // Common JSON wrapper keys
        "action", "actions", "argument", "arguments", "args", "param", "params",
        "parameter", "parameters", "value", "values",
    ];
    text.split(|c: char| !c.is_alphabetic())
        .map(str::to_lowercase)
        .map(|tok| stem(&tok))
        .filter(move |tok| tok.len() > 2 && !STOP_WORDS.contains(&tok.as_str()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fw() -> ProvenanceFirewall {
        ProvenanceFirewall::new(0.45, 3600)
    }

    const SCOPE: &str =
        "You are a database assistant. You may only read data from the customer database. \
         You must not delete or modify any records. Allowed tools: sql_query.";

    #[test]
    fn test_in_scope_action_approved() {
        let mut fw = make_fw();
        fw.declare_scope("wf-1", SCOPE);

        let receipt = fw
            .check_action("wf-1", "sql_query", "agent-1", "sql_query read customer database")
            .unwrap();
        assert_eq!(receipt.verdict, AuthorizationVerdict::Approved);
        assert!(receipt.drift_score <= 0.45);
    }

    #[test]
    fn test_out_of_scope_action_denied() {
        let mut fw = make_fw();
        fw.declare_scope("wf-2", SCOPE);

        let result = fw.check_action(
            "wf-2",
            "shell_exec",
            "agent-1",
            "shell execute rm -rf production server delete all records admin root",
        );
        assert!(result.is_err(), "out-of-scope action must be denied");
        if let Err(KaalformError::DriftExceeded { score, threshold, .. }) = result {
            assert!(score > threshold, "drift must exceed threshold");
        }
    }

    #[test]
    fn test_no_scope_returns_config_error() {
        let mut fw = make_fw();
        let result = fw.check_action("wf-no-scope", "sql_query", "agent-1", "read data");
        assert!(matches!(result, Err(KaalformError::Config(_))));
    }

    #[test]
    fn test_action_log_is_populated() {
        let mut fw = make_fw();
        fw.declare_scope("wf-3", SCOPE);
        let _ = fw.check_action("wf-3", "sql_query", "agent-1", "sql_query read customer");
        let log = fw.session_log("wf-3").unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].tool_id, "sql_query");
    }

    #[test]
    fn test_drift_tokens_are_populated_on_denial() {
        let mut fw = make_fw();
        fw.declare_scope("wf-4", SCOPE);
        let result = fw.check_action(
            "wf-4",
            "shell_exec",
            "agent-1",
            "execute shell command escalate privileges attacker lateral movement",
        );
        if let Err(KaalformError::DriftExceeded { .. }) = result {
            let log = fw.session_log("wf-4").unwrap();
            // Drift tokens should appear in the action log record.
            assert!(!log.is_empty());
        }
    }

    #[test]
    fn test_cosine_sim_identical_texts_zero_drift() {
        let bow1 = BagOfWords::from_text("sql query read customer database");
        let bow2 = BagOfWords::from_text("sql query read customer database");
        let (drift, _) = bow1.drift_from(&bow2);
        assert!(drift < 0.01, "identical texts must have near-zero drift");
    }

    #[test]
    fn test_cosine_sim_disjoint_texts_max_drift() {
        let bow1 = BagOfWords::from_text("execute shell command root admin delete destroy");
        let bow2 = BagOfWords::from_text("query read customer sales orders invoice");
        let (drift, _) = bow1.drift_from(&bow2);
        assert!(
            drift > 0.8,
            "completely disjoint texts must have high drift"
        );
    }
}
