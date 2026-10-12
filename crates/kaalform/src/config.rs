//! Kaalform configuration — loaded from environment variables.
//!
//! All configuration is read from environment variables at startup.
//! No hardcoded credentials, addresses, or keys.
//!
//! | Variable                          | Default            | Description                                 |
//! |-----------------------------------|--------------------|---------------------------------------------|
//! | `KAALFORM_LISTEN_ADDR`            | `0.0.0.0:7070`     | HTTP gateway listen address                 |
//! | `KAALFORM_UPSTREAM_MCP_URL`       | (required)         | Upstream MCP server base URL                |
//! | `KAALFORM_KAALADRISHTI_ADDR`      | `127.0.0.1:9090`   | Kaaladrishti TCP ingestion address          |
//! | `KAALFORM_DRIFT_THRESHOLD`        | `0.45`             | Max cosine drift before Pillar 5 denial     |
//! | `KAALFORM_REQUIRE_MANIFEST`       | `true`             | Reject calls with no manifest (Pillar 4)    |
//! | `KAALFORM_TRUSTED_KEYS_PATH`      | (optional)         | JSON file of trusted Ed25519 public keys    |
//! | `KAALFORM_SIGNING_KEY_PATH`       | (optional)         | Path to Ed25519 private key (PEM/hex)       |
//! | `KAALFORM_SESSION_TTL_SECS`       | `3600`             | Provenance session lifetime in seconds      |
//! | `KAALFORM_LOG_LEVEL`              | `info`             | Tracing log level                           |

use std::env;

use crate::error::{KaalformError, Result};

/// Runtime configuration for the Kaalform gateway.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP gateway listens on.
    pub listen_addr: String,

    /// Base URL of the upstream MCP server Kaalform proxies to.
    pub upstream_mcp_url: String,

    /// TCP address of the Kaaladrishti Go engine ingestion port.
    pub kaaladrishti_addr: String,

    /// Maximum allowed cosine drift score before Pillar 5 denies the call.
    /// Range [0.0, 1.0]. Lower = stricter.
    pub drift_threshold: f64,

    /// If true, tool calls with no tool manifest are rejected immediately (Pillar 4).
    pub require_manifest: bool,

    /// Optional path to a JSON file containing trusted Ed25519 public keys.
    /// If None, Pillar 4 operates in log-only mode (no enforcement).
    pub trusted_keys_path: Option<String>,

    /// Optional path to the Ed25519 private key used by Kaalform to sign
    /// authorization receipts. Hex-encoded raw 32-byte seed.
    pub signing_key_path: Option<String>,

    /// Provenance session lifetime in seconds.
    /// After expiry, the session's accumulated context is cleared.
    pub session_ttl_secs: u64,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Returns an error if `KAALFORM_UPSTREAM_MCP_URL` is not set.
    pub fn from_env() -> Result<Self> {
        let upstream_mcp_url = env::var("KAALFORM_UPSTREAM_MCP_URL").map_err(|_| {
            KaalformError::Config(
                "KAALFORM_UPSTREAM_MCP_URL is required but not set".to_string(),
            )
        })?;

        let drift_threshold = env::var("KAALFORM_DRIFT_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.45);

        if !(0.0..=1.0).contains(&drift_threshold) {
            return Err(KaalformError::Config(format!(
                "KAALFORM_DRIFT_THRESHOLD must be in [0.0, 1.0], got {drift_threshold}"
            )));
        }

        let session_ttl_secs = env::var("KAALFORM_SESSION_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3600);

        Ok(Self {
            listen_addr: env::var("KAALFORM_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:7070".to_string()),
            upstream_mcp_url,
            kaaladrishti_addr: env::var("KAALFORM_KAALADRISHTI_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9090".to_string()),
            drift_threshold,
            require_manifest: env::var("KAALFORM_REQUIRE_MANIFEST")
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            trusted_keys_path: env::var("KAALFORM_TRUSTED_KEYS_PATH")
                .ok()
                .or_else(|| {
                    let candidates = [
                        "crates/kaalform/config/trusted_keys.json",
                        "config/trusted_keys.json",
                    ];
                    for c in &candidates {
                        if std::path::Path::new(c).exists() {
                            return Some(c.to_string());
                        }
                    }
                    None
                }),
            signing_key_path: env::var("KAALFORM_SIGNING_KEY_PATH").ok(),
            session_ttl_secs,
        })
    }
}
