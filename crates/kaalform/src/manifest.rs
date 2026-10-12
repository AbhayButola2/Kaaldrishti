//! Tool manifest data model and canonical serialization (Pillar 4).
//!
//! A `ToolManifest` is a JSON document that describes an MCP tool and carries
//! a cryptographic signature over its canonical form. The signature is produced
//! by a trusted key (controlled by the organization's tool-attestation pipeline)
//! and verified by the `ManifestVerifier` before the tool call is forwarded.
//!
//! ## Canonical Form
//!
//! To prevent ambiguity, the signature is computed over the *canonical* JSON
//! serialization, which is:
//!
//! ```text
//! SHA-256( canonical_json(ToolManifestBody) )
//! ```
//!
//! where `canonical_json` produces a UTF-8 JSON string with keys sorted
//! alphabetically and no extra whitespace.
//!
//! ## Wire Format
//!
//! The manifest is transmitted as a JSON string in the `X-Kaalform-Manifest`
//! HTTP header of every MCP tool call request. The gateway extracts and verifies
//! it before proxying.
//!
//! ## Versioning
//!
//! The `manifest_version` field must be `"1"` in this implementation.
//! Future versions extend the body additively.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{KaalformError, Result};

/// The signed manifest body — fields that are included in the signature digest.
///
/// When adding new fields in future versions, add them with `Option<>` so
/// that old manifests remain verifiable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolManifestBody {
    /// Manifest schema version. Must be "1" in this implementation.
    pub manifest_version: String,

    /// Globally unique, stable identifier for this tool definition.
    /// Example: `"kaaladrishti/graph-query@1.2.0"`
    pub tool_id: String,

    /// Human-readable name shown in SOC dashboards.
    pub tool_name: String,

    /// Semver version of the tool implementation.
    pub tool_version: String,

    /// Declared capabilities (read-only, write, network, exec, …).
    /// Used by Pillar 5 to validate the tool's permitted privilege class.
    pub capabilities: Vec<String>,

    /// Allowed principal identifiers that may invoke this tool.
    /// Wildcard `"*"` permits any principal.
    pub allowed_principals: Vec<String>,

    /// Maximum allowed privilege level (0.0 = unprivileged, 10.0 = root).
    pub max_privilege_level: f64,

    /// ISO-8601 UTC expiry timestamp after which the manifest is invalid.
    /// Example: `"2027-01-01T00:00:00Z"`
    pub expires_at: String,

    /// Fingerprint (hex-encoded SHA-256) of the signing public key.
    /// Used by the verifier to look up the key in the trust store.
    pub signing_key_fingerprint: String,
}

/// A complete, signed tool manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    /// The manifest content that was signed.
    pub body: ToolManifestBody,

    /// Hex-encoded Ed25519 signature over `SHA-256(canonical_json(body))`.
    pub signature: String,
}

impl ToolManifest {
    /// Compute the canonical signing digest for this manifest's body.
    ///
    /// The digest is `SHA-256(canonical_json(body))` where `canonical_json`
    /// serializes the body with sorted keys and no whitespace.
    ///
    /// # Errors
    /// Returns `InvalidManifest` if the body cannot be serialized to JSON.
    pub fn signing_digest(&self) -> Result<Vec<u8>> {
        canonical_digest(&self.body)
    }

    /// Validate the structural constraints on the manifest body.
    ///
    /// Does NOT verify the cryptographic signature — that is the responsibility
    /// of the `ManifestVerifier`.
    ///
    /// # Errors
    /// Returns `InvalidManifest` if any field is empty or out of range.
    pub fn validate_structure(&self) -> Result<()> {
        if self.body.manifest_version != "1" {
            return Err(KaalformError::InvalidManifest(format!(
                "unsupported manifest_version '{}'; expected '1'",
                self.body.manifest_version
            )));
        }
        if self.body.tool_id.is_empty() {
            return Err(KaalformError::InvalidManifest(
                "tool_id must not be empty".to_string(),
            ));
        }
        if self.body.tool_version.is_empty() {
            return Err(KaalformError::InvalidManifest(
                "tool_version must not be empty".to_string(),
            ));
        }
        if self.body.signing_key_fingerprint.is_empty() {
            return Err(KaalformError::InvalidManifest(
                "signing_key_fingerprint must not be empty".to_string(),
            ));
        }
        if !(0.0..=10.0).contains(&self.body.max_privilege_level) {
            return Err(KaalformError::InvalidManifest(format!(
                "max_privilege_level {} out of range [0.0, 10.0]",
                self.body.max_privilege_level
            )));
        }
        if self.signature.is_empty() {
            return Err(KaalformError::InvalidManifest(
                "signature must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Parse a `ToolManifest` from a JSON string (e.g., from the HTTP header).
    ///
    /// # Errors
    /// Returns `Json` if the JSON is malformed.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(KaalformError::Json)
    }

    /// Serialize to a compact JSON string.
    ///
    /// # Errors
    /// Returns `Json` if serialization fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(KaalformError::Json)
    }
}

/// Produce a deterministic SHA-256 digest over the canonical JSON of a value.
///
/// Canonical JSON: keys sorted alphabetically, no extra whitespace.
/// This is done by deserializing into a `serde_json::Value` and re-serializing
/// with `serde_json::to_string`, which preserves insertion order for objects —
/// so we sort the keys explicitly via a BTreeMap.
fn canonical_digest<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Serialize to an intermediate Value.
    let json_value = serde_json::to_value(value).map_err(KaalformError::Json)?;

    // Recursively sort object keys using BTreeMap (alphabetical).
    let sorted = sort_keys(&json_value);

    // Re-serialize to compact JSON.
    let canonical = serde_json::to_string(&sorted).map_err(KaalformError::Json)?;

    // SHA-256 hash.
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().to_vec())
}

fn sort_keys(value: &serde_json::Value) -> serde_json::Value {
    use std::collections::BTreeMap;
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&str, serde_json::Value> =
                map.iter().map(|(k, v)| (k.as_str(), sort_keys(v))).collect();
            serde_json::Value::Object(sorted.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_keys).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> ToolManifestBody {
        ToolManifestBody {
            manifest_version: "1".to_string(),
            tool_id: "kaaladrishti/graph-query@1.0.0".to_string(),
            tool_name: "Graph Query".to_string(),
            tool_version: "1.0.0".to_string(),
            capabilities: vec!["read".to_string()],
            allowed_principals: vec!["alice@corp.internal".to_string()],
            max_privilege_level: 2.0,
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            signing_key_fingerprint: "aabbcc".to_string(),
        }
    }

    #[test]
    fn test_canonical_digest_is_deterministic() {
        let body = sample_body();
        let d1 = canonical_digest(&body).unwrap();
        let d2 = canonical_digest(&body).unwrap();
        assert_eq!(d1, d2, "digest must be deterministic");
        assert_eq!(d1.len(), 32, "SHA-256 must produce 32 bytes");
    }

    #[test]
    fn test_validate_structure_rejects_empty_tool_id() {
        let mut manifest = ToolManifest {
            body: sample_body(),
            signature: "aabb".to_string(),
        };
        manifest.body.tool_id = String::new();
        assert!(manifest.validate_structure().is_err());
    }

    #[test]
    fn test_validate_structure_rejects_bad_version() {
        let mut manifest = ToolManifest {
            body: sample_body(),
            signature: "aabb".to_string(),
        };
        manifest.body.manifest_version = "99".to_string();
        assert!(manifest.validate_structure().is_err());
    }

    #[test]
    fn test_json_roundtrip() {
        let manifest = ToolManifest {
            body: sample_body(),
            signature: "cafebabe".to_string(),
        };
        let json = manifest.to_json().unwrap();
        let parsed = ToolManifest::from_json(&json).unwrap();
        assert_eq!(manifest.body.tool_id, parsed.body.tool_id);
        assert_eq!(manifest.signature, parsed.signature);
    }
}
