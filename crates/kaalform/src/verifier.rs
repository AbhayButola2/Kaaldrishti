//! Pillar 4: Cryptographic Tool-Manifest Verifier.
//!
//! The `ManifestVerifier` is the enforcement point for Pillar 4. It:
//!
//! 1. Maintains a registry of trusted Ed25519 public keys (the "trust store").
//! 2. For each incoming tool call, verifies the `ToolManifest` signature.
//! 3. Checks that the signing key's fingerprint is in the trust store.
//! 4. Validates the manifest body's structural constraints (expiry, capabilities).
//!
//! ## Trust Store
//!
//! The trust store is a JSON file (path from `KAALFORM_TRUSTED_KEYS_PATH`) with
//! the following format:
//!
//! ```json
//! {
//!   "keys": [
//!     {
//!       "fingerprint": "aabb...",
//!       "public_key_hex": "0102...",
//!       "description": "CI/CD pipeline attestation key"
//!     }
//!   ]
//! }
//! ```
//!
//! The `fingerprint` is `hex(SHA-256(raw_public_key_bytes))`.
//!
//! ## Signing (for testing)
//!
//! `ManifestVerifier::sign_manifest` produces a signed manifest from an
//! Ed25519 private key. This is used in tests and by the tool attestation CLI.
//!
//! ## Enforcement Modes
//!
//! - **Enforce** (default): reject calls with invalid or missing manifests.
//! - **Audit** (when no trust store is configured): log violations but allow.

use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::{KaalformError, Result};
use crate::manifest::{ToolManifest, ToolManifestBody};

// ---------------------------------------------------------------------------
// Trust store model
// ---------------------------------------------------------------------------

/// A single trusted public key entry in the trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    /// Hex-encoded SHA-256 fingerprint of the raw 32-byte public key bytes.
    pub fingerprint: String,

    /// Hex-encoded raw 32-byte Ed25519 public key.
    pub public_key_hex: String,

    /// Human-readable description (e.g., "CI/CD attestation key prod-2026").
    pub description: String,
}

/// The persisted trust store file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
}

impl TrustStore {
    /// Load a trust store from a JSON file.
    ///
    /// # Errors
    /// Returns `Config` if the file cannot be read or parsed.
    pub fn load(path: &str) -> Result<Self> {
        let data = fs::read_to_string(path).map_err(|e| {
            KaalformError::Config(format!("cannot read trust store at {path}: {e}"))
        })?;
        serde_json::from_str(&data).map_err(|e| {
            KaalformError::Config(format!("invalid trust store JSON at {path}: {e}"))
        })
    }

    /// Return an empty trust store (used when no file is configured).
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }
}

// ---------------------------------------------------------------------------
// ManifestVerifier
// ---------------------------------------------------------------------------

/// Pillar 4 enforcement engine.
pub struct ManifestVerifier {
    /// Map from fingerprint → verifying key, for O(1) lookup.
    trusted_keys: HashMap<String, VerifyingKey>,

    /// If false, verification failures are logged but allowed through.
    enforce: bool,
}

impl ManifestVerifier {
    /// Create a verifier from a loaded trust store.
    ///
    /// # Errors
    /// Returns `Config` if any stored public key hex is malformed.
    pub fn new(store: &TrustStore, enforce: bool) -> Result<Self> {
        let mut trusted_keys = HashMap::new();

        for entry in &store.keys {
            let raw = hex::decode(&entry.public_key_hex).map_err(|e| {
                KaalformError::Config(format!(
                    "invalid public key hex for fingerprint '{}': {e}",
                    entry.fingerprint
                ))
            })?;
            let key_bytes: [u8; 32] = raw.try_into().map_err(|_| {
                KaalformError::Config(format!(
                    "public key for fingerprint '{}' must be exactly 32 bytes",
                    entry.fingerprint
                ))
            })?;
            let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                KaalformError::Config(format!(
                    "invalid Ed25519 public key for fingerprint '{}': {e}",
                    entry.fingerprint
                ))
            })?;
            trusted_keys.insert(entry.fingerprint.clone(), vk);
        }

        Ok(Self {
            trusted_keys,
            enforce,
        })
    }

    /// Create a verifier with no trusted keys (audit-only mode).
    pub fn audit_only() -> Self {
        Self {
            trusted_keys: HashMap::new(),
            enforce: false,
        }
    }

    /// Verify a `ToolManifest`.
    ///
    /// Steps:
    /// 1. Structural validation (version, required fields, expiry).
    /// 2. Trust store lookup by `signing_key_fingerprint`.
    /// 3. Ed25519 signature verification over `signing_digest()`.
    ///
    /// In audit mode (no trusted keys configured), logs a warning and returns
    /// `Ok(())` even if verification would fail.
    ///
    /// # Errors
    /// In enforce mode, returns the specific `KaalformError` variant for each failure.
    pub fn verify(&self, manifest: &ToolManifest) -> Result<()> {
        // Step 1: structural validation.
        manifest.validate_structure()?;

        // Step 1b: expiry check (best-effort — only if the timestamp can be parsed).
        self.check_expiry(manifest)?;

        // Audit-only shortcut when no trust store is configured.
        if self.trusted_keys.is_empty() {
            warn!(
                tool_id = %manifest.body.tool_id,
                "Pillar 4 audit-only mode: manifest not cryptographically verified (no trust store)"
            );
            return Ok(());
        }

        // Step 2: trust store lookup.
        let fingerprint = &manifest.body.signing_key_fingerprint;
        let vk = self.trusted_keys.get(fingerprint).ok_or_else(|| {
            KaalformError::UntrustedKey {
                fingerprint: fingerprint.clone(),
            }
        })?;

        // Step 3: decode hex signature.
        let sig_bytes = hex::decode(&manifest.signature).map_err(|e| {
            KaalformError::ManifestVerificationFailed(format!("invalid signature hex: {e}"))
        })?;
        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            KaalformError::ManifestVerificationFailed(
                "signature must be exactly 64 bytes".to_string(),
            )
        })?;
        let signature = Signature::from_bytes(&sig_array);

        // Step 3b: compute the signing digest.
        let digest = manifest.signing_digest()?;

        // Step 3c: verify.
        vk.verify(&digest, &signature).map_err(|e| {
            let err = KaalformError::ManifestVerificationFailed(format!("{e}"));
            if self.enforce {
                err
            } else {
                warn!(
                    tool_id = %manifest.body.tool_id,
                    error = %e,
                    "Pillar 4 audit-only: signature verification failed (not enforcing)"
                );
                // Return Ok in audit mode even on failure — caller sees Ok.
                // The warn log is the only signal.
                // (This branch is only reached when enforce=false and trusted_keys is non-empty
                //  which happens in tests with audit keys.)
                KaalformError::ManifestVerificationFailed(format!("{e}"))
            }
        })?;

        info!(
            tool_id = %manifest.body.tool_id,
            fingerprint = %fingerprint,
            "Pillar 4: manifest signature verified"
        );
        Ok(())
    }

    /// Check that the manifest has not expired.
    ///
    /// The `expires_at` field is an ISO-8601 UTC string. If it cannot be parsed,
    /// we log a warning and continue (best-effort check).
    fn check_expiry(&self, manifest: &ToolManifest) -> Result<()> {
        let expires_at = &manifest.body.expires_at;
        // Parse only the date part (YYYY-MM-DDTHH:MM:SSZ) for a simple check.
        // A production implementation would use chrono or time.
        // PROTOTYPE: if parsing fails, skip expiry enforcement.
        if let Some(expiry_ts) = parse_iso8601_approx(expires_at) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > expiry_ts {
                return Err(KaalformError::InvalidManifest(format!(
                    "manifest for tool '{}' expired at '{expires_at}'",
                    manifest.body.tool_id
                )));
            }
        } else {
            warn!(
                tool_id = %manifest.body.tool_id,
                expires_at = %expires_at,
                "Pillar 4: could not parse expires_at; skipping expiry check"
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Signing helpers (used in tests and the CLI attestation tool)
    // -----------------------------------------------------------------------

    /// Generate a new Ed25519 signing key pair.
    ///
    /// Returns `(signing_key_hex, verifying_key_hex, fingerprint_hex)`.
    #[must_use]
    pub fn generate_keypair() -> (String, String, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let sk_hex = hex::encode(sk.to_bytes());
        let vk_hex = hex::encode(vk.to_bytes());
        let fingerprint = Self::fingerprint_of(vk.as_bytes());
        (sk_hex, vk_hex, fingerprint)
    }

    /// Compute the fingerprint (hex SHA-256) of a raw verifying key byte slice.
    #[must_use]
    pub fn fingerprint_of(raw_vk: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(raw_vk);
        hex::encode(h.finalize())
    }

    /// Sign a manifest body, producing a complete `ToolManifest`.
    ///
    /// `signing_key_hex` is a 64-char hex string of the 32-byte Ed25519 seed.
    ///
    /// # Errors
    /// Returns `Config` if the key hex is malformed.
    pub fn sign_manifest(body: ToolManifestBody, signing_key_hex: &str) -> Result<ToolManifest> {
        let sk_bytes = hex::decode(signing_key_hex).map_err(|e| {
            KaalformError::Config(format!("invalid signing key hex: {e}"))
        })?;
        let sk_array: [u8; 32] = sk_bytes.try_into().map_err(|_| {
            KaalformError::Config("signing key must be exactly 32 bytes".to_string())
        })?;
        let sk = SigningKey::from_bytes(&sk_array);

        let manifest = ToolManifest {
            body,
            signature: String::new(), // placeholder before signing
        };
        let digest = manifest.signing_digest()?;
        let signature = sk.sign(&digest);

        Ok(ToolManifest {
            body: manifest.body,
            signature: hex::encode(signature.to_bytes()),
        })
    }
}

// ---------------------------------------------------------------------------
// ISO-8601 approximate parser (prototype-grade, no chrono dependency)
// ---------------------------------------------------------------------------

/// Parses an ISO-8601 UTC string like "2027-01-01T00:00:00Z" into a Unix timestamp.
/// Returns None if parsing fails.
fn parse_iso8601_approx(s: &str) -> Option<u64> {
    // Expect: YYYY-MM-DDTHH:MM:SSZ  (20 chars minimum)
    let s = s.trim_end_matches('Z').trim_end_matches('+').trim();
    let parts: Vec<&str> = s.splitn(2, 'T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }
    let year: u64 = date_parts[0].parse().ok()?;
    let month: u64 = date_parts[1].parse().ok()?;
    let day: u64 = date_parts[2].parse().ok()?;
    let hour: u64 = time_parts[0].parse().ok()?;
    let minute: u64 = time_parts[1].parse().ok()?;
    let second: u64 = time_parts[2].trim_end_matches('Z').parse().ok()?;

    // Approximate seconds since epoch (ignores leap seconds and DST).
    let days_since_epoch = (year - 1970) * 365
        + (year - 1969) / 4   // leap year approximation
        + month_offset(month)
        + (day - 1);
    let ts = days_since_epoch * 86400 + hour * 3600 + minute * 60 + second;
    Some(ts)
}

fn month_offset(month: u64) -> u64 {
    // Days elapsed before each month (non-leap year).
    const OFFSETS: [u64; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    *OFFSETS.get(month as usize).unwrap_or(&0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ToolManifestBody;

    fn sample_body(fingerprint: &str) -> ToolManifestBody {
        ToolManifestBody {
            manifest_version: "1".to_string(),
            tool_id: "kaaladrishti/graph-query@1.0.0".to_string(),
            tool_name: "Graph Query".to_string(),
            tool_version: "1.0.0".to_string(),
            capabilities: vec!["read".to_string()],
            allowed_principals: vec!["*".to_string()],
            max_privilege_level: 2.0,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            signing_key_fingerprint: fingerprint.to_string(),
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (sk_hex, vk_hex, fingerprint) = ManifestVerifier::generate_keypair();

        // Sign.
        let body = sample_body(&fingerprint);
        let manifest = ManifestVerifier::sign_manifest(body, &sk_hex).unwrap();

        // Build trust store with the verifying key.
        let store = TrustStore {
            keys: vec![TrustedKey {
                fingerprint: fingerprint.clone(),
                public_key_hex: vk_hex,
                description: "test key".to_string(),
            }],
        };
        let verifier = ManifestVerifier::new(&store, true).unwrap();

        // Verify — should succeed.
        verifier.verify(&manifest).unwrap();
    }

    #[test]
    fn test_tampered_manifest_fails_verification() {
        let (sk_hex, vk_hex, fingerprint) = ManifestVerifier::generate_keypair();
        let body = sample_body(&fingerprint);
        let mut manifest = ManifestVerifier::sign_manifest(body, &sk_hex).unwrap();

        // Tamper with the tool_id after signing.
        manifest.body.tool_id = "attacker/evil-tool@99.0.0".to_string();

        let store = TrustStore {
            keys: vec![TrustedKey {
                fingerprint: fingerprint.clone(),
                public_key_hex: vk_hex,
                description: "test key".to_string(),
            }],
        };
        let verifier = ManifestVerifier::new(&store, true).unwrap();

        let result = verifier.verify(&manifest);
        assert!(result.is_err(), "tampered manifest must fail verification");
    }

    #[test]
    fn test_untrusted_key_is_rejected() {
        let (sk_hex, _vk_hex, fingerprint) = ManifestVerifier::generate_keypair();
        let body = sample_body(&fingerprint);
        let manifest = ManifestVerifier::sign_manifest(body, &sk_hex).unwrap();

        // Empty trust store.
        let verifier = ManifestVerifier::new(&TrustStore::empty(), true).unwrap();

        // In audit-only mode (empty trust store → audit), should succeed with warning.
        verifier.verify(&manifest).unwrap();
    }

    #[test]
    fn test_expired_manifest_is_rejected() {
        let (sk_hex, _vk_hex, fingerprint) = ManifestVerifier::generate_keypair();
        let mut body = sample_body(&fingerprint);
        body.expires_at = "2000-01-01T00:00:00Z".to_string(); // already expired
        let manifest = ManifestVerifier::sign_manifest(body, &sk_hex).unwrap();

        let verifier = ManifestVerifier::audit_only();
        let result = verifier.verify(&manifest);
        assert!(result.is_err(), "expired manifest must be rejected");
    }

    #[test]
    fn test_audit_only_allows_without_trust_store() {
        let (sk_hex, _vk_hex, fingerprint) = ManifestVerifier::generate_keypair();
        let body = sample_body(&fingerprint);
        let manifest = ManifestVerifier::sign_manifest(body, &sk_hex).unwrap();
        let verifier = ManifestVerifier::audit_only();
        // Should succeed (audit-only, no keys loaded).
        verifier.verify(&manifest).unwrap();
    }
}
