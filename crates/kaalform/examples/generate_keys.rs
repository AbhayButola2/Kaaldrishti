use std::fs;
use std::path::Path;
use kaalform::manifest::ToolManifestBody;
use kaalform::verifier::{ManifestVerifier, TrustStore, TrustedKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk_hex, vk_hex, fingerprint) = ManifestVerifier::generate_keypair();
    println!("Generated Ed25519 Keypair:");
    println!("  Fingerprint:       {}", fingerprint);
    println!("  Public Key (Hex):  {}", vk_hex);
    println!("  Private Key (Hex): {}", sk_hex);

    let store = TrustStore {
        keys: vec![TrustedKey {
            fingerprint: fingerprint.clone(),
            public_key_hex: vk_hex.clone(),
            description: "Default Kaalform Development Key".to_string(),
        }],
    };

    let config_dir = Path::new("crates/kaalform/config");
    fs::create_dir_all(config_dir)?;
    let store_path = config_dir.join("trusted_keys.json");
    fs::write(&store_path, serde_json::to_string_pretty(&store)?)?;
    println!("Wrote trust store to: {}", store_path.display());

    let body = ToolManifestBody {
        manifest_version: "1".to_string(),
        tool_id: "kaaladrishti/graph-query@1.0.0".to_string(),
        tool_name: "Graph Query".to_string(),
        tool_version: "1.0.0".to_string(),
        capabilities: vec!["read".to_string()],
        allowed_principals: vec!["*".to_string()],
        max_privilege_level: 2.0,
        expires_at: "2099-01-01T00:00:00Z".to_string(),
        signing_key_fingerprint: fingerprint,
    };

    let manifest = ManifestVerifier::sign_manifest(body, &sk_hex)?;
    let examples_dir = Path::new("crates/kaalform/examples");
    fs::create_dir_all(examples_dir)?;
    let manifest_path = examples_dir.join("sample_signed_manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    println!("Wrote sample signed manifest to: {}", manifest_path.display());

    Ok(())
}
