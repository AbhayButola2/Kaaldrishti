# Kaalform — Agent Execution Firewall

**Pillar 4 (Cryptographic Tool-Manifest Signing) + Pillar 5 (Context-to-Action Provenance Firewall)**

Companion to [Kaaladrishti](../../README.md) — the SOC control plane.

---

## What Kaalform Does

```
AI Agent / LLM Workflow
     │
     │  POST /mcp/v1/call  (JSON)
     ▼
┌─────────────────────────────────────────────┐
│            KAALFORM MCP GATEWAY             │
│  ┌──────────────────────────────────────┐   │
│  │ PILLAR 4: ManifestVerifier           │   │
│  │  • Ed25519 signature check           │   │
│  │  • Trust store key lookup            │   │
│  │  • Expiry validation                 │   │
│  └──────────────────────────────────────┘   │
│  ┌──────────────────────────────────────┐   │
│  │ PILLAR 5: ProvenanceFirewall         │   │
│  │  • Bag-of-Words cosine drift score   │   │
│  │  • Session-scoped context tracking   │   │
│  │  • AuthorizationReceipt issued       │   │
│  └──────────────────────────────────────┘   │
│  ┌──────────────────────────────────────┐   │
│  │ ProvenanceEmitter                    │   │
│  │  • GraphDelta → Kaaladrishti TCP     │   │
│  │  • Adds provenance chain to graph    │   │
│  └──────────────────────────────────────┘   │
└──────┬───────────────────────┬──────────────┘
       │ DENIED (403)          │ ALLOWED
       ▼                       ▼
  Returns to agent        Upstream MCP Server
```

---

## Quick Start

### Prerequisites
- Rust 1.75+  
- Kaaladrishti Go engine running on `127.0.0.1:9090`

### 1. Set environment variables

```powershell
$env:KAALFORM_UPSTREAM_MCP_URL = "http://localhost:9000"   # Your MCP server
$env:KAALFORM_KAALADRISHTI_ADDR = "127.0.0.1:9090"
$env:KAALFORM_DRIFT_THRESHOLD = "0.45"
$env:KAALFORM_REQUIRE_MANIFEST = "false"    # true = enforce Pillar 4
```

### 2. Run

```powershell
cargo run --bin kaalform
# Gateway on http://0.0.0.0:7070
```

### 3. Declare scope (Pillar 5)

```bash
curl -X POST http://localhost:7070/mcp/v1/scope \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_id": "wf-1",
    "declared_scope": "Read-only access to customer database using sql_query tool"
  }'
```

### 4. Make a gated tool call

```bash
curl -X POST http://localhost:7070/mcp/v1/call \
  -H "Content-Type: application/json" \
  -H "X-Kaalform-Workflow-Id: wf-1" \
  -H "X-Kaalform-Principal-Id: alice@corp.internal" \
  -d '{"tool_id":"sql_query","arguments":{"query":"SELECT * FROM customers LIMIT 10"}}'
```

---

## Pillar 4: Tool-Manifest Signing

### Generate a keypair

```bash
curl -X POST http://localhost:7070/keys/generate
# Returns: signing_key_hex, verifying_key_hex, fingerprint
```

### Sign a tool manifest

```bash
curl -X POST http://localhost:7070/manifest/sign \
  -H "Content-Type: application/json" \
  -d '{
    "signing_key_hex": "<your-sk-hex>",
    "body": {
      "manifest_version": "1",
      "tool_id": "myorg/sql_query@1.0.0",
      "tool_name": "SQL Query",
      "tool_version": "1.0.0",
      "capabilities": ["read"],
      "allowed_principals": ["*"],
      "max_privilege_level": 2.0,
      "expires_at": "2027-01-01T00:00:00Z",
      "signing_key_fingerprint": "<your-fingerprint>"
    }
  }'
```

### Add the verifying key to the trust store

Create `trust_store.json`:

```json
{
  "keys": [
    {
      "fingerprint": "<your-fingerprint>",
      "public_key_hex": "<your-vk-hex>",
      "description": "My tool attestation key"
    }
  ]
}
```

```powershell
$env:KAALFORM_TRUSTED_KEYS_PATH = "trust_store.json"
$env:KAALFORM_REQUIRE_MANIFEST = "true"
```

### Send a signed tool call

```bash
curl -X POST http://localhost:7070/mcp/v1/call \
  -H "Content-Type: application/json" \
  -H "X-Kaalform-Workflow-Id: wf-1" \
  -H "X-Kaalform-Principal-Id: alice@corp.internal" \
  -H "X-Kaalform-Manifest: <manifest-json>" \
  -d '{"tool_id":"sql_query","arguments":{"query":"SELECT 1"}}'
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health and active configuration |
| `POST` | `/mcp/v1/scope` | Declare workflow scope for Pillar 5 |
| `POST` | `/mcp/v1/call` | Gate and proxy an MCP tool call |
| `GET` | `/audit/{workflow_id}` | Retrieve session action log |
| `POST` | `/keys/generate` | Generate Ed25519 keypair |
| `POST` | `/manifest/sign` | Sign a manifest body |
| `POST` | `/manifest/verify` | Verify a manifest offline |

### Required Headers for `/mcp/v1/call`

| Header | Required | Description |
|--------|----------|-------------|
| `X-Kaalform-Workflow-Id` | Yes | Agent session identifier |
| `X-Kaalform-Principal-Id` | Yes | Agent/user identity |
| `X-Kaalform-Manifest` | Conditional | JSON manifest (required if `KAALFORM_REQUIRE_MANIFEST=true`) |

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `KAALFORM_LISTEN_ADDR` | `0.0.0.0:7070` | Gateway listen address |
| `KAALFORM_UPSTREAM_MCP_URL` | *(required)* | Upstream MCP server URL |
| `KAALFORM_KAALADRISHTI_ADDR` | `127.0.0.1:9090` | Kaaladrishti ingestion TCP address |
| `KAALFORM_DRIFT_THRESHOLD` | `0.45` | Max cosine drift before Pillar 5 denies |
| `KAALFORM_REQUIRE_MANIFEST` | `true` | Pillar 4 enforcement mode |
| `KAALFORM_TRUSTED_KEYS_PATH` | *(optional)* | JSON trust store path |
| `KAALFORM_SIGNING_KEY_PATH` | *(optional)* | Ed25519 private key (hex) |
| `KAALFORM_SESSION_TTL_SECS` | `3600` | Session expiry (seconds) |

---

## Architecture

### Modules

| Module | Role |
|--------|------|
| `config` | Environment-variable configuration |
| `manifest` | `ToolManifest` data model, canonical digest |
| `verifier` | Ed25519 signature verification, trust store (Pillar 4) |
| `provenance` | Cosine drift scoring, session tracking, authorization receipts (Pillar 5) |
| `emitter` | GraphDelta encoder, TCP stream to Kaaladrishti |
| `gateway` | Axum HTTP server, all endpoint handlers |

### Provenance Graph emitted to Kaaladrishti

Every tool call creates the following subgraph in Kaaladrishti's enterprise graph:

```
AgentPlan (NODE_TYPE_AGENT_PLAN)
  ├── PERFORMS → Action (NODE_TYPE_ACTION)
  │     └── AUTHORIZED_BY → AuthorizationReceipt (NODE_TYPE_AUTHORIZATION)
  ├── HAS_PLAN → ContextArtifact (NODE_TYPE_CONTEXT_ARTIFACT) [manifest]
  └── (Action) INVOKES → ToolCall (NODE_TYPE_TOOL_CALL)
```

This makes every agent tool invocation visible in the Kaaladrishti SOC dashboard.

---

## Running Tests

```powershell
cargo test -p kaalform
```

Tests cover:
- **Pillar 4**: sign/verify roundtrip, tampered manifest rejection, expiry enforcement, untrusted key rejection, audit-only mode.
- **Pillar 5**: in-scope approval, out-of-scope denial, no-scope error, action log population, cosine similarity edge cases.
- **Manifest model**: canonical digest determinism, structural validation, JSON roundtrip.

---

## Deferred (Future Work)

- Replace bag-of-words drift with neural sentence embeddings (via Kaaladrishti Python ML service).
- Implement memory rollback (undo agentic side-effects on denial).
- mTLS between Kaalform and Kaaladrishti.
- KMS/HSM integration for trust store key management.
- Persistent session storage (currently in-memory, lost on restart).

*Academic prototype — University of Petroleum & Energy Studies. Not for production deployment.*
