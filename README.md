# Kaaladrishti — काल-दृष्टि

**"Vision Across Time" — Multi-Agent Predictive Cybersecurity Defense Platform**

*University of Petroleum & Energy Studies, School of Computer Science*

---

## Overview

Kaaladrishti is a multi-agent, predictive cybersecurity defense platform that
replaces siloed, reactive EDR/XDR tooling with:

- A **live, heterogeneous enterprise graph** (identity, endpoint, network, cloud)
  that all agents read from a scoped subscription
- A **probabilistic blast-radius engine** (GNN + link-prediction-weighted
  Personalized PageRank / Random-Walk-with-Restart) estimating attacker reach
  to crown-jewel assets
- A **next-attack-technique forecaster** (Transformer/LSTM sequence model on
  MITRE ATT&CK chains)
- **Intent Lineage Tracking** — cosine-distance scope-drift scoring detecting
  when an autonomous workflow has been hijacked
- **Simulated, reversible Moving Target Defense** and **cyber deception**
  (decoy credentials / shares), confidence-gated via a deterministic FSM
- A **drift-safe retraining pipeline** (CUSUM/ADWIN) preventing baseline poisoning
- A **live SOC dashboard** with human-approval interface for every high-impact action

---

## Architecture

```
┌────────────────────────────┐
│   Synthetic Telemetry Gen  │
└──────────────┬─────────────┘
               │
               ▼
┌────────────────────────────┐
│  Rust: telemetry-kernel    │  #![forbid(unsafe_code)]
│  TelemetrySource trait     │  SyntheticTelemetrySource
│  Protobuf + UDS transport  │
└──────────────┬─────────────┘
               │  protobuf over Unix Domain Socket
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Go: engine (core security control plane)                           │
│  ingestion → validation → GraphStore (InMemory + BoltDB snapshot)  │
│       → AgentDispatcher (scoped subscription) → orchestration       │
│       → governance/response FSM → audit                             │
│  REST + WebSocket API → dashboard (embedded static assets)          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  gRPC
                               ▼
              ┌────────────────────────────┐
              │ Python: ml-analytics       │
              │ GNN embedding / risk score │
              │ blast-radius (PPR/RWR)     │
              │ next-attack forecast       │
              │ intent-lineage drift score │
              │ CUSUM/ADWIN drift detect   │
              └────────────────────────────┘
```

**Go is the single authoritative decision-maker.** Python returns analysis only.
Rust never speaks to Python directly.

---

## Quick Start

### Prerequisites

- **Rust** 1.75+ (`rustup install stable`)
- **Go** 1.22+ (`go.dev/dl`)
- **Python** 3.11+ with `pip`
- **protoc** 25+ with `protoc-gen-go`, `protoc-gen-go-grpc`, `grpc_tools_python`
- **Windows:** UDS requires Windows 10 1803+ (build 17134)

### 1. Generate protobuf bindings

```powershell
.\scripts\gen_proto.ps1
```

### 2. Build and test Rust telemetry kernel

```powershell
cd crates\telemetry-kernel
cargo build
cargo test
```

### 3. Build and test Go engine

```powershell
go build .\...
go test -race .\...
```

### 4. Set up Python ML service

```powershell
cd services\ml-analytics
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest tests\ -v
```

### 5. Run everything together

```powershell
.\scripts\run_all.ps1
```

Open `http://localhost:8080` for the SOC dashboard.

---

## Configuration

All configuration via environment variables (no hardcoded credentials):

| Variable | Default | Description |
|---|---|---|
| `KAALADRISHTI_UDS_PATH` | `/tmp/kaaladrishti.sock` | Unix Domain Socket path |
| `KAALADRISHTI_ML_GRPC_ADDR` | `localhost:50051` | Python ML service gRPC address |
| `KAALADRISHTI_GRAPH_DB_PATH` | `kaaladrishti_graph.db` | BoltDB snapshot file |
| `KAALADRISHTI_API_ADDR` | `:8080` | Go HTTP/WebSocket API address |
| `KAALADRISHTI_AUDIT_LOG_PATH` | `kaaladrishti_audit.jsonl` | Append-only audit log |
| `KAALADRISHTI_PROPOSAL_CONFIDENCE` | `0.65` | Min confidence to generate proposal |
| `KAALADRISHTI_AGENT_TIMEOUT` | `10s` | Per-agent analysis timeout |
| `KAALADRISHTI_DECAY_FACTOR` | `0.95` | Graph recency decay factor per interval |
| `KAALADRISHTI_DECAY_INTERVAL` | `60s` | Graph decay application interval |

---

## Repository Structure

```
kaaladrishti/
├── proto/kaaladrishti/v1/platform.proto   # Canonical protobuf schema
├── crates/telemetry-kernel/               # Rust telemetry source
├── cmd/engine/                            # Go engine entrypoint
├── internal/                             # Go engine internals
│   ├── domain/     ipc/     ingestion/
│   ├── graph/      dispatcher/  agents/
│   ├── orchestration/ governance/ response/
│   ├── audit/      api/     config/   ml/
├── services/ml-analytics/                 # Python ML service
│   ├── app/                              # FastAPI + gRPC inference
│   └── training/                         # Offline dataset loaders
├── web/                                  # Dashboard (served by Go)
├── generated/{rust,go,python}/           # Protobuf codegen output
├── tests/{unit,contract,integration}/
├── docs/architecture/
└── scripts/
```

---

## Development Phases

| Phase | Status | Description |
|---|---|---|
| 1 | ✅ | Architecture + protobuf contract |
| 2 | ✅ | Repository bootstrap |
| 3 | ✅ | Protobuf codegen + contract test |
| 4 | ✅ | Rust telemetry kernel |
| 5 | ✅ | Go ingestion + graph |
| 6 | ✅ | Go dispatcher + two agents |
| 7 | ✅ | Python ML service |
| 8 | ✅ | Governance + response FSM + audit |
| 9 | ✅ | API/dashboard + orchestration |
| 10 | ✅ | End-to-end integration test |
| 11 | ✅ | Testing hardening + docs |

---

## End-to-End Acceptance Criteria

See `docs/architecture/` for full details. The prototype is complete when:

1. Synthetic telemetry flows Rust → UDS → Go without manual intervention
2. Graph updates incrementally; snapshot file persists and reloads on restart
3. Identity agent never receives `NetworkSocket`/`Module` events (tested)
4. Blast-radius agent finding includes score + next-attack from Python service
5. High-confidence finding reaches `HUMAN_APPROVAL_REQUIRED` in dashboard
6. Approval → `SIMULATED_EXECUTION` → `AUDITED` with full causal chain in log
7. Killing Python service does not crash/hang Go core (failure-isolation test)
8. Two-agent findings against related entities merge into one correlated incident
9. `go test -race ./...`, `cargo test`, `pytest` all pass

---

## License

Academic prototype — University of Petroleum & Energy Studies.
Not for production deployment. See `docs/architecture/deferred_work.md`.
