# Deferred Work — Kaaladrishti Long-Term Architecture

## Purpose

This document catalogs capabilities that were **intentionally excluded** from
the Phases 1–11 prototype per Section 4 of the master implementation prompt.
Each item includes the extension point that was designed to accept it without
breaking existing code.

---

## Explicitly Excluded — Do Not Implement in Phases 1–11

### Pillar 4: Cryptographic Tool-Manifest Signing/Verification

- **What it is:** Cryptographic signing and verification of MCP tool manifests
  to ensure agentic workflows cannot invoke tools that are not cryptographically
  attested as approved.
- **Why excluded:** Documented future work per supplementary note; out of scope
  for this prototype.
- **Extension point:** `AgentRequest.tool_manifest_ref` field is reserved in
  the protobuf schema but never read or written in Phases 1–11. When Pillar 4
  is implemented, this field carries the reference to the signed tool manifest.

### Pillar 5: Context-to-Action Provenance Firewall

- **What it is:** A cross-session, external authorization-receipt system
  governing MCP tool calls, with information-flow labels, memory rollback,
  and authorization receipts.
- **Why excluded:** Pillar 5 is distinct from Intent Lineage Tracking (which
  IS in scope). Pillar 5 requires `ContextArtifact`, `MemoryEntry`, `AgentPlan`,
  and `AuthorizationReceipt` node types — none of which exist in this prototype's
  graph schema.
- **Extension point:** The `GraphStore` interface accepts new node types via
  the `NodeType` enum; adding Pillar 5 node types is additive and backward-compatible.

### eBPF / OS-Level Telemetry Sensor

- **What it is:** A kernel-space eBPF program collecting real OS events (syscalls,
  network packets, process lifecycle) rather than synthetic events.
- **Why excluded:** Requires kernel headers, privileged build environment, and
  unsafe Rust code (justified in its own isolated crate).
- **Extension point:** `crates/telemetry-kernel/src/source/ebpf_stub.rs` is the
  feature-gated stub. Enable with `cargo build --features ebpf`. The stub module
  compiles to nothing in the default build.

### Durable / Distributed Graph Store

- **What it is:** A distributed graph database (e.g., TigerGraph, Neo4j cluster)
  behind the `GraphStore` interface for multi-node, HA deployments.
- **Why excluded:** `InMemoryGraphStore` + BoltDB snapshot is sufficient for
  prototype scale.
- **Extension point:** The `GraphStore` interface in `internal/graph/store.go`
  is the only boundary. A new implementation (e.g., `Neo4jGraphStore`) can be
  swapped in by changing `cmd/engine/main.go`; no other code changes required.

### Real SIEM / EDR Ingestion

- **What it is:** Consuming real telemetry from Splunk, CrowdStrike, Microsoft
  Defender, or other commercial EDR/SIEM products.
- **Why excluded:** Requires vendor API credentials, licensing, and integration
  testing with external systems.
- **Extension point:** Implement a new `TelemetrySource` in a separate Rust crate
  (e.g., `crates/siem-source/`) that produces the same `TelemetryEvent` protobuf
  messages over UDS. The Go ingestion layer requires no changes.

### Real MTD / Deception Execution

- **What it is:** Actual kernel-level or production-OS Moving Target Defense
  (network re-routing, credential rotation) and live deception asset deployment.
- **Why excluded:** Irreversible OS modifications are unsafe in a prototype
  environment; academic prototype scope requires simulated execution only.
- **Extension point:** `internal/response/executor.go` has a `SimulatedExecutor`
  that logs what it would do. A `RealExecutor` implementing the same `ResponseExecutor`
  interface can be swapped in for production deployment.

### mTLS between Go Engine and Python ML Service

- **What it is:** Mutual TLS authentication on the gRPC channel between Go and Python.
- **Why excluded:** Certificate management infrastructure is out of scope for
  prototype. The gRPC channel is currently unencrypted on localhost.
- **Extension point:** gRPC channel options in `internal/ml/client.go` accept
  `grpc.WithTransportCredentials(credentials.NewTLS(...))` as a drop-in replacement
  for the current `grpc.WithTransportCredentials(insecure.NewCredentials())`.

### Full OpenTelemetry / Prometheus Instrumentation

- **What it is:** Distributed tracing (OTLP), Prometheus metrics scraping,
  and Grafana dashboards.
- **Why excluded:** Full observability stack adds infrastructure overhead without
  changing prototype functionality.
- **Extension point:** Structured JSON logs with `correlation_id` and `request_id`
  on every log line are the minimal scaffolding. Adding
  `go.opentelemetry.io/otel` spans is additive at the call sites already instrumented
  with `context.Context`.

### Multi-Region / HA Deployment

- **What it is:** Kubernetes-orchestrated multi-replica deployment with a
  distributed event broker (Kafka), distributed graph store, and global load balancing.
- **Why excluded:** UDS+gRPC at prototype scale does not need a broker, per the
  dependency strategy (Section 20 of the implementation plan).
- **Extension point:** The UDS transport in Rust and Go can be replaced by a
  Kafka producer/consumer behind the same trait/interface boundaries with no
  changes to the ingestion, graph, or agent layers.

---

## Summary Table

| Deferred Capability | Extension Point | Breaking Change Required |
|---|---|---|
| Pillar 4 (tool-manifest signing) | `AgentRequest.tool_manifest_ref` | No — additive |
| Pillar 5 (provenance firewall) | `NodeType` enum, `GraphStore` interface | No — additive |
| eBPF telemetry | `TelemetrySource` trait, `ebpf_stub.rs` | No — feature-gated |
| Distributed graph store | `GraphStore` interface | No — swap implementation |
| Real SIEM/EDR ingestion | New Rust crate implementing `TelemetrySource` | No — additive |
| Real MTD/deception execution | `ResponseExecutor` interface | No — swap implementation |
| mTLS (Go↔Python gRPC) | gRPC channel options in `ml/client.go` | No — config change |
| Full observability (OTel/Prometheus) | `context.Context` call sites already in place | No — additive |
| Multi-region HA | Transport layer behind trait/interface | Requires infra changes |
