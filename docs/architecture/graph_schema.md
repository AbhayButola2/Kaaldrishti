# Graph Schema — Kaaladrishti Enterprise Graph

## Overview

The enterprise graph is a heterogeneous, directed, weighted property graph
stored in `InMemoryGraphStore`. It is the single shared state that all agents
read (via scoped subscriptions) and the Go ingestion layer writes.

---

## Node Types

| NodeType | Description | Key Properties |
|---|---|---|
| `PRINCIPAL` | A human user, service account, or machine identity | `principal.username`, `principal.domain`, `principal.type` (user/service/machine) |
| `CREDENTIAL` | An authentication credential (token, cert, password reference) | `credential.type` (token/cert/password), `credential.issuer`, `credential.expiry_ms` |
| `HOST` | A physical or virtual machine | `host.hostname`, `host.ip_addresses`, `host.os_type`, `host.os_version` |
| `PROCESS` | A running OS process | `process.pid`, `process.image_path`, `process.command_line`, `process.parent_pid` |
| `MODULE` | A loaded shared library or kernel module | `module.path`, `module.hash_sha256`, `module.signed` |
| `NETWORK_SOCKET` | An active or recently-closed network connection endpoint | `socket.src_ip`, `socket.src_port`, `socket.dst_ip`, `socket.dst_port`, `socket.protocol` |
| `DATA_ASSET` | A file, database, or other data resource with a sensitivity classification | `asset.path`, `asset.sensitivity` (public/internal/confidential/crown_jewel), `asset.type` |
| `REGISTRY_KEY` | A Windows registry key (extension — see note below) | `registry.key_path`, `registry.value_name`, `registry.host_id` |

> **Note on `REGISTRY_KEY`:** This node type extends the synopsis's explicit list
> (Principal, Credential, Host, Process, Module, NetworkSocket, DataAsset) to
> support Windows-host realism. It is flagged here per the Section 22
> transparency rule and can be removed without breaking any other node type.

---

## Edge Types

| EdgeType | From | To | Description |
|---|---|---|---|
| `ASSUMES_ROLE` | `PRINCIPAL` | `CREDENTIAL` | A principal uses or assumes a credential/role |
| `SPAWNED` | `PROCESS` | `PROCESS` | Parent process spawned child process |
| `CONNECTS_TO` | `PROCESS` | `NETWORK_SOCKET` | Process opened a network connection |
| `LOADS` | `PROCESS` | `MODULE` | Process loaded a shared library |
| `READS` | `PROCESS` | `DATA_ASSET` \| `REGISTRY_KEY` | Process read a data asset or registry key |
| `WRITES` | `PROCESS` | `DATA_ASSET` \| `REGISTRY_KEY` | Process wrote a data asset or registry key |

---

## Node & Edge Metadata

Every node and edge carries these standard metadata fields:

| Field | Type | Description |
|---|---|---|
| `timestamp_ms` | `int64` | Unix epoch milliseconds of last observation |
| `confidence` | `float64` | [0.0, 1.0] — certainty of existence at last observation |
| `recency_decay` | `float64` | Computed decay factor; `InMemoryGraphStore.ApplyDecay()` reduces this over time |
| `provenance` | `string` | Source `event_id` from the causal `TelemetryEvent`, or `"synthetic"` |

---

## GraphStore Interface

```go
type GraphStore interface {
    UpsertNode(ctx context.Context, node *domain.Node) error
    UpsertEdge(ctx context.Context, edge *domain.Edge) error
    GetNode(ctx context.Context, nodeID string) (*domain.Node, error)
    GetNeighborhood(ctx context.Context, nodeID string, depth int) (*domain.Subgraph, error)
    QuerySubgraph(ctx context.Context, filter domain.SubgraphFilter) (*domain.Subgraph, error)
    ApplyDecay(ctx context.Context, decayFactor float64, cutoffMs int64) error
    Snapshot(ctx context.Context) error  // Persists to BoltDB file; NOT a no-op
    Load(ctx context.Context) error      // Restores from BoltDB file on warm restart
}
```

---

## Snapshot Persistence

`Snapshot()` writes the full in-memory graph to a single BoltDB file
(`kaaladrishti_graph.db` by default, configurable via `KAALADRISHTI_GRAPH_DB_PATH`).

**Justification for BoltDB over SQLite:** BoltDB has no CGo dependency, meaning
cross-platform builds (including Windows) require no external C toolchain.

**Warm restart:** On startup, `Load()` restores the last snapshot before the
telemetry ingestion loop starts, ensuring the graph is not empty after a
controlled restart.

---

## Crown Jewel Assets

`DATA_ASSET` nodes with `asset.sensitivity = "crown_jewel"` are the target
entities for blast-radius scoring. The blast-radius computation (Python PPR/RWR)
scores reachability from an anomalous subject node to all crown-jewel assets
in the graph.

---

## Recency Decay Schedule

The Go engine applies recency decay on a configurable timer (default: every 60s).
`recency_decay` starts at `1.0` and is multiplied by `decayFactor` per interval.
Nodes/edges with `recency_decay < 0.01` are candidates for eviction.
The decay rate is configurable via `KAALADRISHTI_DECAY_FACTOR` (default: `0.95`).
