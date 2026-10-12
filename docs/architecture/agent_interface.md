# Agent Interface Contract — Kaaladrishti

## Overview

Every agent in Kaaladrishti is a Go type that implements the `Agent` interface
defined in `internal/dispatcher/agent.go`. Agents are passive analysis components:
they receive scoped graph information, analyze it, and return findings. They
**never** directly control any platform action, emit `ResponseProposal` messages,
or call the Python ML service directly (only the Go engine does that, on the
agent's behalf when the agent requests it via its finding metadata).

---

## Agent Interface (Go)

```go
// Agent is the interface every Kaaladrishti analysis agent must implement.
// Agents are registered with the AgentDispatcher at startup and receive only
// graph deltas scoped to their declared subscription.
type Agent interface {
    // Identity returns the agent's static metadata and subscription scope.
    // Called once at registration; the returned AgentSubscription is immutable.
    Identity() *proto.AgentSubscription

    // Analyze processes a scope-filtered GraphDelta and returns zero or more
    // findings. The context carries a deadline; agents must respect it.
    // Returning an error marks the agent unhealthy for this cycle; other agents
    // and the correlation layer are unaffected.
    Analyze(ctx context.Context, req *proto.AgentRequest) ([]*proto.AgentFinding, error)

    // HealthCheck returns nil if the agent is operational.
    HealthCheck(ctx context.Context) error
}
```

---

## Dispatcher Contract

The `AgentDispatcher` enforces the following invariants:

1. **Scope filtering** — before delivering a `GraphDelta` to an agent, the
   dispatcher removes all nodes and edges whose types are not in the agent's
   `AgentSubscription.subscribed_node_types` / `subscribed_edge_types`. This
   filtering is performed by the dispatcher, never by the agent itself.

2. **Isolation** — each agent's `Analyze()` call runs in a bounded goroutine.
   A `recover()` wrapper catches panics; the error is logged and the agent is
   marked unhealthy for that cycle without affecting other agents.

3. **Timeout** — every `Analyze()` call receives a `context.Context` with a
   deadline (default: `KAALADRISHTI_AGENT_TIMEOUT`, default 10s). If the agent
   exceeds this deadline, the call is cancelled and the dispatcher proceeds.

4. **No direct ML calls** — agents interact with Python ML indirectly. An agent
   that needs a GNN score includes the relevant subgraph in its `AgentFinding`
   metadata, and the Go orchestration layer calls Python on its behalf.
   (Implementation note: in Phase 6/7, the `BlastRadiusAgent` calls Python via
   the Go `ml.Client` injected at construction time — this is Go→Python, never
   agent→Python directly.)

---

## Currently Registered Agents

### 1. BlastRadiusAgent (`internal/agents/blast_radius_agent.go`)

| Property | Value |
|---|---|
| `agent_id` | `blast-radius-v1` |
| `agent_name` | `Blast Radius & Next-Attack Prediction Agent` |
| `agent_version` | `1.0.0` |
| `subscribed_node_types` | All node types (broad subscription for anomaly detection) |
| `subscribed_edge_types` | All edge types |

**Behavior:** Calls the Python ML service (via Go `ml.Client`) to get:
1. GNN-based anomaly/risk score for the subgraph
2. Blast-radius PPR/RWR score relative to crown-jewel assets
3. Next-attack technique forecast

Returns a `FindingType = FINDING_TYPE_BLAST_RADIUS` finding with embedded
`BlastRadius` and `NextAttackForecastResponse`.

### 2. IdentityAgent (`internal/agents/identity_agent.go`)

| Property | Value |
|---|---|
| `agent_id` | `identity-insider-v1` |
| `agent_name` | `Identity / Insider Threat Agent` |
| `agent_version` | `1.0.0` |
| `subscribed_node_types` | `PRINCIPAL`, `CREDENTIAL` |
| `subscribed_edge_types` | `ASSUMES_ROLE` |

**Behavior:** Rule-based statistical baseline (no GNN dependency):
- Detects unusual `ASSUMES_ROLE` frequency for a principal
- Detects credential use outside normal hours or from unexpected hosts
- Detects repeated `IDENTITY_ACTION_AUTH_FAILURE` sequences

Returns a `FindingType = FINDING_TYPE_IDENTITY_ANOMALY` finding.

**Scope enforcement test:** A contract test in `tests/contract/` asserts that
the `IdentityAgent` never receives a `GraphDelta` containing `NETWORK_SOCKET`
or `MODULE` node types.

---

## Adding New Agents

To add a new agent:

1. Create `internal/agents/<name>_agent.go` implementing the `Agent` interface.
2. Register it in `cmd/engine/main.go` via `dispatcher.Register(agent)`.
3. No changes to existing agent code are required.

The dispatcher framework uses a slice of registered agents; adding to the slice
is the only required change to existing code.

---

## Agent Finding Schema

See `proto/kaaladrishti/v1/platform.proto` → `AgentFinding` message for the
complete typed schema. Key invariants:

- `confidence` is `[0.0, 1.0]`; the governance FSM uses this for proposal gating
- `blast_radius`, `next_attack`, and `intent_lineage` fields are optional; set
  only when the agent has computed the relevant analysis
- `metadata` map is advisory only; its contents are never directly executed
- `subject_node_id` must reference a node currently in the graph
