# Response State Machine — Kaaladrishti Governance

## Overview

The governance FSM is implemented entirely in Go (`internal/governance/state_machine.go`).
It is the sole authority for response decisions. Python ML returns analysis;
it never generates `ResponseProposal` messages or transitions FSM state.
Agents return `AgentFinding` messages; they never control platform actions.

**Key invariant:** Confidence is never authorization. No transition path exists
from any state to `SIMULATED_EXECUTION` that bypasses `HUMAN_APPROVAL_REQUIRED`.
This is enforced structurally (the only function that writes `SIMULATED_EXECUTION`
requires an `AuthorizationDecision.approved = true` parameter), not by convention.

---

## State Diagram

```
                         [TelemetryEvent received]
                                   |
                                   v
                              OBSERVED
                                   |
                         [Agent dispatch triggered]
                                   |
                                   v
                              ANALYZING
                                   |
                         [AgentFinding returned]
                                   |
                                   v
                               FINDING
                                   |
                    [Confidence > proposal_threshold]
                                   |
                                   v
                          RESPONSE_PROPOSED
                                   |
                         [Severity / action check]
                                   |
                                   v
                          CONFIDENCE_CHECK
                                   |
                    [ALWAYS -- regardless of confidence]
                                   |
                                   v
                    HUMAN_APPROVAL_REQUIRED  <---+
                           /           \         |
               [approved]              [denied]  | [expired/re-review]
                  |                       |      |
                  v                       v      |
              APPROVED               DENIED -----+
                  |
     [Simulated execution invoked]
                  |
                  v
          SIMULATED_EXECUTION
                  |
       [Execution outcome recorded]
                  |
                  v
              AUDITED
                  |
       (terminal state for this incident cycle)
```

---

## State Descriptions

| State | Description | Who drives it |
|---|---|---|
| `OBSERVED` | A `TelemetryEvent` has been ingested and graph-mutated | Go ingestion layer |
| `ANALYZING` | One or more agents have been dispatched for this delta | Go dispatcher |
| `FINDING` | An `AgentFinding` has been received and recorded | Agent (via dispatcher) |
| `RESPONSE_PROPOSED` | Governance generated a `ResponseProposal` above the confidence threshold | Go governance |
| `CONFIDENCE_CHECK` | FSM verifying the action type and confidence metadata | Go governance |
| `HUMAN_APPROVAL_REQUIRED` | `AuthorizationRequest` pushed to dashboard; operator must act | Go API/WebSocket |
| `APPROVED` | Operator approved via `AuthorizationDecision.approved = true` | Human operator (via API) |
| `DENIED` | Operator denied; no action taken; incident stays in AUDITED | Human operator (via API) |
| `SIMULATED_EXECUTION` | Reversible simulated action executed (MTD/deception) | Go response executor |
| `AUDITED` | Full causal chain written to append-only audit log | Go audit logger |

---

## Confidence Threshold Configuration

| Parameter | Environment Variable | Default |
|---|---|---|
| Minimum confidence to generate `ResponseProposal` | `KAALADRISHTI_PROPOSAL_CONFIDENCE` | `0.65` |
| Minimum confidence to present in dashboard (display filter) | `KAALADRISHTI_DISPLAY_CONFIDENCE` | `0.40` |

Neither threshold bypasses `HUMAN_APPROVAL_REQUIRED`. They control whether
a proposal is generated at all.

---

## Approval Expiry

`AuthorizationRequest` carries an `expires_at` ISO-8601 timestamp (default: 30 minutes).
If no operator decision is received before expiry:
- The FSM transitions from `HUMAN_APPROVAL_REQUIRED` → `DENIED` automatically.
- An `AuditEvent` with `outcome = "expired"` is written.
- The incident is logged as denied-by-timeout, not silently dropped.

---

## Incident Correlation

The Go orchestration layer (`internal/orchestration/correlator.go`) watches for
`AgentFinding` messages from multiple agents that reference the same or adjacent
graph entities within a configurable time window (default: 5 minutes).

When two or more findings are correlated, they are merged into a single
`CorrelatedIncident` record. The FSM then operates on the correlated incident,
with one `AuthorizationRequest` presented to the operator rather than multiple.

---

## Error / Failure Handling in the FSM

| Failure | FSM behavior |
|---|---|
| Agent returns error or panics | FSM stays in `ANALYZING`; agent marked unhealthy; correlation continues with remaining findings |
| Python ML unavailable | FSM proceeds with lower-confidence rule-based finding; never blocks |
| Simulated execution fails | FSM does NOT transition to `AUDITED`; operator notified; stays in `SIMULATED_EXECUTION` failed state |
| Operator response timeout | Auto-deny transition; `AuditEvent` written with `"expired"` outcome |

---

## Audit Trail

Every FSM state transition writes an `AuditEvent` with:
- `correlation_id`: threads the entire incident causal chain
- `actor`: the component or operator that triggered the transition
- `action`: the state transition (e.g., `"FINDING->RESPONSE_PROPOSED"`)
- `outcome`: `"success"`, `"failure"`, `"rejected"`, `"expired"`, `"pending"`
- `detail`: JSON blob with relevant identifiers (finding_id, proposal_id, etc.)
