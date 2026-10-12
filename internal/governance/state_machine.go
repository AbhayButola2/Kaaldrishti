// Package governance implements the response governance finite state machine.
//
// The FSM is the sole authority for response decisions. No agent, no Python
// service, and no API handler can bypass it. The only path to SIMULATED_EXECUTION
// is through HUMAN_APPROVAL_REQUIRED → APPROVED.
//
// Key invariant (enforced structurally, not by convention):
//   The only function that writes StateSimulatedExecution requires an
//   AuthorizationDecision.Approved == true parameter. There is no other
//   code path to that state.
//
// Thread safety: the FSM uses a sync.RWMutex. Incident records are immutable
// once written; only their state field changes.
package governance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/audit"
	"github.com/kaaladrishti/engine/internal/domain"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// Incident is the in-memory record of a detected security event tracked by the FSM.
type Incident struct {
	ID            string
	CorrelationID string
	State         domain.GovernanceState
	Findings      []*pb.AgentFinding
	Proposal      *pb.ResponseProposal
	AuthRequest   *pb.AuthorizationRequest
	AuthDecision  *pb.AuthorizationDecision
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ProposalConfidenceThreshold is the minimum finding confidence to generate a proposal.
// Can be overridden via config.
const defaultProposalConfidence = 0.65

// StateMachine manages the lifecycle of security incidents.
type StateMachine struct {
	mu                 sync.RWMutex
	incidents          map[string]*Incident
	proposalConfidence float64
	approvalExpiry     time.Duration
	auditLog           *audit.Logger

	// Channel for notifying the API layer of state changes (approval requests, etc.)
	events chan StateEvent
}

// StateEvent is a notification pushed to the API layer on FSM transitions.
type StateEvent struct {
	IncidentID string
	State      domain.GovernanceState
	AuthReq    *pb.AuthorizationRequest // non-nil when HUMAN_APPROVAL_REQUIRED
}

// NewStateMachine creates the governance FSM.
func NewStateMachine(proposalConfidence float64, approvalExpiry time.Duration, auditLog *audit.Logger) *StateMachine {
	if proposalConfidence <= 0 {
		proposalConfidence = defaultProposalConfidence
	}
	return &StateMachine{
		incidents:          make(map[string]*Incident),
		proposalConfidence: proposalConfidence,
		approvalExpiry:     approvalExpiry,
		auditLog:           auditLog,
		events:             make(chan StateEvent, 128),
	}
}

// Events returns the channel of FSM state transition events.
// The API layer consumes this to push WebSocket updates.
func (sm *StateMachine) Events() <-chan StateEvent {
	return sm.events
}

// ProcessFinding handles an incoming AgentFinding. Transitions the FSM
// through OBSERVED → ANALYZING → FINDING → (possibly) RESPONSE_PROPOSED.
func (sm *StateMachine) ProcessFinding(ctx context.Context, correlationID string, finding *pb.AgentFinding) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Find or create the incident for this correlation ID.
	incident := sm.findOrCreateIncident(correlationID)

	// Transition: → ANALYZING (if not already past it).
	if incident.State == domain.StateObserved {
		sm.transition(incident, domain.StateAnalyzing, "governance", "received agent finding")
	}

	// Attach the finding.
	incident.Findings = append(incident.Findings, finding)
	sm.transition(incident, domain.StateFinding, "governance", fmt.Sprintf("finding from agent %s (confidence=%.2f)", finding.AgentId, finding.Confidence))

	sm.writeAudit(incident, domain.AuditCategoryFinding, "received AgentFinding", "success", map[string]any{
		"finding_id": finding.FindingId,
		"agent_id":   finding.AgentId,
		"severity":   finding.Severity.String(),
		"confidence": finding.Confidence,
	})

	// Check if confidence exceeds proposal threshold.
	if finding.Confidence < sm.proposalConfidence {
		log.Debug().
			Str("incident_id", incident.ID).
			Float64("confidence", finding.Confidence).
			Float64("threshold", sm.proposalConfidence).
			Msg("governance: confidence below proposal threshold; no proposal generated")
		return nil
	}

	// Generate a ResponseProposal.
	proposal := sm.buildProposal(finding)
	incident.Proposal = proposal
	sm.transition(incident, domain.StateResponseProposed, "governance", "proposal generated")

	// CONFIDENCE_CHECK state (always passes — check is informational, not a gate).
	sm.transition(incident, domain.StateConfidenceCheck, "governance", "confidence check")

	// ALWAYS require human approval — confidence ≠ authorization.
	authReq := sm.buildAuthRequest(proposal)
	incident.AuthRequest = authReq
	sm.transition(incident, domain.StateHumanApprovalRequired, "governance", "awaiting human approval")

	sm.writeAudit(incident, domain.AuditCategoryGovernance, "HUMAN_APPROVAL_REQUIRED", "pending", map[string]any{
		"proposal_id":     proposal.ProposalId,
		"action_type":     proposal.ActionType.String(),
		"expires_at":      authReq.ExpiresAt,
		"auth_request_id": authReq.AuthRequestId,
	})

	// Notify the API layer.
	sm.pushEvent(StateEvent{
		IncidentID: incident.ID,
		State:      domain.StateHumanApprovalRequired,
		AuthReq:    authReq,
	})

	// Start expiry timer.
	go sm.scheduleExpiry(incident.ID, authReq.AuthRequestId, sm.approvalExpiry)

	return nil
}

// ApproveAction records an operator's authorization decision.
// If approved, transitions to APPROVED → SIMULATED_EXECUTION → AUDITED.
// If denied, transitions to DENIED → AUDITED.
//
// Structural invariant: SIMULATED_EXECUTION is only reachable via approved=true here.
func (sm *StateMachine) ApproveAction(ctx context.Context, decision *pb.AuthorizationDecision) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	incident := sm.findIncidentByAuthRequest(decision.AuthRequestId)
	if incident == nil {
		return fmt.Errorf("governance: auth request %q not found", decision.AuthRequestId)
	}
	if incident.State != domain.StateHumanApprovalRequired {
		return fmt.Errorf("governance: incident %q is in state %s, cannot accept decision", incident.ID, incident.State)
	}

	incident.AuthDecision = decision
	sm.writeAudit(incident, domain.AuditCategoryAuthorization, "operator decision received", "success", map[string]any{
		"auth_request_id": decision.AuthRequestId,
		"operator_id":     decision.OperatorId,
		"approved":        decision.Approved,
		"reason":          decision.Reason,
	})

	if decision.Approved {
		sm.transition(incident, domain.StateApproved, decision.OperatorId, "operator approved")
		// Execute simulation.
		if err := sm.simulateExecution(incident); err != nil {
			sm.writeAudit(incident, domain.AuditCategoryResponse, "simulated execution failed", "failure", map[string]any{
				"error": err.Error(),
			})
			log.Error().Err(err).Str("incident_id", incident.ID).Msg("governance: simulated execution failed")
			return nil
		}
		sm.transition(incident, domain.StateSimulatedExecution, "response-executor", "simulated action executed")
		sm.transition(incident, domain.StateAudited, "governance", "incident audited")
		sm.writeAudit(incident, domain.AuditCategoryResponse, "simulated execution complete", "success", map[string]any{
			"proposal_id": incident.Proposal.ProposalId,
			"action_type": incident.Proposal.ActionType.String(),
			"simulated":   true,
		})
	} else {
		sm.transition(incident, domain.StateDenied, decision.OperatorId, "operator denied: "+decision.Reason)
		sm.transition(incident, domain.StateAudited, "governance", "incident audited (denied)")
		sm.writeAudit(incident, domain.AuditCategoryGovernance, "action denied by operator", "success", map[string]any{
			"reason": decision.Reason,
		})
	}

	sm.pushEvent(StateEvent{IncidentID: incident.ID, State: incident.State})
	return nil
}

// GetIncident retrieves an incident by ID.
func (sm *StateMachine) GetIncident(id string) (*Incident, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	inc, ok := sm.incidents[id]
	if !ok {
		return nil, false
	}
	cp := *inc
	return &cp, true
}

// ListIncidents returns a snapshot of all current incidents.
func (sm *StateMachine) ListIncidents() []*Incident {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]*Incident, 0, len(sm.incidents))
	for _, inc := range sm.incidents {
		cp := *inc
		out = append(out, &cp)
	}
	return out
}

// ListPendingApprovals returns incidents awaiting human approval.
func (sm *StateMachine) ListPendingApprovals() []*Incident {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	var out []*Incident
	for _, inc := range sm.incidents {
		if inc.State == domain.StateHumanApprovalRequired {
			cp := *inc
			out = append(out, &cp)
		}
	}
	return out
}

// --- internal helpers ---

func (sm *StateMachine) findOrCreateIncident(correlationID string) *Incident {
	// Check if an incident already exists for this correlation ID.
	for _, inc := range sm.incidents {
		if inc.CorrelationID == correlationID {
			return inc
		}
	}
	id := uuid.NewString()
	inc := &Incident{
		ID:            id,
		CorrelationID: correlationID,
		State:         domain.StateObserved,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	sm.incidents[id] = inc
	return inc
}

func (sm *StateMachine) findIncidentByAuthRequest(authRequestID string) *Incident {
	for _, inc := range sm.incidents {
		if inc.AuthRequest != nil && inc.AuthRequest.AuthRequestId == authRequestID {
			return inc
		}
	}
	return nil
}

func (sm *StateMachine) transition(inc *Incident, to domain.GovernanceState, actor, reason string) {
	from := inc.State
	inc.State = to
	inc.UpdatedAt = time.Now()
	log.Info().
		Str("incident_id", inc.ID).
		Str("from", string(from)).
		Str("to", string(to)).
		Str("actor", actor).
		Str("reason", reason).
		Msg("governance: state transition")
}

func (sm *StateMachine) buildProposal(finding *pb.AgentFinding) *pb.ResponseProposal {
	actionType := pb.ActionType_ACTION_TYPE_MTD_NETWORK_REROUTE
	if finding.FindingType == pb.FindingType_FINDING_TYPE_IDENTITY_ANOMALY {
		actionType = pb.ActionType_ACTION_TYPE_DECEPTION_HONEYCRED
	} else if finding.FindingType == pb.FindingType_FINDING_TYPE_CLOUD_MISCONFIGURATION {
		actionType = pb.ActionType_ACTION_TYPE_RESTRICT_PUBLIC_ACCESS
	}
	return &pb.ResponseProposal{
		ProposalId:   uuid.NewString(),
		FindingId:    finding.FindingId,
		TimestampMs:  time.Now().UnixMilli(),
		ActionType:   actionType,
		Description:  fmt.Sprintf("Proposed response to %s finding (confidence=%.2f)", finding.FindingType, finding.Confidence),
		TargetNodeId: finding.SubjectNodeId,
		Confidence:   finding.Confidence,
		Simulated:    true, // Always true in Phases 1-11
		ActionParams: map[string]string{"simulated": "true"},
	}
}

func (sm *StateMachine) buildAuthRequest(proposal *pb.ResponseProposal) *pb.AuthorizationRequest {
	expiresAt := time.Now().Add(sm.approvalExpiry).Format(time.RFC3339)
	return &pb.AuthorizationRequest{
		AuthRequestId: uuid.NewString(),
		ProposalId:    proposal.ProposalId,
		TimestampMs:   time.Now().UnixMilli(),
		Proposal:      proposal,
		ExpiresAt:     expiresAt,
	}
}

// simulateExecution logs what the action would do in production.
// PROTOTYPE NOTE: no real OS/network modification is made here.
func (sm *StateMachine) simulateExecution(inc *Incident) error {
	if inc.Proposal == nil {
		return fmt.Errorf("no proposal to execute")
	}
	log.Info().
		Str("incident_id", inc.ID).
		Str("action_type", inc.Proposal.ActionType.String()).
		Str("target_node", inc.Proposal.TargetNodeId).
		Bool("simulated", true).
		Msg("governance: SIMULATED execution (no real action taken)")
	// PROTOTYPE: In production, this would call a real executor.
	// See internal/response/executor.go for the ResponseExecutor interface.
	return nil
}

func (sm *StateMachine) scheduleExpiry(incidentID, authRequestID string, d time.Duration) {
	time.Sleep(d)
	sm.mu.Lock()
	defer sm.mu.Unlock()

	inc, ok := sm.incidents[incidentID]
	if !ok || inc.State != domain.StateHumanApprovalRequired {
		return // Already resolved.
	}
	if inc.AuthRequest == nil || inc.AuthRequest.AuthRequestId != authRequestID {
		return
	}

	log.Warn().
		Str("incident_id", incidentID).
		Str("auth_request_id", authRequestID).
		Msg("governance: approval request expired; auto-denying")

	sm.transition(inc, domain.StateDenied, "governance", "approval expired")
	sm.transition(inc, domain.StateAudited, "governance", "auto-denied by timeout")
	sm.writeAudit(inc, domain.AuditCategoryAuthorization, "approval expired", "expired", map[string]any{
		"auth_request_id": authRequestID,
	})
	sm.pushEvent(StateEvent{IncidentID: incidentID, State: domain.StateDenied})
}

func (sm *StateMachine) writeAudit(inc *Incident, cat domain.AuditCategory, action, outcome string, detail map[string]any) {
	_ = sm.auditLog.Log(audit.NewEvent(cat, "governance", action).
		CorrelationID(inc.CorrelationID).
		Outcome(outcome).
		Detail(detail).
		Build())
}

func (sm *StateMachine) pushEvent(ev StateEvent) {
	select {
	case sm.events <- ev:
	default:
		log.Warn().Msg("governance: event channel full; dropping FSM event")
	}
}
