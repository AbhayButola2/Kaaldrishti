package governance_test

import (
	"context"
	"testing"
	"time"

	"github.com/kaaladrishti/engine/internal/audit"
	"github.com/kaaladrishti/engine/internal/domain"
	"github.com/kaaladrishti/engine/internal/governance"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

func newTestFSM(t *testing.T) (*governance.StateMachine, string) {
	t.Helper()
	dir := t.TempDir()
	auditLog, err := audit.NewLogger(dir + "/audit_test.jsonl")
	if err != nil {
		t.Fatalf("audit.NewLogger: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })
	fsm := governance.NewStateMachine(0.60, 30*time.Minute, auditLog)
	return fsm, dir
}

// TestFSM_BelowThreshold_NoProposal verifies that a low-confidence finding
// does NOT generate an approval request.
func TestFSM_BelowThreshold_NoProposal(t *testing.T) {
	fsm, _ := newTestFSM(t)
	ctx := context.Background()

	finding := &pb.AgentFinding{
		FindingId:     "f-001",
		AgentId:       "test-agent",
		TimestampMs:   time.Now().UnixMilli(),
		FindingType:   pb.FindingType_FINDING_TYPE_ANOMALY,
		Severity:      pb.Severity_SEVERITY_LOW,
		Confidence:    0.30, // Below 0.60 threshold
		Description:   "Low confidence test finding",
		SubjectNodeId: "node-001",
	}

	if err := fsm.ProcessFinding(ctx, "corr-001", finding); err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}

	pending := fsm.ListPendingApprovals()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending approvals for low-confidence finding, got %d", len(pending))
	}
}

// TestFSM_AboveThreshold_GeneratesApprovalRequest verifies that a high-confidence
// finding always requires human approval (structural invariant).
func TestFSM_AboveThreshold_GeneratesApprovalRequest(t *testing.T) {
	fsm, _ := newTestFSM(t)
	ctx := context.Background()

	finding := &pb.AgentFinding{
		FindingId:     "f-002",
		AgentId:       "blast-radius-v1",
		TimestampMs:   time.Now().UnixMilli(),
		FindingType:   pb.FindingType_FINDING_TYPE_BLAST_RADIUS,
		Severity:      pb.Severity_SEVERITY_HIGH,
		Confidence:    0.85,
		Description:   "High anomaly score on crown-jewel access",
		SubjectNodeId: "node-crown-001",
	}

	if err := fsm.ProcessFinding(ctx, "corr-002", finding); err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}

	pending := fsm.ListPendingApprovals()
	if len(pending) == 0 {
		t.Fatal("expected a pending approval request for high-confidence finding")
	}
	inc := pending[0]
	if inc.State != domain.StateHumanApprovalRequired {
		t.Errorf("expected state HUMAN_APPROVAL_REQUIRED, got %s", inc.State)
	}
	if inc.AuthRequest == nil {
		t.Fatal("auth_request must not be nil")
	}
}

// TestFSM_ApproveAction_Transitions correctly tests the APPROVE path through the FSM.
func TestFSM_ApproveAction_Transitions(t *testing.T) {
	fsm, _ := newTestFSM(t)
	ctx := context.Background()

	// Create an incident that needs approval.
	finding := &pb.AgentFinding{
		FindingId:     "f-003",
		AgentId:       "blast-radius-v1",
		TimestampMs:   time.Now().UnixMilli(),
		FindingType:   pb.FindingType_FINDING_TYPE_BLAST_RADIUS,
		Severity:      pb.Severity_SEVERITY_CRITICAL,
		Confidence:    0.92,
		Description:   "Critical crown-jewel blast radius detected",
		SubjectNodeId: "proc-malicious-001",
	}
	if err := fsm.ProcessFinding(ctx, "corr-003", finding); err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}

	pending := fsm.ListPendingApprovals()
	if len(pending) == 0 {
		t.Fatal("expected pending approval")
	}

	authRequestID := pending[0].AuthRequest.AuthRequestId

	// Approve.
	decision := &pb.AuthorizationDecision{
		AuthRequestId: authRequestID,
		OperatorId:    "soc-analyst-test",
		TimestampMs:   time.Now().UnixMilli(),
		Approved:      true,
		Reason:        "Confirmed anomalous activity",
	}
	if err := fsm.ApproveAction(ctx, decision); err != nil {
		t.Fatalf("ApproveAction: %v", err)
	}

	// Find the incident and verify final state.
	incidents := fsm.ListIncidents()
	var found *governance.Incident
	for _, inc := range incidents {
		if inc.AuthRequest != nil && inc.AuthRequest.AuthRequestId == authRequestID {
			found = inc
			break
		}
	}
	if found == nil {
		t.Fatal("could not find incident after approval")
	}
	if found.State != domain.StateAudited {
		t.Errorf("expected state AUDITED after approval, got %s", found.State)
	}
}

// TestFSM_DenyAction tests the DENY path — incident must end in AUDITED.
func TestFSM_DenyAction(t *testing.T) {
	fsm, _ := newTestFSM(t)
	ctx := context.Background()

	finding := &pb.AgentFinding{
		FindingId:     "f-004",
		AgentId:       "identity-insider-v1",
		TimestampMs:   time.Now().UnixMilli(),
		FindingType:   pb.FindingType_FINDING_TYPE_IDENTITY_ANOMALY,
		Severity:      pb.Severity_SEVERITY_HIGH,
		Confidence:    0.78,
		Description:   "Suspicious role assumption by insider",
		SubjectNodeId: "principal-bob",
	}
	if err := fsm.ProcessFinding(ctx, "corr-004", finding); err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}

	pending := fsm.ListPendingApprovals()
	if len(pending) == 0 {
		t.Fatal("expected pending approval")
	}
	authRequestID := pending[0].AuthRequest.AuthRequestId

	// Deny.
	decision := &pb.AuthorizationDecision{
		AuthRequestId: authRequestID,
		OperatorId:    "soc-analyst-test",
		TimestampMs:   time.Now().UnixMilli(),
		Approved:      false,
		Reason:        "False positive confirmed",
	}
	if err := fsm.ApproveAction(ctx, decision); err != nil {
		t.Fatalf("ApproveAction (deny): %v", err)
	}

	incidents := fsm.ListIncidents()
	for _, inc := range incidents {
		if inc.AuthRequest != nil && inc.AuthRequest.AuthRequestId == authRequestID {
			if inc.State != domain.StateAudited {
				t.Errorf("expected AUDITED after denial, got %s", inc.State)
			}
			if inc.AuthDecision == nil || inc.AuthDecision.Approved {
				t.Error("AuthDecision should be non-nil and Approved=false")
			}
			return
		}
	}
	t.Fatal("could not find denied incident")
}

// TestFSM_InvalidAuthRequest_ReturnsError tests that approving a non-existent auth request fails.
func TestFSM_InvalidAuthRequest_ReturnsError(t *testing.T) {
	fsm, _ := newTestFSM(t)
	ctx := context.Background()

	decision := &pb.AuthorizationDecision{
		AuthRequestId: "nonexistent-auth-request",
		OperatorId:    "soc-analyst-test",
		Approved:      true,
	}
	err := fsm.ApproveAction(ctx, decision)
	if err == nil {
		t.Error("expected error for nonexistent auth request, got nil")
	}
}
