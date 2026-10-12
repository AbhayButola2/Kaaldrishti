package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
	"github.com/kaaladrishti/engine/internal/agents"
	"github.com/kaaladrishti/engine/internal/audit"
	"github.com/kaaladrishti/engine/internal/dispatcher"
	"github.com/kaaladrishti/engine/internal/domain"
	"github.com/kaaladrishti/engine/internal/governance"
	"github.com/kaaladrishti/engine/internal/graph"
	"github.com/kaaladrishti/engine/internal/ingestion"
	"github.com/kaaladrishti/engine/internal/ml"
	"github.com/kaaladrishti/engine/internal/orchestration"
)

// TestEndToEndIntegration simulates a complete pipeline run:
// Event -> Ingestion -> Graph -> Dispatch -> Agent -> Orchestrator -> FSM.
// It bypasses UDS and Python gRPC (using a lazy dummy ML client) to test
// the Go core control plane in isolation.
func TestEndToEndIntegration(t *testing.T) {
	// 1. Setup temporary resources.
	dir := t.TempDir()
	dbPath := dir + "/graph.db"
	auditPath := dir + "/audit.jsonl"

	auditLog, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	defer auditLog.Close()

	store := graph.NewInMemoryGraphStore(dbPath)
	fsm := governance.NewStateMachine(0.65, 5*time.Minute, auditLog)
	correlator := orchestration.NewCorrelator(5*time.Minute, fsm)
	disp := dispatcher.NewDispatcher(2, 5*time.Second)
	validator := ingestion.NewValidator(store, auditLog)

	// Register agents.
	// Use a dummy ML client that will fail gracefully and fall back to rule-based logic.
	dummyML := ml.NewClientLazy("localhost:9999", 1*time.Second)
	disp.Register(agents.NewBlastRadiusAgent(dummyML))
	disp.Register(agents.NewIdentityAgent())
	disp.Register(agents.NewCloudSecurityAgent(dummyML))
	disp.Register(agents.NewIntentLineageAgent(dummyML))

	// 2. Create a synthetic high-risk event (external network connection).
	ctx := context.Background()
	event := &pb.TelemetryEvent{
		EventId:       "e2e-event-1",
		TimestampMs:   time.Now().UnixMilli(),
		SourceId:      "sensor-1",
		SchemaVersion: "1.0",
		Payload: &pb.TelemetryEvent_NetworkEvent{
			NetworkEvent: &pb.NetworkEvent{
				ProcessId: "proc-malware",
				HostId:    "host-1",
				DstIp:     "1.2.3.4", // external IP -> rule-based trigger
			},
		},
	}

	// 3. Run Pipeline.
	// 3a. Ingest.
	delta, err := validator.ProcessEvent(ctx, event)
	if err != nil {
		t.Fatalf("ProcessEvent failed: %v", err)
	}
	if delta == nil {
		t.Fatal("expected delta, got nil")
	}

	// 3b. Dispatch to agents.
	findings, err := disp.Dispatch(ctx, event.EventId, delta)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from agents, got 0")
	}

	// 3c. Submit to correlator (which forwards to FSM).
	for _, f := range findings {
		if err := correlator.Submit(ctx, f); err != nil {
			t.Fatalf("Correlator submit failed: %v", err)
		}
	}

	// 4. Verify FSM state.
	// Since ML is down, rule-based fallback gives confidence 0.4.
	// Our threshold is 0.65, so it shouldn't reach HUMAN_APPROVAL_REQUIRED.
	// Wait, we want to test the full pipeline. Let's adjust FSM threshold.
	fsmLowThresh := governance.NewStateMachine(0.30, 5*time.Minute, auditLog)
	correlator2 := orchestration.NewCorrelator(5*time.Minute, fsmLowThresh)
	for _, f := range findings {
		_ = correlator2.Submit(ctx, f)
	}

	pending := fsmLowThresh.ListPendingApprovals()
	if len(pending) == 0 {
		t.Fatal("expected finding to reach HUMAN_APPROVAL_REQUIRED")
	}

	inc := pending[0]
	if inc.AuthRequest == nil {
		t.Fatal("expected AuthRequest to be generated")
	}

	// 5. Approve execution.
	decision := &pb.AuthorizationDecision{
		AuthRequestId: inc.AuthRequest.AuthRequestId,
		OperatorId:    "e2e-tester",
		TimestampMs:   time.Now().UnixMilli(),
		Approved:      true,
		Reason:        "E2E test approval",
	}
	if err := fsmLowThresh.ApproveAction(ctx, decision); err != nil {
		t.Fatalf("ApproveAction failed: %v", err)
	}

	// 6. Verify final state.
	finalInc, ok := fsmLowThresh.GetIncident(inc.ID)
	if !ok {
		t.Fatal("incident not found")
	}
	if finalInc.State != "AUDITED" {
		t.Errorf("expected final state AUDITED, got %s", finalInc.State)
	}

	// 7. Verify audit log was written.
	if stat, err := os.Stat(auditPath); err != nil || stat.Size() == 0 {
		t.Error("audit log file was not written")
	}
}

func TestIntentLineageAgent_E2E(t *testing.T) {
	dir := t.TempDir()
	auditLog, _ := audit.NewLogger(dir + "/audit.jsonl")
	defer auditLog.Close()

	store := graph.NewInMemoryGraphStore(dir + "/graph.db")
	disp := dispatcher.NewDispatcher(2, 5*time.Second)
	validator := ingestion.NewValidator(store, auditLog)

	dummyML := ml.NewClientLazy("localhost:9999", 1*time.Second)
	disp.Register(agents.NewIntentLineageAgent(dummyML))

	ctx := context.Background()

	// Create an Intent delta
	delta := &domain.GraphDelta{
		SourceEventID: "workflow-event-1",
		TimestampMs:   time.Now().UnixMilli(),
		UpsertedNodes: []*domain.Node{
			{
				ID: "intent-1", Type: domain.NodeTypeIntent, Confidence: 1.0, RecencyDecay: 1.0,
				Properties: map[string]string{
					"allowed_actions": "READ,WRITE",
					"allowed_resources": "db-1,db-2",
					"allowed_tools": "sql_query",
					"allowed_privilege_ceiling": "2.0",
				},
			},
			{
				ID: "action-1", Type: domain.NodeTypeAction, Confidence: 1.0, RecencyDecay: 1.0,
				Properties: map[string]string{
					"workflow_id": "wf-1",
					"action_type": "DELETE", // Unauthorized action!
					"resource": "db-1",
					"tool": "sql_query",
					"privilege_level": "1.0",
				},
			},
		},
	}

	// First validate it
	if err := validator.ValidateDelta(ctx, delta); err != nil {
		t.Fatalf("ValidateDelta failed: %v", err)
	}

	// Dispatch to agents
	findings, err := disp.Dispatch(ctx, "workflow-event-1", delta)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from IntentLineageAgent for D1_UNAUTHORIZED_TYPE, got 0")
	}

	driftFound := false
	for _, f := range findings {
		if f.FindingType == pb.FindingType(domain.FindingTypeDriftDetected) {
			driftFound = true
			if f.Metadata["deviation_rule"] != "D1_UNAUTHORIZED_TYPE" {
				t.Errorf("expected D1_UNAUTHORIZED_TYPE, got %s", f.Metadata["deviation_rule"])
			}
		}
	}
	if !driftFound {
		t.Error("expected drift finding but none found")
	}
}
