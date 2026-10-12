// Package dispatcher — dispatcher scope enforcement tests.
package dispatcher_test

import (
	"context"
	"testing"
	"time"

	"github.com/kaaladrishti/engine/internal/dispatcher"
	"github.com/kaaladrishti/engine/internal/domain"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// mockAgent is a test double that records what it received.
type mockAgent struct {
	sub      *pb.AgentSubscription
	received []*pb.AgentRequest
}

func (m *mockAgent) Identity() *pb.AgentSubscription { return m.sub }
func (m *mockAgent) HealthCheck(_ context.Context) error { return nil }
func (m *mockAgent) Analyze(_ context.Context, req *pb.AgentRequest) ([]*pb.AgentFinding, error) {
	m.received = append(m.received, req)
	return nil, nil
}

// TestIdentityAgent_NeverReceivesNetworkOrModuleNodes verifies that the
// IdentityAgent subscription scope is enforced by the dispatcher — not by
// the agent itself. This satisfies acceptance criterion 3.
func TestIdentityAgent_NeverReceivesNetworkOrModuleNodes(t *testing.T) {
	d := dispatcher.NewDispatcher(4, 5*time.Second)

	// Identity agent subscribes only to PRINCIPAL, CREDENTIAL, ASSUMES_ROLE.
	identityAgent := &mockAgent{
		sub: &pb.AgentSubscription{
			AgentId:             "identity-insider-v1",
			AgentName:           "Identity/Insider Threat Agent",
			SubscribedNodeTypes: []pb.NodeType{pb.NodeType_NODE_TYPE_PRINCIPAL, pb.NodeType_NODE_TYPE_CREDENTIAL},
			SubscribedEdgeTypes: []pb.EdgeType{pb.EdgeType_EDGE_TYPE_ASSUMES_ROLE},
		},
	}
	d.Register(identityAgent)

	// Delta containing a mix of node types.
	delta := &domain.GraphDelta{
		DeltaID:       "delta-001",
		TimestampMs:   time.Now().UnixMilli(),
		SourceEventID: "event-001",
		UpsertedNodes: []*domain.Node{
			{ID: "p1", Type: domain.NodeTypePrincipal, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
			{ID: "n1", Type: domain.NodeTypeNetworkSocket, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
			{ID: "m1", Type: domain.NodeTypeModule, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
			{ID: "cred1", Type: domain.NodeTypeCredential, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		},
		UpsertedEdges: []*domain.Edge{
			{ID: "e1", SrcNodeID: "p1", DstNodeID: "cred1", Type: domain.EdgeTypeAssumesRole, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		},
	}

	ctx := context.Background()
	_, err := d.Dispatch(ctx, "corr-001", delta)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	if len(identityAgent.received) == 0 {
		t.Fatal("identity agent was not called (expected to receive scoped delta)")
	}

	req := identityAgent.received[0]
	for _, n := range req.ScopedDelta.UpsertedNodes {
		if n.NodeType == pb.NodeType_NODE_TYPE_NETWORK_SOCKET {
			t.Errorf("identity agent received NETWORK_SOCKET node %q — scope enforcement failed", n.NodeId)
		}
		if n.NodeType == pb.NodeType_NODE_TYPE_MODULE {
			t.Errorf("identity agent received MODULE node %q — scope enforcement failed", n.NodeId)
		}
	}

	// Verify the expected nodes ARE present.
	receivedIDs := make(map[string]bool)
	for _, n := range req.ScopedDelta.UpsertedNodes {
		receivedIDs[n.NodeId] = true
	}
	if !receivedIDs["p1"] {
		t.Error("identity agent should have received PRINCIPAL node p1")
	}
	if !receivedIDs["cred1"] {
		t.Error("identity agent should have received CREDENTIAL node cred1")
	}
}

// TestDispatch_EmptyDeltaSkipsAgent verifies that agents with no matching
// types are not invoked at all.
func TestDispatch_EmptyDeltaSkipsAgent(t *testing.T) {
	d := dispatcher.NewDispatcher(4, 5*time.Second)

	// Agent subscribing only to HOST nodes.
	hostAgent := &mockAgent{
		sub: &pb.AgentSubscription{
			AgentId:             "host-only",
			SubscribedNodeTypes: []pb.NodeType{pb.NodeType_NODE_TYPE_HOST},
		},
	}
	d.Register(hostAgent)

	// Delta with no HOST nodes.
	delta := &domain.GraphDelta{
		DeltaID:       "delta-002",
		TimestampMs:   time.Now().UnixMilli(),
		SourceEventID: "event-002",
		UpsertedNodes: []*domain.Node{
			{ID: "p1", Type: domain.NodeTypePrincipal, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		},
	}

	ctx := context.Background()
	if _, err := d.Dispatch(ctx, "corr-002", delta); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	if len(hostAgent.received) != 0 {
		t.Errorf("host-only agent should not have been called for a delta with no HOST nodes")
	}
}

// TestDispatch_PanicRecovery verifies that a panicking agent does not crash the dispatcher.
func TestDispatch_PanicRecovery(t *testing.T) {
	d := dispatcher.NewDispatcher(4, 5*time.Second)

	panicAgent := &panickyAgent{
		sub: &pb.AgentSubscription{
			AgentId:             "panicky-agent",
			SubscribedNodeTypes: []pb.NodeType{pb.NodeType_NODE_TYPE_HOST},
		},
	}
	d.Register(panicAgent)

	delta := &domain.GraphDelta{
		DeltaID:       "delta-003",
		TimestampMs:   time.Now().UnixMilli(),
		SourceEventID: "event-003",
		UpsertedNodes: []*domain.Node{
			{ID: "h1", Type: domain.NodeTypeHost, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		},
	}

	ctx := context.Background()
	// Must not panic.
	findings, err := d.Dispatch(ctx, "corr-003", delta)
	if err != nil {
		t.Fatalf("Dispatch should not return error on agent panic: %v", err)
	}
	_ = findings // panic recovery returns nil findings — acceptable
}

type panickyAgent struct{ sub *pb.AgentSubscription }

func (p *panickyAgent) Identity() *pb.AgentSubscription                                           { return p.sub }
func (p *panickyAgent) HealthCheck(_ context.Context) error                                       { return nil }
func (p *panickyAgent) Analyze(_ context.Context, _ *pb.AgentRequest) ([]*pb.AgentFinding, error) {
	panic("simulated agent panic for test")
}
