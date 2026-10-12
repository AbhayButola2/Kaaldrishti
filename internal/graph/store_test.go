package graph_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kaaladrishti/engine/internal/domain"
	"github.com/kaaladrishti/engine/internal/graph"
)

func newTestStore(t *testing.T) *graph.InMemoryGraphStore {
	t.Helper()
	dir := t.TempDir()
	return graph.NewInMemoryGraphStore(dir + "/test_graph.db")
}

func TestUpsertAndGetNode(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	node := &domain.Node{
		ID:           "host-001",
		Type:         domain.NodeTypeHost,
		Label:        "workstation-alice-01",
		TimestampMs:  time.Now().UnixMilli(),
		Confidence:   0.95,
		RecencyDecay: 1.0,
		Provenance:   "event-abc123",
		Properties:   map[string]string{"host.hostname": "workstation-alice-01"},
	}

	if err := store.UpsertNode(ctx, node); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}

	got, err := store.GetNode(ctx, "host-001")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.ID != "host-001" {
		t.Errorf("got ID %q, want %q", got.ID, "host-001")
	}
	if got.Type != domain.NodeTypeHost {
		t.Errorf("got type %v, want HOST", got.Type)
	}
}

func TestGetNodeNotFound(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	_, err := store.GetNode(ctx, "nonexistent")
	if err != graph.ErrNodeNotFound {
		t.Errorf("expected ErrNodeNotFound, got %v", err)
	}
}

func TestUpsertNode_RejectsEmptyID(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	err := store.UpsertNode(ctx, &domain.Node{ID: "", Type: domain.NodeTypeHost})
	if err == nil {
		t.Error("expected error for empty node ID")
	}
}

func TestGetNeighborhood(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	// Set up: principal → process → network_socket
	for _, n := range []*domain.Node{
		{ID: "p1", Type: domain.NodeTypePrincipal, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		{ID: "proc1", Type: domain.NodeTypeProcess, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		{ID: "sock1", Type: domain.NodeTypeNetworkSocket, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
	} {
		n.TimestampMs = time.Now().UnixMilli()
		if err := store.UpsertNode(ctx, n); err != nil {
			t.Fatalf("UpsertNode %q: %v", n.ID, err)
		}
	}
	for _, e := range []*domain.Edge{
		{SrcNodeID: "p1", DstNodeID: "proc1", Type: domain.EdgeTypeSpawned, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		{SrcNodeID: "proc1", DstNodeID: "sock1", Type: domain.EdgeTypeConnectsTo, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
	} {
		e.ID = domain.EdgeID(e.SrcNodeID, e.Type, e.DstNodeID)
		e.TimestampMs = time.Now().UnixMilli()
		if err := store.UpsertEdge(ctx, e); err != nil {
			t.Fatalf("UpsertEdge: %v", err)
		}
	}

	// Depth=1 from proc1 should include p1, proc1, sock1
	sub, err := store.GetNeighborhood(ctx, "proc1", 1)
	if err != nil {
		t.Fatalf("GetNeighborhood: %v", err)
	}
	nodeIDs := make(map[string]struct{})
	for _, n := range sub.Nodes {
		nodeIDs[n.ID] = struct{}{}
	}
	for _, want := range []string{"p1", "proc1", "sock1"} {
		if _, ok := nodeIDs[want]; !ok {
			t.Errorf("expected node %q in neighborhood, not found", want)
		}
	}
}

func TestQuerySubgraph_NodeTypeFilter(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	for _, n := range []*domain.Node{
		{ID: "p1", Type: domain.NodeTypePrincipal, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		{ID: "h1", Type: domain.NodeTypeHost, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
		{ID: "s1", Type: domain.NodeTypeNetworkSocket, Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}},
	} {
		n.TimestampMs = time.Now().UnixMilli()
		if err := store.UpsertNode(ctx, n); err != nil {
			t.Fatalf("UpsertNode: %v", err)
		}
	}

	sub, err := store.QuerySubgraph(ctx, domain.SubgraphFilter{
		NodeTypes: []domain.NodeType{domain.NodeTypePrincipal, domain.NodeTypeCredential},
	})
	if err != nil {
		t.Fatalf("QuerySubgraph: %v", err)
	}
	if len(sub.Nodes) != 1 {
		t.Errorf("expected 1 node (PRINCIPAL), got %d", len(sub.Nodes))
	}
	if sub.Nodes[0].ID != "p1" {
		t.Errorf("expected node p1, got %q", sub.Nodes[0].ID)
	}
}

func TestQuerySubgraph_WorkflowScope(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	// Node in workflow 1
	n1 := &domain.Node{ID: "n1", Type: domain.NodeTypeAction, TimestampMs: time.Now().UnixMilli(), Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{"workflow_id": "wf-1"}}
	// Node in workflow 2
	n2 := &domain.Node{ID: "n2", Type: domain.NodeTypeAction, TimestampMs: time.Now().UnixMilli(), Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{"workflow_id": "wf-2"}}

	if err := store.UpsertNode(ctx, n1); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if err := store.UpsertNode(ctx, n2); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}

	// Requesting an unknown workflow should return scope violation
	_, err := store.QuerySubgraph(ctx, domain.SubgraphFilter{WorkflowID: "wf-unknown"})
	if err != graph.ErrScopeViolation {
		t.Errorf("expected ErrScopeViolation for unknown workflow, got %v", err)
	}

	// Requesting wf-1 should return only n1
	sub, err := store.QuerySubgraph(ctx, domain.SubgraphFilter{WorkflowID: "wf-1"})
	if err != nil {
		t.Fatalf("QuerySubgraph: %v", err)
	}
	if len(sub.Nodes) != 1 || sub.Nodes[0].ID != "n1" {
		t.Errorf("expected only n1 in wf-1, got %v", sub.Nodes)
	}
}

func TestDecay(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	node := &domain.Node{
		ID:           "n1",
		Type:         domain.NodeTypeHost,
		TimestampMs:  time.Now().UnixMilli(),
		Confidence:   1.0,
		RecencyDecay: 1.0,
		Properties:   map[string]string{},
	}
	if err := store.UpsertNode(ctx, node); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}

	if err := store.ApplyDecay(ctx, 0.95, 0.01); err != nil {
		t.Fatalf("ApplyDecay: %v", err)
	}

	got, err := store.GetNode(ctx, "n1")
	if err != nil {
		t.Fatalf("GetNode after decay: %v", err)
	}
	if got.RecencyDecay >= 1.0 {
		t.Errorf("expected RecencyDecay < 1.0 after decay, got %f", got.RecencyDecay)
	}
}

func TestApplyDecay_BaselineExemption(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	n1 := &domain.Node{ID: "n1", Type: domain.NodeTypeIntent, TimestampMs: time.Now().UnixMilli(), Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}}
	n2 := &domain.Node{ID: "n2", Type: domain.NodeTypeAgentPlan, TimestampMs: time.Now().UnixMilli(), Confidence: 1.0, RecencyDecay: 1.0, Properties: map[string]string{}}
	store.UpsertNode(ctx, n1)
	store.UpsertNode(ctx, n2)

	// Baseline edge
	e1 := &domain.Edge{ID: "e1", SrcNodeID: "n1", DstNodeID: "n2", Type: domain.EdgeTypeHasPlan, TimestampMs: time.Now().UnixMilli(), Confidence: 1.0, RecencyDecay: 1.0, DecayClass: domain.DecayClassBaseline, Properties: map[string]string{}}
	store.UpsertEdge(ctx, e1)
	// Behavioral edge
	e2 := &domain.Edge{ID: "e2", SrcNodeID: "n1", DstNodeID: "n2", Type: domain.EdgeTypeReads, TimestampMs: time.Now().UnixMilli(), Confidence: 1.0, RecencyDecay: 1.0, DecayClass: domain.DecayClassBehavioral, Properties: map[string]string{}}
	store.UpsertEdge(ctx, e2)

	if err := store.ApplyDecay(ctx, 0.5, 0.01); err != nil {
		t.Fatalf("ApplyDecay: %v", err)
	}

	sub, _ := store.QuerySubgraph(ctx, domain.SubgraphFilter{})
	for _, e := range sub.Edges {
		if e.ID == "e1" && e.RecencyDecay != 1.0 {
			t.Errorf("expected baseline edge to not decay, got %v", e.RecencyDecay)
		}
		if e.ID == "e2" && e.RecencyDecay >= 1.0 {
			t.Errorf("expected behavioral edge to decay, got %v", e.RecencyDecay)
		}
	}
}

func TestSnapshotAndLoad(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/snap.db"
	ctx := context.Background()

	// Create store, add nodes and edges.
	store1 := graph.NewInMemoryGraphStore(dbPath)
	ts := time.Now().UnixMilli()
	if err := store1.UpsertNode(ctx, &domain.Node{
		ID: "n1", Type: domain.NodeTypePrincipal,
		TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Properties: map[string]string{"principal.username": "alice"},
	}); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if err := store1.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Load into a fresh store.
	store2 := graph.NewInMemoryGraphStore(dbPath)
	if err := store2.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := store2.GetNode(ctx, "n1")
	if err != nil {
		t.Fatalf("GetNode after Load: %v", err)
	}
	if got.Properties["principal.username"] != "alice" {
		t.Errorf("property not restored: got %q", got.Properties["principal.username"])
	}
}

func TestLoad_NoSnapshotFile(t *testing.T) {
	ctx := context.Background()
	store := graph.NewInMemoryGraphStore("/tmp/kd_nonexistent_test.db")
	// Should succeed silently (cold start).
	if err := store.Load(ctx); err != nil {
		t.Errorf("Load with no snapshot file should succeed, got: %v", err)
	}
	// Clean up if file was accidentally created.
	os.Remove("/tmp/kd_nonexistent_test.db")
}
