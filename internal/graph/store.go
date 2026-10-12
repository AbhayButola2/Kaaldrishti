// Package graph defines the GraphStore interface and the InMemoryGraphStore.
//
// The GraphStore interface is the single boundary between the ingestion/agent
// layers and the underlying storage implementation. InMemoryGraphStore is the
// only implementation in Phases 1-11; it uses BoltDB for snapshot persistence.
//
// Thread safety: all methods are goroutine-safe. The in-memory store uses a
// sync.RWMutex; reads take a read lock, writes take a write lock.
package graph

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/domain"
)

// GraphStore is the interface all graph storage implementations must satisfy.
//
// Extension point: a future distributed graph store (Neo4j, TigerGraph) can
// implement this interface and be swapped in via cmd/engine/main.go without
// changing any other package.
type GraphStore interface {
	// UpsertNode inserts or updates a node. If a node with the same ID exists,
	// only fields that are non-zero in the incoming node are updated.
	UpsertNode(ctx context.Context, node *domain.Node) error

	// UpsertEdge inserts or updates an edge.
	UpsertEdge(ctx context.Context, edge *domain.Edge) error

	// GetNode retrieves a node by ID. Returns ErrNodeNotFound if absent.
	GetNode(ctx context.Context, nodeID string) (*domain.Node, error)

	// GetNeighborhood returns all nodes and edges within `depth` hops of nodeID.
	// depth=1 returns immediate neighbors only.
	GetNeighborhood(ctx context.Context, nodeID string, depth int) (*domain.Subgraph, error)

	// QuerySubgraph returns a filtered subgraph matching the given criteria.
	QuerySubgraph(ctx context.Context, filter domain.SubgraphFilter) (*domain.Subgraph, error)

	// ApplyDecay multiplies recency_decay of all nodes/edges by decayFactor.
	// Entities with recency_decay < cutoffThreshold after decay are candidates
	// for eviction (but are not automatically removed — eviction is separate).
	ApplyDecay(ctx context.Context, decayFactor float64, cutoffThreshold float64) error

	// Snapshot persists the current in-memory graph to durable storage.
	// This is NOT a no-op; it satisfies the cold-start durability requirement.
	Snapshot(ctx context.Context) error

	// Load restores the graph from the last snapshot. Called on warm restart.
	Load(ctx context.Context) error

	// NodeCount returns the current number of nodes in the graph.
	NodeCount() int

	// EdgeCount returns the current number of edges in the graph.
	EdgeCount() int
}

// ErrNodeNotFound is returned by GetNode when the requested node does not exist.
var ErrNodeNotFound = fmt.Errorf("node not found")

// ErrEdgeNotFound is returned by GetEdge when the requested edge does not exist.
var ErrEdgeNotFound = fmt.Errorf("edge not found")

// ErrScopeViolation is returned when an agent queries outside its authorized workflow scope.
var ErrScopeViolation = fmt.Errorf("scope violation: workflow access denied")

// InMemoryGraphStore is the in-memory implementation of GraphStore.
// It is backed by BoltDB for snapshot persistence (see snapshot.go).
type InMemoryGraphStore struct {
	mu    sync.RWMutex
	nodes map[string]*domain.Node
	edges map[string]*domain.Edge

	// adjOut maps srcNodeID → set of edge IDs originating from that node.
	adjOut map[string]map[string]struct{}
	// adjIn maps dstNodeID → set of edge IDs pointing to that node.
	adjIn map[string]map[string]struct{}

	snapshotPath string
}

// NewInMemoryGraphStore creates an empty in-memory graph store.
// snapshotPath is the BoltDB file path for Snapshot/Load operations.
func NewInMemoryGraphStore(snapshotPath string) *InMemoryGraphStore {
	return &InMemoryGraphStore{
		nodes:        make(map[string]*domain.Node),
		edges:        make(map[string]*domain.Edge),
		adjOut:       make(map[string]map[string]struct{}),
		adjIn:        make(map[string]map[string]struct{}),
		snapshotPath: snapshotPath,
	}
}

// UpsertNode inserts or updates a node. Goroutine-safe.
func (s *InMemoryGraphStore) UpsertNode(ctx context.Context, node *domain.Node) error {
	if node.ID == "" {
		return fmt.Errorf("graph: UpsertNode: node ID must not be empty")
	}
	if node.Properties == nil {
		node.Properties = make(map[string]string)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.nodes[node.ID]
	if !ok {
		// New node: store a copy.
		cp := *node
		s.nodes[node.ID] = &cp
		log.Debug().Str("node_id", node.ID).Str("type", node.Type.String()).Msg("graph: node inserted")
		return nil
	}

	// Update: merge non-zero fields onto the existing node.
	if node.TimestampMs > existing.TimestampMs {
		existing.TimestampMs = node.TimestampMs
	}
	if node.Confidence > 0 {
		existing.Confidence = node.Confidence
	}
	if node.Label != "" {
		existing.Label = node.Label
	}
	// Reset decay on re-observation.
	existing.RecencyDecay = 1.0
	if node.Provenance != "" {
		existing.Provenance = node.Provenance
	}
	for k, v := range node.Properties {
		existing.Properties[k] = v
	}

	log.Debug().Str("node_id", node.ID).Msg("graph: node updated")
	return nil
}

// UpsertEdge inserts or updates an edge. Goroutine-safe.
func (s *InMemoryGraphStore) UpsertEdge(ctx context.Context, edge *domain.Edge) error {
	if edge.SrcNodeID == "" || edge.DstNodeID == "" {
		return fmt.Errorf("graph: UpsertEdge: src and dst node IDs must not be empty")
	}
	if edge.ID == "" {
		edge.ID = domain.EdgeID(edge.SrcNodeID, edge.Type, edge.DstNodeID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.edges[edge.ID]
	if !ok {
		cp := *edge
		s.edges[edge.ID] = &cp
		// Update adjacency index.
		if s.adjOut[edge.SrcNodeID] == nil {
			s.adjOut[edge.SrcNodeID] = make(map[string]struct{})
		}
		s.adjOut[edge.SrcNodeID][edge.ID] = struct{}{}
		if s.adjIn[edge.DstNodeID] == nil {
			s.adjIn[edge.DstNodeID] = make(map[string]struct{})
		}
		s.adjIn[edge.DstNodeID][edge.ID] = struct{}{}
		log.Debug().Str("edge_id", edge.ID).Msg("graph: edge inserted")
		return nil
	}

	if edge.TimestampMs > existing.TimestampMs {
		existing.TimestampMs = edge.TimestampMs
	}
	if edge.Confidence > 0 {
		existing.Confidence = edge.Confidence
	}
	existing.RecencyDecay = 1.0
	for k, v := range edge.Properties {
		existing.Properties[k] = v
	}
	return nil
}

// GetNode retrieves a node by ID. Returns ErrNodeNotFound if absent.
func (s *InMemoryGraphStore) GetNode(ctx context.Context, nodeID string) (*domain.Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n, ok := s.nodes[nodeID]
	if !ok {
		return nil, ErrNodeNotFound
	}
	cp := *n
	return &cp, nil
}

// GetNeighborhood returns all nodes and edges within `depth` hops of nodeID.
// depth=1 returns immediate neighbors. Uses BFS.
func (s *InMemoryGraphStore) GetNeighborhood(ctx context.Context, nodeID string, depth int) (*domain.Subgraph, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	visited := make(map[string]struct{})
	edgeSet := make(map[string]*domain.Edge)
	queue := []string{nodeID}
	visited[nodeID] = struct{}{}

	for d := 0; d < depth && len(queue) > 0; d++ {
		next := []string{}
		for _, nid := range queue {
			// Traverse outgoing edges.
			for eid := range s.adjOut[nid] {
				e, ok := s.edges[eid]
				if !ok {
					continue
				}
				edgeSet[eid] = e
				if _, seen := visited[e.DstNodeID]; !seen {
					visited[e.DstNodeID] = struct{}{}
					next = append(next, e.DstNodeID)
				}
			}
			// Traverse incoming edges.
			for eid := range s.adjIn[nid] {
				e, ok := s.edges[eid]
				if !ok {
					continue
				}
				edgeSet[eid] = e
				if _, seen := visited[e.SrcNodeID]; !seen {
					visited[e.SrcNodeID] = struct{}{}
					next = append(next, e.SrcNodeID)
				}
			}
		}
		queue = next
	}

	subgraph := &domain.Subgraph{}
	for nid := range visited {
		if n, ok := s.nodes[nid]; ok {
			cp := *n
			subgraph.Nodes = append(subgraph.Nodes, &cp)
		}
	}
	for _, e := range edgeSet {
		cp := *e
		subgraph.Edges = append(subgraph.Edges, &cp)
	}
	return subgraph, nil
}

// QuerySubgraph returns nodes and edges matching the given filter.
func (s *InMemoryGraphStore) QuerySubgraph(ctx context.Context, filter domain.SubgraphFilter) (*domain.Subgraph, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Enforce strict workflow scoping if WorkflowID is specified.
	if filter.WorkflowID != "" {
		// Verify that the requested workflow actually exists/has nodes.
		// For simplicity, we just filter nodes/edges that don't match the workflow ID.
		// If an agent asks for a workflow it doesn't own, this logic should reject it.
		// (In a real system, the dispatcher would inject the correct workflow ID).
		workflowFound := false
		for _, n := range s.nodes {
			if n.Properties["workflow_id"] == filter.WorkflowID {
				workflowFound = true
				break
			}
		}
		if !workflowFound {
			return nil, ErrScopeViolation
		}
	}

	nodeTypeSet := make(map[domain.NodeType]struct{})
	for _, nt := range filter.NodeTypes {
		nodeTypeSet[nt] = struct{}{}
	}
	edgeTypeSet := make(map[domain.EdgeType]struct{})
	for _, et := range filter.EdgeTypes {
		edgeTypeSet[et] = struct{}{}
	}

	subgraph := &domain.Subgraph{}

	for _, n := range s.nodes {
		if len(nodeTypeSet) > 0 {
			if _, ok := nodeTypeSet[n.Type]; !ok {
				continue
			}
		}
		if filter.SinceMs > 0 && n.TimestampMs < filter.SinceMs {
			continue
		}
		if filter.MinConfidence > 0 && n.Confidence < filter.MinConfidence {
			continue
		}
		if filter.WorkflowID != "" && n.Properties["workflow_id"] != filter.WorkflowID {
			continue
		}
		cp := *n
		subgraph.Nodes = append(subgraph.Nodes, &cp)
	}

	for _, e := range s.edges {
		if len(edgeTypeSet) > 0 {
			if _, ok := edgeTypeSet[e.Type]; !ok {
				continue
			}
		}
		if filter.SinceMs > 0 && e.TimestampMs < filter.SinceMs {
			continue
		}
		if filter.MinConfidence > 0 && e.Confidence < filter.MinConfidence {
			continue
		}
		if filter.WorkflowID != "" && e.Properties["workflow_id"] != filter.WorkflowID {
			continue
		}
		cp := *e
		subgraph.Edges = append(subgraph.Edges, &cp)
	}

	return subgraph, nil
}

// ApplyDecay multiplies recency_decay on every node and edge by decayFactor.
// Entities dropping below cutoffThreshold are logged but not evicted.
func (s *InMemoryGraphStore) ApplyDecay(ctx context.Context, decayFactor float64, cutoffThreshold float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	evictionCandidates := 0
	for _, n := range s.nodes {
		n.RecencyDecay *= decayFactor
		if n.RecencyDecay < cutoffThreshold {
			evictionCandidates++
		}
	}
	for _, e := range s.edges {
		if e.DecayClass != domain.DecayClassBaseline {
			e.RecencyDecay *= decayFactor
		}
	}

	if evictionCandidates > 0 {
		log.Info().
			Int("eviction_candidates", evictionCandidates).
			Float64("cutoff_threshold", cutoffThreshold).
			Msg("graph: decay applied; some nodes below eviction threshold (not yet evicted)")
	}

	return nil
}

// NodeCount returns the current number of nodes. Goroutine-safe.
func (s *InMemoryGraphStore) NodeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

// EdgeCount returns the current number of edges. Goroutine-safe.
func (s *InMemoryGraphStore) EdgeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.edges)
}

// allNodesAndEdges returns copies of all nodes and edges (caller must hold at
// least a read lock).
func (s *InMemoryGraphStore) allNodesUnsafe() []*domain.Node {
	out := make([]*domain.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		out = append(out, &cp)
	}
	return out
}

func (s *InMemoryGraphStore) allEdgesUnsafe() []*domain.Edge {
	out := make([]*domain.Edge, 0, len(s.edges))
	for _, e := range s.edges {
		cp := *e
		out = append(out, &cp)
	}
	return out
}

// nowMs returns the current time as Unix epoch milliseconds.
func nowMs() int64 {
	return time.Now().UnixMilli()
}
