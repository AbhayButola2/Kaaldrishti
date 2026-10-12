// Package dispatcher routes graph deltas to subscribed agents with least-privilege scoping.
//
// The dispatcher is the enforcement point for agent scope isolation. It:
//   1. Maintains a registry of registered agents and their subscriptions.
//   2. Filters incoming GraphDeltas to include only node/edge types each agent has declared.
//   3. Dispatches the scoped delta to each matching agent in a bounded worker pool.
//   4. Wraps each agent call with recover() so a panicking agent cannot crash the dispatcher.
//   5. Returns all findings collected from all agents for a given delta.
//
// Concurrency: each agent dispatch is a separate goroutine, bounded by maxWorkers.
// No unbounded goroutine creation.
package dispatcher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/domain"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// Agent is the interface every Kaaladrishti analysis agent must implement.
// See docs/architecture/agent_interface.md for the full contract.
type Agent interface {
	// Identity returns the agent's static metadata and subscription scope.
	// Called once at registration; the returned subscription is immutable.
	Identity() *pb.AgentSubscription

	// Analyze processes a scope-filtered GraphDelta and returns findings.
	// The context carries a deadline (AgentTimeout from config).
	// Returning an error marks the agent unhealthy for this cycle.
	Analyze(ctx context.Context, req *pb.AgentRequest) ([]*pb.AgentFinding, error)

	// HealthCheck returns nil if the agent is operational.
	HealthCheck(ctx context.Context) error
}

// Dispatcher routes graph deltas to subscribed agents.
type Dispatcher struct {
	agents     []Agent
	agentsMu   sync.RWMutex
	maxWorkers int
	timeout    time.Duration
}

// NewDispatcher creates a dispatcher with the given worker pool size and per-agent timeout.
func NewDispatcher(maxWorkers int, timeout time.Duration) *Dispatcher {
	if maxWorkers <= 0 {
		maxWorkers = 8
	}
	return &Dispatcher{
		maxWorkers: maxWorkers,
		timeout:    timeout,
	}
}

// Register adds an agent to the dispatcher. Safe to call before or after dispatching starts.
func (d *Dispatcher) Register(agent Agent) {
	d.agentsMu.Lock()
	defer d.agentsMu.Unlock()
	sub := agent.Identity()
	d.agents = append(d.agents, agent)
	log.Info().
		Str("agent_id", sub.AgentId).
		Str("agent_name", sub.AgentName).
		Msg("dispatcher: agent registered")
}

// Dispatch delivers a GraphDelta to all subscribed agents and collects their findings.
// Each agent receives only the subset of nodes/edges it has declared in its subscription.
// Runs agents concurrently, bounded by maxWorkers.
func (d *Dispatcher) Dispatch(ctx context.Context, correlationID string, delta *domain.GraphDelta) ([]*pb.AgentFinding, error) {
	d.agentsMu.RLock()
	agents := make([]Agent, len(d.agents))
	copy(agents, d.agents)
	d.agentsMu.RUnlock()

	if len(agents) == 0 {
		return nil, nil
	}

	// Semaphore for bounded worker pool.
	sem := make(chan struct{}, d.maxWorkers)
	var (
		mu       sync.Mutex
		findings []*pb.AgentFinding
		wg       sync.WaitGroup
	)

	for _, agent := range agents {
		sub := agent.Identity()
		scopedDelta := filterDelta(delta, sub)
		if scopedDelta == nil {
			// No matching nodes/edges for this agent — skip.
			continue
		}

		req := &pb.AgentRequest{
			RequestId:   correlationID + ":" + sub.AgentId,
			AgentId:     sub.AgentId,
			TimestampMs: time.Now().UnixMilli(),
			ScopedDelta: domainDeltaToProto(scopedDelta),
			// tool_manifest_ref intentionally left empty — see deferred_work.md
		}

		wg.Add(1)
		agent := agent // capture
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			agentFindings := d.invokeAgent(ctx, agent, req)
			if len(agentFindings) > 0 {
				mu.Lock()
				findings = append(findings, agentFindings...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return findings, nil
}

// DispatchToAgent invokes a single named agent directly (for manual SOC invocations).
func (d *Dispatcher) DispatchToAgent(ctx context.Context, agentID string, delta *domain.GraphDelta) ([]*pb.AgentFinding, error) {
	d.agentsMu.RLock()
	var target Agent
	for _, a := range d.agents {
		if a.Identity().AgentId == agentID {
			target = a
			break
		}
	}
	d.agentsMu.RUnlock()

	if target == nil {
		return nil, fmt.Errorf("dispatcher: agent %q not found", agentID)
	}

	sub := target.Identity()
	scopedDelta := filterDelta(delta, sub)
	if scopedDelta == nil {
		return nil, nil
	}

	req := &pb.AgentRequest{
		RequestId:   uuid.NewString(),
		AgentId:     sub.AgentId,
		TimestampMs: time.Now().UnixMilli(),
		ScopedDelta: domainDeltaToProto(scopedDelta),
	}

	return d.invokeAgent(ctx, target, req), nil
}

// invokeAgent calls agent.Analyze with a timeout and recover wrapper.
func (d *Dispatcher) invokeAgent(ctx context.Context, agent Agent, req *pb.AgentRequest) (findings []*pb.AgentFinding) {
	sub := agent.Identity()

	// Panic recovery: a panicking agent must not crash the dispatcher.
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Str("agent_id", sub.AgentId).
				Interface("panic", r).
				Msg("dispatcher: agent panicked; recovering")
		}
	}()

	agentCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	start := time.Now()
	results, err := agent.Analyze(agentCtx, req)
	elapsed := time.Since(start)

	if err != nil {
		log.Error().
			Err(err).
			Str("agent_id", sub.AgentId).
			Dur("elapsed", elapsed).
			Msg("dispatcher: agent returned error")
		return nil
	}

	log.Debug().
		Str("agent_id", sub.AgentId).
		Int("findings", len(results)).
		Dur("elapsed", elapsed).
		Msg("dispatcher: agent completed")

	return results
}

// filterDelta returns a copy of delta containing only nodes/edges matching the agent's subscription.
// Returns nil if the filtered delta would be empty (no matching entities).
func filterDelta(delta *domain.GraphDelta, sub *pb.AgentSubscription) *domain.GraphDelta {
	nodeTypeSet := make(map[domain.NodeType]struct{})
	for _, nt := range sub.SubscribedNodeTypes {
		nodeTypeSet[domain.NodeType(nt)] = struct{}{}
	}
	edgeTypeSet := make(map[domain.EdgeType]struct{})
	for _, et := range sub.SubscribedEdgeTypes {
		edgeTypeSet[domain.EdgeType(et)] = struct{}{}
	}

	filtered := &domain.GraphDelta{
		DeltaID:       delta.DeltaID,
		TimestampMs:   delta.TimestampMs,
		SourceEventID: delta.SourceEventID,
	}

	// If subscription declares no type filters, pass everything.
	allNodes := len(nodeTypeSet) == 0
	allEdges := len(edgeTypeSet) == 0

	for _, n := range delta.UpsertedNodes {
		if allNodes {
			cp := *n
			filtered.UpsertedNodes = append(filtered.UpsertedNodes, &cp)
		} else if _, ok := nodeTypeSet[n.Type]; ok {
			cp := *n
			filtered.UpsertedNodes = append(filtered.UpsertedNodes, &cp)
		}
	}
	for _, e := range delta.UpsertedEdges {
		if allEdges {
			cp := *e
			filtered.UpsertedEdges = append(filtered.UpsertedEdges, &cp)
		} else if _, ok := edgeTypeSet[e.Type]; ok {
			cp := *e
			filtered.UpsertedEdges = append(filtered.UpsertedEdges, &cp)
		}
	}

	if len(filtered.UpsertedNodes) == 0 && len(filtered.UpsertedEdges) == 0 {
		return nil
	}
	return filtered
}

// domainDeltaToProto converts a domain.GraphDelta to the proto wire type.
func domainDeltaToProto(d *domain.GraphDelta) *pb.GraphDelta {
	if d == nil {
		return nil
	}
	proto := &pb.GraphDelta{
		DeltaId:       d.DeltaID,
		TimestampMs:   d.TimestampMs,
		SourceEventId: d.SourceEventID,
	}
	for _, n := range d.UpsertedNodes {
		proto.UpsertedNodes = append(proto.UpsertedNodes, &pb.GraphNode{
			NodeId:       n.ID,
			NodeType:     pb.NodeType(n.Type),
			Label:        n.Label,
			TimestampMs:  n.TimestampMs,
			Confidence:   n.Confidence,
			RecencyDecay: n.RecencyDecay,
			Provenance:   n.Provenance,
			Properties:   n.Properties,
		})
	}
	for _, e := range d.UpsertedEdges {
		proto.UpsertedEdges = append(proto.UpsertedEdges, &pb.GraphEdge{
			EdgeId:       e.ID,
			SrcNodeId:    e.SrcNodeID,
			DstNodeId:    e.DstNodeID,
			EdgeType:     pb.EdgeType(e.Type),
			TimestampMs:  e.TimestampMs,
			Confidence:   e.Confidence,
			RecencyDecay: e.RecencyDecay,
			Provenance:   e.Provenance,
			Properties:   e.Properties,
		})
	}
	return proto
}
