// Package ingestion validates raw telemetry events and converts them to graph mutations.
//
// Validation rules:
//   - event_id must be non-empty
//   - timestamp_ms must be > 0 and not more than 60s in the future
//   - source_id must be non-empty
//   - payload must be present and well-formed (enforced by the proto oneof)
//   - payload-specific required fields (e.g. process_id, principal_id) must be non-empty
//
// Any event failing validation is rejected: a rejection audit event is written
// and the event is dropped. The Go engine continues processing; a single bad
// event never crashes the ingestion loop.
package ingestion

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/audit"
	"github.com/kaaladrishti/engine/internal/domain"
	"github.com/kaaladrishti/engine/internal/graph"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// maxFutureSkewMs is the maximum allowed clock skew (event timestamp in future).
const maxFutureSkewMs = 60_000

// Validator validates and processes incoming TelemetryEvents.
type Validator struct {
	store    graph.GraphStore
	auditLog *audit.Logger
}

// NewValidator creates a new Validator.
func NewValidator(store graph.GraphStore, auditLog *audit.Logger) *Validator {
	return &Validator{store: store, auditLog: auditLog}
}

// ProcessEvent validates a proto TelemetryEvent and applies the resulting graph mutations.
// Returns the graph delta generated, or nil on rejection (rejection is not an error).
// Errors are returned only for unexpected internal failures (e.g., graph store errors).
func (v *Validator) ProcessEvent(ctx context.Context, event *pb.TelemetryEvent) (*domain.GraphDelta, error) {
	if err := v.validate(event); err != nil {
		v.logRejection(event, err.Error())
		return nil, nil // Rejection: drop and continue
	}

	delta, err := v.buildDelta(event)
	if err != nil {
		return nil, fmt.Errorf("ingestion: build delta: %w", err)
	}

	if err := v.ValidateDelta(ctx, delta); err != nil {
		v.logRejection(event, err.Error())
		return nil, nil
	}

	// Apply mutations to the graph store.
	for _, n := range delta.UpsertedNodes {
		if err := v.store.UpsertNode(ctx, n); err != nil {
			return nil, fmt.Errorf("ingestion: upsert node %q: %w", n.ID, err)
		}
	}
	for _, e := range delta.UpsertedEdges {
		if err := v.store.UpsertEdge(ctx, e); err != nil {
			return nil, fmt.Errorf("ingestion: upsert edge %q: %w", e.ID, err)
		}
	}

	_ = v.auditLog.Log(audit.NewEvent(
		domain.AuditCategoryIngestion,
		"ingestion",
		fmt.Sprintf("processed TelemetryEvent %s", event.EventId),
	).Detail(map[string]any{
		"event_id":  event.EventId,
		"source_id": event.SourceId,
		"nodes":     len(delta.UpsertedNodes),
		"edges":     len(delta.UpsertedEdges),
	}).Build())

	log.Debug().
		Str("event_id", event.EventId).
		Int("nodes", len(delta.UpsertedNodes)).
		Int("edges", len(delta.UpsertedEdges)).
		Msg("ingestion: event processed")

	return delta, nil
}

// validate checks the structural validity of a TelemetryEvent.
func (v *Validator) validate(event *pb.TelemetryEvent) error {
	if event.EventId == "" {
		return fmt.Errorf("event_id is empty")
	}
	if event.TimestampMs <= 0 {
		return fmt.Errorf("timestamp_ms must be > 0")
	}
	nowMs := time.Now().UnixMilli()
	if event.TimestampMs > nowMs+maxFutureSkewMs {
		return fmt.Errorf("timestamp_ms is too far in the future (skew > %dms)", maxFutureSkewMs)
	}
	if event.SourceId == "" {
		return fmt.Errorf("source_id is empty")
	}
	if event.Payload == nil {
		return fmt.Errorf("payload is nil")
	}
	return v.validatePayload(event)
}

// validatePayload validates the typed event payload.
func (v *Validator) validatePayload(event *pb.TelemetryEvent) error {
	switch p := event.Payload.(type) {
	case *pb.TelemetryEvent_ProcessEvent:
		if p.ProcessEvent == nil {
			return fmt.Errorf("process_event is nil")
		}
		if p.ProcessEvent.ProcessId == "" {
			return fmt.Errorf("process_event.process_id is empty")
		}
	case *pb.TelemetryEvent_NetworkEvent:
		if p.NetworkEvent == nil {
			return fmt.Errorf("network_event is nil")
		}
		if p.NetworkEvent.DstIp == "" {
			return fmt.Errorf("network_event.dst_ip is empty")
		}
	case *pb.TelemetryEvent_IdentityEvent:
		if p.IdentityEvent == nil {
			return fmt.Errorf("identity_event is nil")
		}
		if p.IdentityEvent.PrincipalId == "" {
			return fmt.Errorf("identity_event.principal_id is empty")
		}
	case *pb.TelemetryEvent_FileEvent:
		if p.FileEvent == nil {
			return fmt.Errorf("file_event is nil")
		}
		if p.FileEvent.FilePath == "" {
			return fmt.Errorf("file_event.file_path is empty")
		}
	case *pb.TelemetryEvent_RegistryEvent:
		if p.RegistryEvent == nil {
			return fmt.Errorf("registry_event is nil")
		}
		if p.RegistryEvent.KeyPath == "" {
			return fmt.Errorf("registry_event.key_path is empty")
		}
	default:
		return fmt.Errorf("unknown payload type: %T", event.Payload)
	}
	return nil
}

// buildDelta converts a validated TelemetryEvent into graph mutations.
func (v *Validator) buildDelta(event *pb.TelemetryEvent) (*domain.GraphDelta, error) {
	delta := &domain.GraphDelta{
		SourceEventID: event.EventId,
		TimestampMs:   event.TimestampMs,
	}
	ts := event.TimestampMs
	prov := event.EventId

	switch p := event.Payload.(type) {
	case *pb.TelemetryEvent_ProcessEvent:
		nodes, edges := buildProcessNodes(p.ProcessEvent, ts, prov)
		delta.UpsertedNodes = append(delta.UpsertedNodes, nodes...)
		delta.UpsertedEdges = append(delta.UpsertedEdges, edges...)

	case *pb.TelemetryEvent_NetworkEvent:
		nodes, edges := buildNetworkNodes(p.NetworkEvent, ts, prov)
		delta.UpsertedNodes = append(delta.UpsertedNodes, nodes...)
		delta.UpsertedEdges = append(delta.UpsertedEdges, edges...)

	case *pb.TelemetryEvent_IdentityEvent:
		nodes, edges := buildIdentityNodes(p.IdentityEvent, ts, prov)
		delta.UpsertedNodes = append(delta.UpsertedNodes, nodes...)
		delta.UpsertedEdges = append(delta.UpsertedEdges, edges...)

	case *pb.TelemetryEvent_FileEvent:
		nodes, edges := buildFileNodes(p.FileEvent, ts, prov)
		delta.UpsertedNodes = append(delta.UpsertedNodes, nodes...)
		delta.UpsertedEdges = append(delta.UpsertedEdges, edges...)

	case *pb.TelemetryEvent_RegistryEvent:
		nodes, edges := buildRegistryNodes(p.RegistryEvent, ts, prov)
		delta.UpsertedNodes = append(delta.UpsertedNodes, nodes...)
		delta.UpsertedEdges = append(delta.UpsertedEdges, edges...)
	}

	return delta, nil
}

// --- per-event-type graph node/edge builders ---

func buildProcessNodes(pe *pb.ProcessEvent, ts int64, provenance string) ([]*domain.Node, []*domain.Edge) {
	hostNode := &domain.Node{
		ID: "host:" + pe.HostId, Type: domain.NodeTypeHost,
		Label: pe.HostId, TimestampMs: ts, Confidence: 0.95, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{"host.hostname": pe.HostId},
	}
	procNode := &domain.Node{
		ID: "proc:" + pe.ProcessId, Type: domain.NodeTypeProcess,
		Label: pe.ImagePath, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{
			"process.pid":          pe.ProcessId,
			"process.image_path":   pe.ImagePath,
			"process.command_line": pe.CommandLine,
			"process.host_id":      pe.HostId,
		},
	}
	principalNode := &domain.Node{
		ID: "principal:" + pe.UserId, Type: domain.NodeTypePrincipal,
		Label: pe.UserId, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{"principal.username": pe.UserId},
	}

	nodes := []*domain.Node{hostNode, procNode, principalNode}
	spawnEdge := &domain.Edge{
		SrcNodeID: "principal:" + pe.UserId, DstNodeID: "proc:" + pe.ProcessId,
		Type: domain.EdgeTypeSpawned, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{},
	}
	spawnEdge.ID = domain.EdgeID(spawnEdge.SrcNodeID, spawnEdge.Type, spawnEdge.DstNodeID)
	edges := []*domain.Edge{spawnEdge}

	if pe.ParentPid != "" && pe.ParentPid != "0" {
		parentNode := &domain.Node{
			ID: "proc:" + pe.ParentPid, Type: domain.NodeTypeProcess,
			Label: "proc-" + pe.ParentPid, TimestampMs: ts, Confidence: 0.8, RecencyDecay: 1.0,
			Provenance: provenance, Properties: map[string]string{"process.pid": pe.ParentPid},
		}
		nodes = append(nodes, parentNode)
		parentEdge := &domain.Edge{
			SrcNodeID: "proc:" + pe.ParentPid, DstNodeID: "proc:" + pe.ProcessId,
			Type: domain.EdgeTypeSpawned, TimestampMs: ts, Confidence: 0.85, RecencyDecay: 1.0,
			Provenance: provenance, Properties: map[string]string{},
		}
		parentEdge.ID = domain.EdgeID(parentEdge.SrcNodeID, parentEdge.Type, parentEdge.DstNodeID)
		edges = append(edges, parentEdge)
	}

	return nodes, edges
}

func buildNetworkNodes(ne *pb.NetworkEvent, ts int64, provenance string) ([]*domain.Node, []*domain.Edge) {
	socketID := fmt.Sprintf("socket:%s:%d->%s:%d", ne.SrcIp, ne.SrcPort, ne.DstIp, ne.DstPort)
	socketNode := &domain.Node{
		ID: socketID, Type: domain.NodeTypeNetworkSocket,
		Label:       fmt.Sprintf("%s:%d→%s:%d", ne.SrcIp, ne.SrcPort, ne.DstIp, ne.DstPort),
		TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{
			"socket.src_ip":   ne.SrcIp,
			"socket.dst_ip":   ne.DstIp,
			"socket.dst_port": fmt.Sprintf("%d", ne.DstPort),
			"socket.protocol": ne.Protocol,
		},
	}
	procNode := &domain.Node{
		ID: "proc:" + ne.ProcessId, Type: domain.NodeTypeProcess,
		Label: "proc-" + ne.ProcessId, TimestampMs: ts, Confidence: 0.85, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{"process.pid": ne.ProcessId},
	}
	connEdge := &domain.Edge{
		SrcNodeID: "proc:" + ne.ProcessId, DstNodeID: socketID,
		Type: domain.EdgeTypeConnectsTo, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{
			"bytes_sent": fmt.Sprintf("%d", ne.BytesSent),
			"bytes_recv": fmt.Sprintf("%d", ne.BytesRecv),
		},
	}
	connEdge.ID = domain.EdgeID(connEdge.SrcNodeID, connEdge.Type, connEdge.DstNodeID)
	return []*domain.Node{socketNode, procNode}, []*domain.Edge{connEdge}
}

func buildIdentityNodes(ie *pb.IdentityEvent, ts int64, provenance string) ([]*domain.Node, []*domain.Edge) {
	principalNode := &domain.Node{
		ID: "principal:" + ie.PrincipalId, Type: domain.NodeTypePrincipal,
		Label: ie.PrincipalId, TimestampMs: ts, Confidence: 0.95, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{"principal.username": ie.PrincipalId},
	}
	credNode := &domain.Node{
		ID: "credential:" + ie.CredentialId, Type: domain.NodeTypeCredential,
		Label: ie.CredentialId, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{
			"credential.id":     ie.CredentialId,
			"credential.target": ie.TargetResource,
		},
	}
	roleEdge := &domain.Edge{
		SrcNodeID: "principal:" + ie.PrincipalId, DstNodeID: "credential:" + ie.CredentialId,
		Type: domain.EdgeTypeAssumesRole, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{
			"success": fmt.Sprintf("%v", ie.Success),
		},
	}
	roleEdge.ID = domain.EdgeID(roleEdge.SrcNodeID, roleEdge.Type, roleEdge.DstNodeID)
	return []*domain.Node{principalNode, credNode}, []*domain.Edge{roleEdge}
}

func buildFileNodes(fe *pb.FileEvent, ts int64, provenance string) ([]*domain.Node, []*domain.Edge) {
	assetNode := &domain.Node{
		ID: "asset:" + fe.FilePath, Type: domain.NodeTypeDataAsset,
		Label: fe.FilePath, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{
			"asset.path":        fe.FilePath,
			"asset.sensitivity": crownJewelSensitivity(fe.FilePath),
		},
	}
	procNode := &domain.Node{
		ID: "proc:" + fe.ProcessId, Type: domain.NodeTypeProcess,
		Label: "proc-" + fe.ProcessId, TimestampMs: ts, Confidence: 0.8, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{"process.pid": fe.ProcessId},
	}
	edgeType := domain.EdgeTypeReads
	if fe.Action == pb.FileEvent_FILE_ACTION_WRITE || fe.Action == pb.FileEvent_FILE_ACTION_DELETE {
		edgeType = domain.EdgeTypeWrites
	}
	fileEdge := &domain.Edge{
		SrcNodeID: "proc:" + fe.ProcessId, DstNodeID: "asset:" + fe.FilePath,
		Type: edgeType, TimestampMs: ts, Confidence: 0.9, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{"bytes": fmt.Sprintf("%d", fe.Bytes)},
	}
	fileEdge.ID = domain.EdgeID(fileEdge.SrcNodeID, fileEdge.Type, fileEdge.DstNodeID)
	return []*domain.Node{assetNode, procNode}, []*domain.Edge{fileEdge}
}

func buildRegistryNodes(re *pb.RegistryEvent, ts int64, provenance string) ([]*domain.Node, []*domain.Edge) {
	regID := "registry:" + re.HostId + ":" + re.KeyPath
	regNode := &domain.Node{
		ID: regID, Type: domain.NodeTypeRegistryKey,
		Label: re.KeyPath, TimestampMs: ts, Confidence: 0.85, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{
			"registry.key_path":   re.KeyPath,
			"registry.value_name": re.ValueName,
			"registry.host_id":    re.HostId,
		},
	}
	procNode := &domain.Node{
		ID: "proc:" + re.ProcessId, Type: domain.NodeTypeProcess,
		Label: "proc-" + re.ProcessId, TimestampMs: ts, Confidence: 0.8, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{"process.pid": re.ProcessId},
	}
	edgeType := domain.EdgeTypeReads
	if re.Action == pb.RegistryEvent_REGISTRY_ACTION_WRITE || re.Action == pb.RegistryEvent_REGISTRY_ACTION_CREATE {
		edgeType = domain.EdgeTypeWrites
	}
	regEdge := &domain.Edge{
		SrcNodeID: "proc:" + re.ProcessId, DstNodeID: regID,
		Type: edgeType, TimestampMs: ts, Confidence: 0.85, RecencyDecay: 1.0,
		Provenance: provenance, Properties: map[string]string{},
	}
	regEdge.ID = domain.EdgeID(regEdge.SrcNodeID, regEdge.Type, regEdge.DstNodeID)
	return []*domain.Node{regNode, procNode}, []*domain.Edge{regEdge}
}

// crownJewelSensitivity classifies a file path's sensitivity level.
func crownJewelSensitivity(path string) string {
	crownJewelMarkers := []string{
		"crown-jewel", "secrets", "credentials", "financial", "hr-data",
	}
	lower := strings.ToLower(path)
	for _, marker := range crownJewelMarkers {
		if strings.Contains(lower, marker) {
			return "crown_jewel"
		}
	}
	return "internal"
}

// ValidateDelta enforces strict graph schema invariants before write.
func (v *Validator) ValidateDelta(ctx context.Context, delta *domain.GraphDelta) error {
	// Map to track new nodes in the delta
	newNodes := make(map[string]*domain.Node)
	for _, n := range delta.UpsertedNodes {
		newNodes[n.ID] = n
	}

	// Helper to get workflow_id of a node (checks delta, then store)
	getWorkflowID := func(nodeID string) string {
		if n, ok := newNodes[nodeID]; ok {
			return n.Properties["workflow_id"]
		}
		if n, err := v.store.GetNode(ctx, nodeID); err == nil {
			return n.Properties["workflow_id"]
		}
		return ""
	}

	// 1. Node invariants
	for _, n := range delta.UpsertedNodes {
		switch n.Type {
		case domain.NodeTypeAction:
			if n.Properties["workflow_id"] == "" {
				return fmt.Errorf("Action %s missing workflow_id", n.ID)
			}
			parentID := n.Properties["parent_action_id"]
			if parentID != "" {
				parentWf := getWorkflowID(parentID)
				if parentWf != "" && parentWf != n.Properties["workflow_id"] {
					// Must have explicit DELEGATES_TO edge in delta
					hasDelegation := false
					for _, e := range delta.UpsertedEdges {
						if e.Type == domain.EdgeTypeDelegatesTo && e.SrcNodeID == parentID && e.DstNodeID == n.ID {
							hasDelegation = true
							break
						}
					}
					if !hasDelegation {
						return fmt.Errorf("cross-workflow parent link without DELEGATES_TO edge")
					}
				}
			}
		case domain.NodeTypeWorkflowExecution:
			if n.Properties["authorized_plan_id"] == "" {
				return fmt.Errorf("WorkflowExecution %s missing authorized_plan_id", n.ID)
			}
		case domain.NodeTypeToolCall:
			toolID := n.Properties["tool_id"]
			if toolID == "" {
				return fmt.Errorf("ToolCall %s missing tool_id", n.ID)
			}
			if _, ok := newNodes[toolID]; !ok {
				if _, err := v.store.GetNode(ctx, toolID); err != nil {
					return fmt.Errorf("ToolCall %s references unknown Tool %s", n.ID, toolID)
				}
			}
		case domain.NodeTypeAgentPlan:
			if n.Properties["intent_id"] == "" {
				return fmt.Errorf("AgentPlan %s missing intent_id", n.ID)
			}
		}
	}

	// 2. Edge invariants: Cross-workflow edges must be DELEGATES_TO
	for _, e := range delta.UpsertedEdges {
		if e.Type == domain.EdgeTypeDelegatesTo {
			continue
		}
		srcWf := getWorkflowID(e.SrcNodeID)
		dstWf := getWorkflowID(e.DstNodeID)
		
		if srcWf != "" && dstWf != "" && srcWf != dstWf {
			return fmt.Errorf("cross-workflow edge %s not typed DELEGATES_TO", e.ID)
		}
	}

	return nil
}

func (v *Validator) logRejection(event *pb.TelemetryEvent, reason string) {
	log.Warn().
		Str("event_id", event.GetEventId()).
		Str("reason", reason).
		Msg("ingestion: event rejected")

	_ = v.auditLog.Log(audit.NewEvent(
		domain.AuditCategoryIngestion,
		"ingestion",
		"rejected TelemetryEvent",
	).Outcome("rejected").Detail(map[string]any{
		"event_id": event.GetEventId(),
		"reason":   reason,
	}).Build())
}
