package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

type ZeroDayAgent struct {
	pzedsURL string
	client   *http.Client
}

func NewZeroDayAgent(pzedsURL string) *ZeroDayAgent {
	if pzedsURL == "" {
		pzedsURL = "http://127.0.0.1:8000"
	}
	return &ZeroDayAgent{
		pzedsURL: pzedsURL,
		client: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

func (a *ZeroDayAgent) Identity() *pb.AgentSubscription {
	return &pb.AgentSubscription{
		AgentId:      "zero-day-pzeds-v1",
		AgentName:    "Predictive Zero-Day Exploitation Detection System (PZEDS)",
		AgentVersion: "2.0.0",
		Description:  "External integration with the PZEDS behavioral anomaly engine.",
		// Subscribe to everything to forward the full graph
		SubscribedNodeTypes: []pb.NodeType{},
		SubscribedEdgeTypes: []pb.EdgeType{},
	}
}

func (a *ZeroDayAgent) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", a.pzedsURL+"/status", nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PZEDS returned status %d", resp.StatusCode)
	}
	return nil
}

// PZEDSEvent matches the Python Event schema in PZEDS
type PZEDSEvent struct {
	Timestamp  float64                `json:"timestamp"`
	SourceID   string                 `json:"source_id"`
	SourceType string                 `json:"source_type"`
	TargetID   string                 `json:"target_id"`
	TargetType string                 `json:"target_type"`
	EdgeType   string                 `json:"edge_type"`
	Properties map[string]interface{} `json:"properties"`
}

func (a *ZeroDayAgent) Analyze(ctx context.Context, req *pb.AgentRequest) ([]*pb.AgentFinding, error) {
	if req.ScopedDelta == nil {
		return nil, nil
	}

	// We only care about new edges to map to PZEDS Events which require a source and target
	for _, e := range req.ScopedDelta.UpsertedEdges {
		
		// Map types approximately to PZEDS schemas
		sourceType := "Process" // Default fallback
		targetType := "Process"
		
		// Find node types from the delta
		for _, n := range req.ScopedDelta.UpsertedNodes {
			if n.NodeId == e.SrcNodeId {
				sourceType = mapNodeType(n.NodeType)
			}
			if n.NodeId == e.DstNodeId {
				targetType = mapNodeType(n.NodeType)
			}
		}

		event := PZEDSEvent{
			Timestamp:  float64(time.Now().UnixNano()) / 1e9,
			SourceID:   e.SrcNodeId,
			SourceType: sourceType,
			TargetID:   e.DstNodeId,
			TargetType: targetType,
			EdgeType:   mapEdgeType(e.EdgeType),
			Properties: make(map[string]interface{}),
		}
		
		for k, v := range e.Properties {
			event.Properties[k] = v
		}

		// Send to PZEDS
		payload, err := json.Marshal(event)
		if err != nil {
			continue
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", a.pzedsURL+"/ingest/event", bytes.NewReader(payload))
		if err == nil {
			httpReq.Header.Set("Content-Type", "application/json")
			resp, err := a.client.Do(httpReq)
			if err == nil {
				resp.Body.Close()
			} else {
				log.Debug().Err(err).Msg("Failed to forward event to PZEDS")
			}
		}
	}

	// For now, we only forward telemetry. 
	// To fully integrate, we would also poll PZEDS for detections and convert them into AgentFindings.
	// We return nil findings to let PZEDS dashboard handle the visualization, or we could poll `/detections` here.
	return nil, nil
}

func mapNodeType(nt pb.NodeType) string {
	switch nt {
	case pb.NodeType_NODE_TYPE_PRINCIPAL: return "Principal"
	case pb.NodeType_NODE_TYPE_CREDENTIAL: return "Credential"
	case pb.NodeType_NODE_TYPE_HOST: return "Host"
	case pb.NodeType_NODE_TYPE_PROCESS: return "Process"
	case pb.NodeType_NODE_TYPE_MODULE: return "Module"
	case pb.NodeType_NODE_TYPE_NETWORK_SOCKET: return "NetworkSocket"
	case pb.NodeType_NODE_TYPE_DATA_ASSET: return "DataAsset"
	case pb.NodeType_NODE_TYPE_REGISTRY_KEY: return "RegistryKey"
	default: return "Process"
	}
}

func mapEdgeType(et pb.EdgeType) string {
	switch et {
	case pb.EdgeType_EDGE_TYPE_ASSUMES_ROLE: return "ASSUMES_ROLE"
	case pb.EdgeType_EDGE_TYPE_SPAWNED: return "SPAWNED"
	case pb.EdgeType_EDGE_TYPE_CONNECTS_TO: return "CONNECTS_TO"
	case pb.EdgeType_EDGE_TYPE_LOADS: return "LOADS"
	case pb.EdgeType_EDGE_TYPE_READS: return "READS"
	case pb.EdgeType_EDGE_TYPE_WRITES: return "WRITES"
	default: return "SPAWNED"
	}
}
