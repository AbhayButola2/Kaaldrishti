package agents

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/ml"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// =============================================================================
// CloudSecurityAgent — Cloud Security & Misconfiguration Agent
// =============================================================================

// CloudSecurityAgent detects cloud configuration weaknesses and determines
// whether they create a meaningful attack path to high-value assets.
type CloudSecurityAgent struct {
	mlClient *ml.Client
}

// NewCloudSecurityAgent creates the cloud security agent with the given ML client.
func NewCloudSecurityAgent(mlClient *ml.Client) *CloudSecurityAgent {
	return &CloudSecurityAgent{mlClient: mlClient}
}

// Identity declares the cloud-specific subscription scope.
func (a *CloudSecurityAgent) Identity() *pb.AgentSubscription {
	return &pb.AgentSubscription{
		AgentId:      "cloud-security-v1",
		AgentName:    "Cloud Security & Misconfiguration Agent",
		AgentVersion: "1.0.0",
		Description:  "Detects cloud configuration weaknesses and contextual attack paths to critical assets.",
		SubscribedNodeTypes: []pb.NodeType{
			pb.NodeType_NODE_TYPE_PRINCIPAL,
			pb.NodeType_NODE_TYPE_CREDENTIAL,
			pb.NodeType_NODE_TYPE_HOST,
			pb.NodeType_NODE_TYPE_NETWORK_SOCKET,
			pb.NodeType_NODE_TYPE_DATA_ASSET,
			pb.NodeType_NODE_TYPE_CLOUD_RESOURCE,
		},
		SubscribedEdgeTypes: []pb.EdgeType{
			pb.EdgeType_EDGE_TYPE_ASSUMES_ROLE,
			pb.EdgeType_EDGE_TYPE_CONNECTS_TO,
			pb.EdgeType_EDGE_TYPE_READS,
			pb.EdgeType_EDGE_TYPE_WRITES,
			pb.EdgeType_EDGE_TYPE_HAS_PERMISSION,
			pb.EdgeType_EDGE_TYPE_EXPOSES,
			pb.EdgeType_EDGE_TYPE_TRUSTS,
			pb.EdgeType_EDGE_TYPE_DEPENDS_ON,
			pb.EdgeType_EDGE_TYPE_ACCESSES,
		},
	}
}

// HealthCheck returns nil if operational. We allow graceful degradation if ML is unavailable.
func (a *CloudSecurityAgent) HealthCheck(ctx context.Context) error {
	// ML client availability is not strictly required; agent falls back to deterministic rules.
	return nil
}

// Analyze processes the scoped delta to detect cloud misconfigurations and contextual risk.
func (a *CloudSecurityAgent) Analyze(ctx context.Context, req *pb.AgentRequest) ([]*pb.AgentFinding, error) {
	if req.ScopedDelta == nil || len(req.ScopedDelta.UpsertedNodes) == 0 {
		return nil, nil
	}

	var findings []*pb.AgentFinding

	// Index nodes and edges for faster graph traversal during this cycle
	nodeIndex := make(map[string]*pb.GraphNode)
	for _, n := range req.ScopedDelta.UpsertedNodes {
		nodeIndex[n.NodeId] = n
	}
	
	// Index edges by source
	edgesBySrc := make(map[string][]*pb.GraphEdge)
	for _, e := range req.ScopedDelta.UpsertedEdges {
		edgesBySrc[e.SrcNodeId] = append(edgesBySrc[e.SrcNodeId], e)
	}

	// Layer 1: Configuration Risk (Evaluate each CloudResource and related entities)
	for _, node := range req.ScopedDelta.UpsertedNodes {
		var finding *pb.AgentFinding

		switch node.NodeType {
		case pb.NodeType_NODE_TYPE_CLOUD_RESOURCE:
			finding = a.analyzeCloudResource(node, edgesBySrc, nodeIndex)
		case pb.NodeType_NODE_TYPE_PRINCIPAL:
			finding = a.analyzePrincipal(node, edgesBySrc, nodeIndex)
		}

		if finding != nil {
			finding.RequestId = req.RequestId
			findings = append(findings, finding)
		}
	}

	// Layer 2: Contextual Risk & ML Integration
	// (Apply ML anomaly score if client is available, otherwise use deterministic scoring)
	for _, f := range findings {
		if a.mlClient != nil && a.mlClient.IsAvailable(ctx) {
			riskReq := &pb.RiskScoreRequest{
				RequestId:     req.RequestId,
				SubjectNodeId: f.SubjectNodeId,
				Nodes:         req.ScopedDelta.UpsertedNodes,
				Edges:         req.ScopedDelta.UpsertedEdges,
			}
			riskResp, err := a.mlClient.ScoreRisk(ctx, riskReq)
			if err == nil {
				// ML augmentation: boost confidence or adjust severity
				if riskResp.AnomalyScore > 0.7 {
					f.Severity = pb.Severity_SEVERITY_CRITICAL
					f.Confidence = max(f.Confidence, riskResp.AnomalyScore)
					f.Description += fmt.Sprintf(" [ML Augmented: Anomaly Score %.2f]", riskResp.AnomalyScore)
				}
			} else {
				log.Warn().Err(err).Str("agent", "cloud-security-v1").Msg("ML scoring failed; falling back to deterministic")
			}
		}
	}

	return findings, nil
}

func (a *CloudSecurityAgent) analyzeCloudResource(node *pb.GraphNode, edgesBySrc map[string][]*pb.GraphEdge, nodeIndex map[string]*pb.GraphNode) *pb.AgentFinding {
	// Rule 1: Public Exposure
	// Check if the resource has a property indicating public exposure or an EXPOSES edge
	isPublic := node.Properties["public_read"] == "true" || node.Properties["public"] == "true"
	
	if !isPublic {
		for _, e := range edgesBySrc[node.NodeId] {
			if e.EdgeType == pb.EdgeType_EDGE_TYPE_EXPOSES {
				isPublic = true
				break
			}
		}
	}

	if isPublic {
		// Contextual check: Does this lead to a crown jewel?
		isCrownJewelLinked, crownJewelPath := isLinkedToCrownJewel(node.NodeId, edgesBySrc, nodeIndex, 0)
		
		severity := pb.Severity_SEVERITY_HIGH
		confidence := 0.8
		desc := fmt.Sprintf("Public exposure detected for cloud resource %s", node.NodeId)
		
		if isCrownJewelLinked {
			severity = pb.Severity_SEVERITY_CRITICAL
			confidence = 0.95
			desc += fmt.Sprintf(". Critical attack path to crown jewel: %v", crownJewelPath)
		}

		return &pb.AgentFinding{
			FindingId:     uuid.NewString(),
			AgentId:       "cloud-security-v1",
			TimestampMs:   time.Now().UnixMilli(),
			FindingType:   pb.FindingType_FINDING_TYPE_CLOUD_MISCONFIGURATION,
			Severity:      severity,
			Confidence:    confidence,
			Description:   desc,
			SubjectNodeId: node.NodeId,
			EvidenceNodeIds: []string{node.NodeId},
		}
	}

	return nil
}

func (a *CloudSecurityAgent) analyzePrincipal(node *pb.GraphNode, edgesBySrc map[string][]*pb.GraphEdge, nodeIndex map[string]*pb.GraphNode) *pb.AgentFinding {
	// Rule 2: Excessive Permissions / Dangerous IAM Trust
	for _, e := range edgesBySrc[node.NodeId] {
		if e.EdgeType == pb.EdgeType_EDGE_TYPE_HAS_PERMISSION && (e.Properties["permission"] == "*" || e.Properties["permission"] == "AdministratorAccess") {
			// Contextual check: What can they access?
			isCrownJewelLinked, crownJewelPath := isLinkedToCrownJewel(node.NodeId, edgesBySrc, nodeIndex, 0)
			
			severity := pb.Severity_SEVERITY_MEDIUM
			confidence := 0.7
			desc := fmt.Sprintf("Principal %s has excessive '*' permissions", node.NodeId)
			
			if isCrownJewelLinked {
				severity = pb.Severity_SEVERITY_HIGH
				confidence = 0.85
				desc += fmt.Sprintf(". High-risk path to crown jewel: %v", crownJewelPath)
			}

			return &pb.AgentFinding{
				FindingId:     uuid.NewString(),
				AgentId:       "cloud-security-v1",
				TimestampMs:   time.Now().UnixMilli(),
				FindingType:   pb.FindingType_FINDING_TYPE_CLOUD_MISCONFIGURATION,
				Severity:      severity,
				Confidence:    confidence,
				Description:   desc,
				SubjectNodeId: node.NodeId,
				EvidenceNodeIds: []string{node.NodeId, e.DstNodeId},
				EvidenceEdgeIds: []string{e.EdgeId},
			}
		}
	}
	return nil
}

// isLinkedToCrownJewel performs a bounded DFS to check if the entity can reach a DataAsset labeled "crown_jewel"
func isLinkedToCrownJewel(startNodeId string, edgesBySrc map[string][]*pb.GraphEdge, nodeIndex map[string]*pb.GraphNode, depth int) (bool, []string) {
	if depth > 3 {
		return false, nil
	}
	
	for _, edge := range edgesBySrc[startNodeId] {
		targetNode, exists := nodeIndex[edge.DstNodeId]
		if exists && targetNode.NodeType == pb.NodeType_NODE_TYPE_DATA_ASSET && targetNode.Properties["asset.sensitivity"] == "crown_jewel" {
			return true, []string{startNodeId, targetNode.NodeId}
		}
		
		found, path := isLinkedToCrownJewel(edge.DstNodeId, edgesBySrc, nodeIndex, depth+1)
		if found {
			return true, append([]string{startNodeId}, path...)
		}
	}
	return false, nil
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
