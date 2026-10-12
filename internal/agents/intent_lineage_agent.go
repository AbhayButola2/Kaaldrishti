package agents

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
	"github.com/kaaladrishti/engine/internal/domain"
	"github.com/kaaladrishti/engine/internal/ml"
)

// IntentLineageAgent evaluates whether an autonomous workflow remains within
// its authorized scope and intent, using causal graph traversal and drift scoring.
type IntentLineageAgent struct {
	mlClient *ml.Client
}

// NewIntentLineageAgent creates a new IntentLineageAgent.
func NewIntentLineageAgent(mlClient *ml.Client) *IntentLineageAgent {
	return &IntentLineageAgent{
		mlClient: mlClient,
	}
}

func (a *IntentLineageAgent) Identity() *pb.AgentSubscription {
	return &pb.AgentSubscription{
		AgentId:       "intent-lineage-v1",
		AgentName:     "Intent Lineage & Drift Detection Agent",
		AgentVersion:  "1.0.0",
		Description:   "Evaluates causal lineage and semantic drift of agentic workflows against their authorized intents.",
		SubscribedNodeTypes: []pb.NodeType{
			pb.NodeType(domain.NodeTypeIntent),
			pb.NodeType(domain.NodeTypeAgentPlan),
			pb.NodeType(domain.NodeTypeWorkflowExecution),
			pb.NodeType(domain.NodeTypeAction),
			pb.NodeType(domain.NodeTypeTool),
			pb.NodeType(domain.NodeTypeToolCall),
			pb.NodeType(domain.NodeTypeContextArtifact),
			pb.NodeType(domain.NodeTypeMemoryEntry),
			pb.NodeType(domain.NodeTypeAuthorization),
			pb.NodeType(domain.NodeTypeFinding),
		},
		SubscribedEdgeTypes: []pb.EdgeType{
			pb.EdgeType(domain.EdgeTypeInitiatedBy),
			pb.EdgeType(domain.EdgeTypeAuthorizedBy),
			pb.EdgeType(domain.EdgeTypeExecutedBy),
			pb.EdgeType(domain.EdgeTypeHasIntent),
			pb.EdgeType(domain.EdgeTypeHasPlan),
			pb.EdgeType(domain.EdgeTypeDerivedFrom),
			pb.EdgeType(domain.EdgeTypePerforms),
			pb.EdgeType(domain.EdgeTypeInvokes),
			pb.EdgeType(domain.EdgeTypeInfluences),
			pb.EdgeType(domain.EdgeTypeDelegatesTo),
			pb.EdgeType(domain.EdgeTypeFollows),
			pb.EdgeType(domain.EdgeTypeDeviatesFrom),
			pb.EdgeType(domain.EdgeTypeAffects),
			pb.EdgeType(domain.EdgeTypeProduces),
			pb.EdgeType(domain.EdgeTypeReferences),
			pb.EdgeType(domain.EdgeTypeReads),
			pb.EdgeType(domain.EdgeTypeWrites),
			pb.EdgeType(domain.EdgeTypeAccesses),
		},
	}
}

func (a *IntentLineageAgent) Analyze(ctx context.Context, req *pb.AgentRequest) ([]*pb.AgentFinding, error) {
	delta := req.ScopedDelta
	var findings []*pb.AgentFinding

	// We only process if there is a new ACTION or TOOL_CALL
	var targetNodes []*pb.GraphNode
	for _, n := range delta.UpsertedNodes {
		if domain.NodeType(n.NodeType) == domain.NodeTypeAction || domain.NodeType(n.NodeType) == domain.NodeTypeToolCall {
			targetNodes = append(targetNodes, n)
		}
	}

	if len(targetNodes) == 0 {
		return nil, nil // Nothing to evaluate for intent lineage
	}

	for _, node := range targetNodes {
		finding, err := a.evaluateDeviation(ctx, req.RequestId, node, delta)
		if err != nil {
			// Log error but continue with other nodes
			continue
		}
		if finding != nil {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (a *IntentLineageAgent) HealthCheck(ctx context.Context) error {
	if a.mlClient == nil {
		return fmt.Errorf("mlClient is nil")
	}
	return nil
}

func (a *IntentLineageAgent) evaluateDeviation(ctx context.Context, reqID string, node *pb.GraphNode, delta *pb.GraphDelta) (*pb.AgentFinding, error) {
	workflowID := node.Properties["workflow_id"]
	if workflowID == "" {
		return nil, fmt.Errorf("node %s has no workflow_id", node.NodeId)
	}

	// In a full implementation, we would extract the full Intent baseline and compare.
	// For this prototype, we simulate the extraction of properties for D1-D5 rules.
	
	actionType := node.Properties["action_type"]
	resource := node.Properties["resource"]
	tool := node.Properties["tool"]
	privilege, _ := strconv.ParseFloat(node.Properties["privilege_level"], 64)
	
	allowedActions := strings.Split(node.Properties["allowed_actions"], ",")
	allowedResources := strings.Split(node.Properties["allowed_resources"], ",")
	allowedTools := strings.Split(node.Properties["allowed_tools"], ",")
	privilegeCeiling, _ := strconv.ParseFloat(node.Properties["allowed_privilege_ceiling"], 64)

	var deviationRule string
	var deviationDetail string
	
	// D1. UNAUTHORIZED_TYPE
	if actionType != "" && !contains(allowedActions, actionType) {
		deviationRule = "D1_UNAUTHORIZED_TYPE"
		deviationDetail = fmt.Sprintf("Action type '%s' not in allowed set", actionType)
	} else if resource != "" && !contains(allowedResources, resource) {
		deviationRule = "D1_UNAUTHORIZED_TYPE"
		deviationDetail = fmt.Sprintf("Resource '%s' not in allowed set", resource)
	} else if tool != "" && !contains(allowedTools, tool) {
		deviationRule = "D1_UNAUTHORIZED_TYPE"
		deviationDetail = fmt.Sprintf("Tool '%s' not in allowed set", tool)
	} else if privilege > privilegeCeiling {
		// D2. PRIVILEGE_ESCALATION
		deviationRule = "D2_PRIVILEGE_ESCALATION"
		deviationDetail = fmt.Sprintf("Privilege %f exceeds ceiling %f", privilege, privilegeCeiling)
	} else if node.Properties["destination_class"] == "external-unapproved" {
		// D3. DESTINATION_VIOLATION
		deviationRule = "D3_DESTINATION_VIOLATION"
		deviationDetail = "Targeted external-unapproved destination"
	} else if node.Properties["parent_action_id"] == "" && node.Properties["causation_id"] == "" {
		// D4. STRUCTURAL_BREAK
		deviationRule = "D4_STRUCTURAL_BREAK"
		deviationDetail = "Node has no causal link to AgentPlan"
	}

	// We calculate risk score based on Section 19 formula (mocked here based on factors)
	driftScore := 0.0
	if deviationRule != "" {
		driftScore = 0.8 // Arbitrary high drift score for demonstration of D1-D4 violation
	}

	// Ask ML plane for intent lineage semantic score
	var intentLineageResp *pb.IntentLineageResponse
	if a.mlClient != nil {
		req := &pb.IntentLineageRequest{
			RequestId:         reqID,
			WorkflowId:        workflowID,
			DeclaredScopeText: node.Properties["intent_objective"],
			ActualActionText:  node.Properties["action_summary"],
		}
		var err error
		intentLineageResp, err = a.mlClient.ScoreIntentLineage(ctx, req)
		if err == nil && intentLineageResp != nil {
			// D5: THRESHOLD_BREACH if ML drift score is very high and D1-D4 didn't catch it
			if deviationRule == "" && intentLineageResp.DriftScore > 0.6 {
				deviationRule = "D5_THRESHOLD_BREACH"
				deviationDetail = "Semantic drift score exceeded HIGH threshold"
				driftScore = intentLineageResp.DriftScore
			} else if deviationRule == "" {
				driftScore = intentLineageResp.DriftScore
			}
		}
	}

	if deviationRule != "" {
		finding := &pb.AgentFinding{
			FindingId:        uuid.NewString(),
			RequestId:        reqID,
			AgentId:          a.Identity().AgentId,
			TimestampMs:      time.Now().UnixMilli(),
			FindingType:      pb.FindingType(domain.FindingTypeDriftDetected),
			Severity:         pb.Severity(domain.SeverityHigh),
			Confidence:       0.9,
			Description:      fmt.Sprintf("Intent Drift Detected (%s): %s", deviationRule, deviationDetail),
			SubjectNodeId:    node.NodeId,
			IntentLineage:    intentLineageResp,
			EvidenceNodeIds:  []string{node.NodeId},
			Metadata: map[string]string{
				"deviation_rule":   deviationRule,
				"workflow_id":      workflowID,
				"drift_score":      fmt.Sprintf("%f", driftScore),
			},
		}
		return finding, nil
	}

	return nil, nil
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
