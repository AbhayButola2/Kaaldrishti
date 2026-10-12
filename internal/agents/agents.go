// Package agents implements the two named Kaaladrishti agents.
//
// BlastRadiusAgent: flagship agent subscribing to all node/edge types.
// Calls Python ML for GNN risk score, blast radius, and next-attack forecast.
//
// IdentityAgent: rule-based insider threat agent subscribing only to
// PRINCIPAL, CREDENTIAL, and ASSUMES_ROLE types.
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
// BlastRadiusAgent — flagship agent
// =============================================================================

// BlastRadiusAgent subscribes to all graph types and uses Python ML to
// compute GNN-based risk scores, blast radius, and next-attack forecasts.
type BlastRadiusAgent struct {
	mlClient *ml.Client
}

// NewBlastRadiusAgent creates the flagship agent with the given ML client.
func NewBlastRadiusAgent(mlClient *ml.Client) *BlastRadiusAgent {
	return &BlastRadiusAgent{mlClient: mlClient}
}

// Identity declares all node and edge type subscriptions (broad scope).
func (a *BlastRadiusAgent) Identity() *pb.AgentSubscription {
	return &pb.AgentSubscription{
		AgentId:      "blast-radius-v1",
		AgentName:    "Blast Radius & Next-Attack Prediction Agent",
		AgentVersion: "1.0.0",
		Description:  "GNN-based risk scoring, blast-radius (PPR/RWR), and next-attack forecasting via Python ML service.",
		// Broad subscription: receives all node and edge types.
		// Empty slice = all types (per dispatcher.filterDelta convention).
		SubscribedNodeTypes: []pb.NodeType{
			pb.NodeType_NODE_TYPE_PRINCIPAL,
			pb.NodeType_NODE_TYPE_CREDENTIAL,
			pb.NodeType_NODE_TYPE_HOST,
			pb.NodeType_NODE_TYPE_PROCESS,
			pb.NodeType_NODE_TYPE_MODULE,
			pb.NodeType_NODE_TYPE_NETWORK_SOCKET,
			pb.NodeType_NODE_TYPE_DATA_ASSET,
			pb.NodeType_NODE_TYPE_REGISTRY_KEY,
		},
		SubscribedEdgeTypes: []pb.EdgeType{
			pb.EdgeType_EDGE_TYPE_ASSUMES_ROLE,
			pb.EdgeType_EDGE_TYPE_SPAWNED,
			pb.EdgeType_EDGE_TYPE_CONNECTS_TO,
			pb.EdgeType_EDGE_TYPE_LOADS,
			pb.EdgeType_EDGE_TYPE_READS,
			pb.EdgeType_EDGE_TYPE_WRITES,
		},
	}
}

// HealthCheck returns nil if the ML client is reachable.
func (a *BlastRadiusAgent) HealthCheck(ctx context.Context) error {
	if !a.mlClient.IsAvailable(ctx) {
		return fmt.Errorf("blast-radius-agent: ML service not available")
	}
	return nil
}

// Analyze computes risk score, blast radius, and next-attack forecast for
// anomalous entities in the scoped delta. Returns findings only if the
// risk score exceeds the anomaly threshold.
func (a *BlastRadiusAgent) Analyze(ctx context.Context, req *pb.AgentRequest) ([]*pb.AgentFinding, error) {
	if req.ScopedDelta == nil || len(req.ScopedDelta.UpsertedNodes) == 0 {
		return nil, nil
	}

	// Select the "most interesting" node as the analysis subject.
	// Heuristic: prefer data assets (crown jewels), then network sockets, then processes.
	subject := pickSubjectNode(req.ScopedDelta.UpsertedNodes)
	if subject == nil {
		return nil, nil
	}

	riskReq := &pb.RiskScoreRequest{
		RequestId:     req.RequestId,
		SubjectNodeId: subject.NodeId,
		Nodes:         req.ScopedDelta.UpsertedNodes,
		Edges:         req.ScopedDelta.UpsertedEdges,
	}

	// Call GNN risk scoring.
	riskResp, err := a.mlClient.ScoreRisk(ctx, riskReq)
	if err != nil {
		// ML unavailable: return a lower-confidence rule-based finding.
		log.Warn().Err(err).Str("agent", "blast-radius-v1").Msg("ML unavailable; using rule-based fallback")
		return a.ruleBasedFinding(req, subject), nil
	}

	// Only generate a finding if the anomaly score exceeds threshold.
	const anomalyThreshold = 0.4
	if riskResp.AnomalyScore < anomalyThreshold {
		return nil, nil
	}

	// Call blast radius scoring.
	blastResp, err := a.mlClient.ComputeBlastRadius(ctx, riskReq)
	if err != nil {
		log.Warn().Err(err).Msg("blast radius scoring failed; omitting from finding")
	}

	// Call next-attack forecast.
	forecastResp, err := a.mlClient.ForecastNextAttack(ctx, &pb.NextAttackForecastRequest{
		RequestId:          req.RequestId,
		SubjectNodeId:      subject.NodeId,
		ObservedTechniques: extractObservedTechniques(req.ScopedDelta),
		TopK:               3,
	})
	if err != nil {
		log.Warn().Err(err).Msg("next-attack forecast failed; omitting from finding")
	}

	severity := scoreToProbSeverity(riskResp.AnomalyScore)
	finding := &pb.AgentFinding{
		FindingId:     uuid.NewString(),
		RequestId:     req.RequestId,
		AgentId:       "blast-radius-v1",
		TimestampMs:   time.Now().UnixMilli(),
		FindingType:   pb.FindingType_FINDING_TYPE_BLAST_RADIUS,
		Severity:      severity,
		Confidence:    riskResp.AnomalyScore,
		Description:   fmt.Sprintf("GNN anomaly score %.2f for node %s", riskResp.AnomalyScore, subject.NodeId),
		SubjectNodeId: subject.NodeId,
		Metadata: map[string]string{
			"model_version": riskResp.ModelVersion,
		},
	}

	if blastResp != nil {
		finding.BlastRadius = blastResp
	}
	if forecastResp != nil {
		finding.NextAttack = forecastResp
	}

	// Collect evidence nodes/edges.
	for _, n := range req.ScopedDelta.UpsertedNodes {
		finding.EvidenceNodeIds = append(finding.EvidenceNodeIds, n.NodeId)
	}

	return []*pb.AgentFinding{finding}, nil
}

// ruleBasedFinding produces a lower-confidence finding without ML when Python is unavailable.
func (a *BlastRadiusAgent) ruleBasedFinding(req *pb.AgentRequest, subject *pb.GraphNode) []*pb.AgentFinding {
	// Simple heuristic: crown-jewel access or external network = suspicious.
	isSuspicious := false
	for _, n := range req.ScopedDelta.UpsertedNodes {
		if n.Properties["asset.sensitivity"] == "crown_jewel" {
			isSuspicious = true
		}
		if n.NodeType == pb.NodeType_NODE_TYPE_NETWORK_SOCKET {
			if dst := n.Properties["socket.dst_ip"]; isExternalIP(dst) {
				isSuspicious = true
			}
		}
	}
	if !isSuspicious {
		return nil
	}

	return []*pb.AgentFinding{{
		FindingId:     uuid.NewString(),
		RequestId:     req.RequestId,
		AgentId:       "blast-radius-v1",
		TimestampMs:   time.Now().UnixMilli(),
		FindingType:   pb.FindingType_FINDING_TYPE_ANOMALY,
		Severity:      pb.Severity_SEVERITY_MEDIUM,
		Confidence:    0.4, // Lower confidence without ML
		Description:   "Heuristic anomaly detected (ML unavailable); manual review recommended",
		SubjectNodeId: subject.NodeId,
		Metadata:      map[string]string{"ml_available": "false"},
	}}
}

// pickSubjectNode selects the most analytically interesting node.
func pickSubjectNode(nodes []*pb.GraphNode) *pb.GraphNode {
	priority := map[pb.NodeType]int{
		pb.NodeType_NODE_TYPE_DATA_ASSET:     3,
		pb.NodeType_NODE_TYPE_NETWORK_SOCKET: 2,
		pb.NodeType_NODE_TYPE_PROCESS:        1,
	}
	var best *pb.GraphNode
	bestPrio := -1
	for _, n := range nodes {
		p := priority[n.NodeType]
		if p > bestPrio {
			bestPrio = p
			best = n
		}
	}
	if best == nil && len(nodes) > 0 {
		return nodes[0]
	}
	return best
}

// extractObservedTechniques infers MITRE ATT&CK technique hints from graph topology.
// PROTOTYPE NOTE: this is a heuristic mapping, not a real technique classifier.
func extractObservedTechniques(delta *pb.GraphDelta) []string {
	var techniques []string
	for _, n := range delta.UpsertedNodes {
		switch n.NodeType {
		case pb.NodeType_NODE_TYPE_NETWORK_SOCKET:
			techniques = append(techniques, "T1071") // Application Layer Protocol
		case pb.NodeType_NODE_TYPE_DATA_ASSET:
			if n.Properties["asset.sensitivity"] == "crown_jewel" {
				techniques = append(techniques, "T1005") // Data from Local System
			}
		}
	}
	for _, e := range delta.UpsertedEdges {
		if e.EdgeType == pb.EdgeType_EDGE_TYPE_ASSUMES_ROLE {
			techniques = append(techniques, "T1078") // Valid Accounts
		}
	}
	return techniques
}

func scoreToProbSeverity(score float64) pb.Severity {
	switch {
	case score >= 0.85:
		return pb.Severity_SEVERITY_CRITICAL
	case score >= 0.70:
		return pb.Severity_SEVERITY_HIGH
	case score >= 0.55:
		return pb.Severity_SEVERITY_MEDIUM
	default:
		return pb.Severity_SEVERITY_LOW
	}
}

func isExternalIP(ip string) bool {
	// Simple heuristic: RFC1918 private ranges = internal.
	privateRanges := []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.", "127.", "::1"}
	for _, r := range privateRanges {
		if len(ip) >= len(r) && ip[:len(r)] == r {
			return false
		}
	}
	return ip != "" && ip != "0.0.0.0"
}

// =============================================================================
// IdentityAgent — rule-based insider threat agent
// =============================================================================

// IdentityAgent subscribes only to PRINCIPAL, CREDENTIAL, and ASSUMES_ROLE.
// It uses rule-based statistical analysis (no GNN dependency), proving that
// not all agents need to be ML-heavy.
type IdentityAgent struct{}

// NewIdentityAgent creates the identity/insider threat agent.
func NewIdentityAgent() *IdentityAgent {
	return &IdentityAgent{}
}

// Identity declares narrow subscription: only PRINCIPAL, CREDENTIAL, ASSUMES_ROLE.
// This is the subscription enforced by the dispatcher for acceptance criterion 3.
func (a *IdentityAgent) Identity() *pb.AgentSubscription {
	return &pb.AgentSubscription{
		AgentId:      "identity-insider-v1",
		AgentName:    "Identity / Insider Threat Agent",
		AgentVersion: "1.0.0",
		Description:  "Rule-based detection of identity anomalies: privilege escalation, unusual role assumptions, repeated auth failures.",
		SubscribedNodeTypes: []pb.NodeType{
			pb.NodeType_NODE_TYPE_PRINCIPAL,
			pb.NodeType_NODE_TYPE_CREDENTIAL,
		},
		SubscribedEdgeTypes: []pb.EdgeType{
			pb.EdgeType_EDGE_TYPE_ASSUMES_ROLE,
		},
	}
}

// HealthCheck always returns nil for the rule-based agent.
func (a *IdentityAgent) HealthCheck(_ context.Context) error { return nil }

// Analyze applies rule-based heuristics to detect identity anomalies.
func (a *IdentityAgent) Analyze(_ context.Context, req *pb.AgentRequest) ([]*pb.AgentFinding, error) {
	if req.ScopedDelta == nil {
		return nil, nil
	}

	var findings []*pb.AgentFinding

	// Rule 1: Privilege escalation detected in edge metadata or node type.
	for _, n := range req.ScopedDelta.UpsertedNodes {
		if n.NodeType == pb.NodeType_NODE_TYPE_PRINCIPAL {
			// Check for suspicious credential access patterns.
			for _, e := range req.ScopedDelta.UpsertedEdges {
				if e.EdgeType == pb.EdgeType_EDGE_TYPE_ASSUMES_ROLE &&
					e.SrcNodeId == n.NodeId &&
					e.Properties["success"] == "false" {
					findings = append(findings, &pb.AgentFinding{
						FindingId:     uuid.NewString(),
						RequestId:     req.RequestId,
						AgentId:       "identity-insider-v1",
						TimestampMs:   time.Now().UnixMilli(),
						FindingType:   pb.FindingType_FINDING_TYPE_IDENTITY_ANOMALY,
						Severity:      pb.Severity_SEVERITY_MEDIUM,
						Confidence:    0.72,
						Description:   fmt.Sprintf("Failed role assumption by principal %s", n.NodeId),
						SubjectNodeId: n.NodeId,
						EvidenceNodeIds: []string{n.NodeId, e.DstNodeId},
						EvidenceEdgeIds: []string{e.EdgeId},
						Metadata: map[string]string{
							"rule":       "failed_role_assumption",
							"credential": e.DstNodeId,
						},
					})
				}
			}
		}
	}

	// Rule 2: Credential with admin target resource = elevated privilege use.
	for _, n := range req.ScopedDelta.UpsertedNodes {
		if n.NodeType == pb.NodeType_NODE_TYPE_CREDENTIAL {
			target := n.Properties["credential.target"]
			if isAdminResource(target) {
				findings = append(findings, &pb.AgentFinding{
					FindingId:     uuid.NewString(),
					RequestId:     req.RequestId,
					AgentId:       "identity-insider-v1",
					TimestampMs:   time.Now().UnixMilli(),
					FindingType:   pb.FindingType_FINDING_TYPE_IDENTITY_ANOMALY,
					Severity:      pb.Severity_SEVERITY_HIGH,
					Confidence:    0.78,
					Description:   fmt.Sprintf("Credential %s used to access admin resource: %s", n.NodeId, target),
					SubjectNodeId: n.NodeId,
					EvidenceNodeIds: []string{n.NodeId},
					Metadata: map[string]string{
						"rule":            "admin_resource_access",
						"target_resource": target,
					},
				})
			}
		}
	}

	return findings, nil
}

func isAdminResource(resource string) bool {
	adminPatterns := []string{"admin$", "Admin", "\\admin", "/admin", "root", "sudo", "wheel"}
	for _, p := range adminPatterns {
		if len(resource) >= len(p) {
			for i := 0; i <= len(resource)-len(p); i++ {
				if resource[i:i+len(p)] == p {
					return true
				}
			}
		}
	}
	return false
}
