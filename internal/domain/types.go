// Package domain defines the core data types shared across all Go packages.
//
// These types mirror the protobuf contract in proto/kaaladrishti/v1/platform.proto
// exactly. Any divergence between these types and the proto schema must be
// treated as a bug and called out explicitly.
//
// Design rationale: maintaining a separate domain model (rather than using
// protobuf-generated types throughout) keeps business logic independent of
// wire format details and makes the protobuf boundary explicit.
package domain

import (
	"fmt"
	"time"
)

// NodeType enumerates the entity classes in the enterprise graph.
// Mirrors proto NodeType enum.
type NodeType int32

const (
	NodeTypeUnspecified   NodeType = 0
	NodeTypePrincipal     NodeType = 1
	NodeTypeCredential    NodeType = 2
	NodeTypeHost          NodeType = 3
	NodeTypeProcess       NodeType = 4
	NodeTypeModule        NodeType = 5
	NodeTypeNetworkSocket NodeType = 6
	NodeTypeDataAsset     NodeType = 7
	// NodeTypeRegistryKey: extension beyond synopsis's explicit list.
	// Added for Windows-host realism. See docs/architecture/graph_schema.md.
	NodeTypeRegistryKey  NodeType = 8
	NodeTypeCloudResource NodeType = 9
	NodeTypeIntent             NodeType = 10
	NodeTypeAgentPlan          NodeType = 11
	NodeTypeWorkflowExecution  NodeType = 12
	NodeTypeAction             NodeType = 13
	NodeTypeTool               NodeType = 14
	NodeTypeToolCall           NodeType = 15
	NodeTypeContextArtifact    NodeType = 16
	NodeTypeMemoryEntry        NodeType = 17
	NodeTypeAuthorization      NodeType = 18
	NodeTypeFinding            NodeType = 19
)

// String returns the human-readable name of a NodeType.
func (n NodeType) String() string {
	names := map[NodeType]string{
		NodeTypeUnspecified:   "UNSPECIFIED",
		NodeTypePrincipal:     "PRINCIPAL",
		NodeTypeCredential:    "CREDENTIAL",
		NodeTypeHost:          "HOST",
		NodeTypeProcess:       "PROCESS",
		NodeTypeModule:        "MODULE",
		NodeTypeNetworkSocket: "NETWORK_SOCKET",
		NodeTypeDataAsset:     "DATA_ASSET",
		NodeTypeRegistryKey:   "REGISTRY_KEY",
		NodeTypeCloudResource: "CLOUD_RESOURCE",
		NodeTypeIntent:             "INTENT",
		NodeTypeAgentPlan:          "AGENT_PLAN",
		NodeTypeWorkflowExecution:  "WORKFLOW_EXECUTION",
		NodeTypeAction:             "ACTION",
		NodeTypeTool:               "TOOL",
		NodeTypeToolCall:           "TOOL_CALL",
		NodeTypeContextArtifact:    "CONTEXT_ARTIFACT",
		NodeTypeMemoryEntry:        "MEMORY_ENTRY",
		NodeTypeAuthorization:      "AUTHORIZATION",
		NodeTypeFinding:            "FINDING",
	}
	if name, ok := names[n]; ok {
		return name
	}
	return fmt.Sprintf("NodeType(%d)", int32(n))
}

// EdgeType enumerates the relationship classes in the enterprise graph.
// Mirrors proto EdgeType enum.
type EdgeType int32

const (
	EdgeTypeUnspecified EdgeType = 0
	EdgeTypeAssumesRole EdgeType = 1
	EdgeTypeSpawned     EdgeType = 2
	EdgeTypeConnectsTo  EdgeType = 3
	EdgeTypeLoads       EdgeType = 4
	EdgeTypeReads       EdgeType = 5
	EdgeTypeWrites      EdgeType = 6
	EdgeTypeHasPermission EdgeType = 7
	EdgeTypeExposes       EdgeType = 8
	EdgeTypeTrusts        EdgeType = 9
	EdgeTypeDependsOn     EdgeType = 10
	EdgeTypeAccesses      EdgeType = 11
	EdgeTypeInitiatedBy    EdgeType = 12
	EdgeTypeAuthorizedBy   EdgeType = 13
	EdgeTypeExecutedBy     EdgeType = 14
	EdgeTypeHasIntent      EdgeType = 15
	EdgeTypeHasPlan        EdgeType = 16
	EdgeTypeDerivedFrom    EdgeType = 17
	EdgeTypePerforms       EdgeType = 18
	EdgeTypeInvokes        EdgeType = 19
	EdgeTypeInfluences     EdgeType = 20
	EdgeTypeDelegatesTo    EdgeType = 21
	EdgeTypeFollows        EdgeType = 22
	EdgeTypeDeviatesFrom   EdgeType = 23
	EdgeTypeAffects        EdgeType = 24
	EdgeTypeProduces       EdgeType = 25
	EdgeTypeReferences     EdgeType = 26
)

// String returns the human-readable name of an EdgeType.
func (e EdgeType) String() string {
	names := map[EdgeType]string{
		EdgeTypeUnspecified: "UNSPECIFIED",
		EdgeTypeAssumesRole: "ASSUMES_ROLE",
		EdgeTypeSpawned:     "SPAWNED",
		EdgeTypeConnectsTo:  "CONNECTS_TO",
		EdgeTypeLoads:       "LOADS",
		EdgeTypeReads:       "READS",
		EdgeTypeWrites:      "WRITES",
		EdgeTypeHasPermission: "HAS_PERMISSION",
		EdgeTypeExposes:       "EXPOSES",
		EdgeTypeTrusts:        "TRUSTS",
		EdgeTypeDependsOn:     "DEPENDS_ON",
		EdgeTypeAccesses:      "ACCESSES",
		EdgeTypeInitiatedBy:    "INITIATED_BY",
		EdgeTypeAuthorizedBy:   "AUTHORIZED_BY",
		EdgeTypeExecutedBy:     "EXECUTED_BY",
		EdgeTypeHasIntent:      "HAS_INTENT",
		EdgeTypeHasPlan:        "HAS_PLAN",
		EdgeTypeDerivedFrom:    "DERIVED_FROM",
		EdgeTypePerforms:       "PERFORMS",
		EdgeTypeInvokes:        "INVOKES",
		EdgeTypeInfluences:     "INFLUENCES",
		EdgeTypeDelegatesTo:    "DELEGATES_TO",
		EdgeTypeFollows:        "FOLLOWS",
		EdgeTypeDeviatesFrom:   "DEVIATES_FROM",
		EdgeTypeAffects:        "AFFECTS",
		EdgeTypeProduces:       "PRODUCES",
		EdgeTypeReferences:     "REFERENCES",
	}
	if name, ok := names[e]; ok {
		return name
	}
	return fmt.Sprintf("EdgeType(%d)", int32(e))
}

// Node is a typed, metadata-bearing entity in the enterprise graph.
type Node struct {
	ID           string
	Type         NodeType
	Label        string
	TimestampMs  int64
	Confidence   float64 // [0.0, 1.0]
	RecencyDecay float64 // multiplied by decay factor per interval
	Provenance   string  // source event_id or "synthetic"
	Properties   map[string]string
}

// LastSeen returns the node's last-seen time as a time.Time.
func (n *Node) LastSeen() time.Time {
	return time.UnixMilli(n.TimestampMs)
}

// DecayClass classifies an edge for decay behavior.
type DecayClass int32

const (
	DecayClassBehavioral DecayClass = 0
	DecayClassBaseline   DecayClass = 1
)

// Edge is a directed, metadata-bearing relationship between two nodes.
type Edge struct {
	ID           string  // "{src}:{type}:{dst}"
	SrcNodeID    string
	DstNodeID    string
	Type         EdgeType
	TimestampMs  int64
	Confidence   float64
	RecencyDecay float64
	Provenance   string
	Properties   map[string]string
	IsBaseline   bool
	DecayClass   DecayClass
}

// EdgeID constructs the stable edge identifier.
func EdgeID(srcID string, edgeType EdgeType, dstID string) string {
	return fmt.Sprintf("%s:%s:%s", srcID, edgeType, dstID)
}

// Subgraph is a set of nodes and edges returned by a graph query.
type Subgraph struct {
	Nodes []*Node
	Edges []*Edge
}

// SubgraphFilter specifies the criteria for a graph query.
type SubgraphFilter struct {
	// NodeTypes restricts returned nodes. Empty means all types.
	NodeTypes []NodeType
	// EdgeTypes restricts returned edges. Empty means all types.
	EdgeTypes []EdgeType
	// SinceMs restricts to nodes/edges last seen after this timestamp.
	SinceMs int64
	// MinConfidence filters out low-confidence entities.
	MinConfidence float64
	// WorkflowID enforces strict server-side scoping.
	WorkflowID string
	// MaxDepth restricts search depth for workflow scoping.
	MaxDepth int
}

// FindingType classifies the nature of an agent's finding.
type FindingType int32

const (
	FindingTypeUnspecified        FindingType = 0
	FindingTypeAnomaly            FindingType = 1
	FindingTypeBlastRadius        FindingType = 2
	FindingTypeNextAttackForecast FindingType = 3
	FindingTypeIdentityAnomaly    FindingType = 4
	FindingTypeDriftDetected      FindingType = 5
	FindingTypeCloudMisconfiguration FindingType = 6
)

// Severity maps to dashboard alert level and governance confidence gating.
type Severity int32

const (
	SeverityUnspecified Severity = 0
	SeverityInfo        Severity = 1
	SeverityLow         Severity = 2
	SeverityMedium      Severity = 3
	SeverityHigh        Severity = 4
	SeverityCritical    Severity = 5
)

// String returns a human-readable severity name.
func (s Severity) String() string {
	names := map[Severity]string{
		SeverityUnspecified: "UNSPECIFIED",
		SeverityInfo:        "INFO",
		SeverityLow:         "LOW",
		SeverityMedium:      "MEDIUM",
		SeverityHigh:        "HIGH",
		SeverityCritical:    "CRITICAL",
	}
	if name, ok := names[s]; ok {
		return name
	}
	return fmt.Sprintf("Severity(%d)", int32(s))
}

// ActionType classifies the proposed defensive action.
type ActionType int32

const (
	ActionTypeUnspecified         ActionType = 0
	ActionTypeMTDNetworkReroute   ActionType = 1
	ActionTypeMTDCredentialRotate ActionType = 2
	ActionTypeDeceptionHoneycred  ActionType = 3
	ActionTypeDeceptionHoneyshare ActionType = 4
	ActionTypeIsolateHost         ActionType = 5
	ActionTypeRevokeSession       ActionType = 6
	ActionTypeRestrictPublicAccess ActionType = 7
	ActionTypeReducePermission     ActionType = 8
	ActionTypeIsolateResource      ActionType = 9
)

// GovernanceState represents a state in the response governance FSM.
type GovernanceState string

const (
	StateObserved                GovernanceState = "OBSERVED"
	StateAnalyzing               GovernanceState = "ANALYZING"
	StateFinding                 GovernanceState = "FINDING"
	StateResponseProposed        GovernanceState = "RESPONSE_PROPOSED"
	StateConfidenceCheck         GovernanceState = "CONFIDENCE_CHECK"
	StateHumanApprovalRequired   GovernanceState = "HUMAN_APPROVAL_REQUIRED"
	StateApproved                GovernanceState = "APPROVED"
	StateDenied                  GovernanceState = "DENIED"
	StateSimulatedExecution      GovernanceState = "SIMULATED_EXECUTION"
	StateAudited                 GovernanceState = "AUDITED"
)

// AuditCategory classifies the source subsystem of an audit event.
type AuditCategory string

const (
	AuditCategoryIngestion     AuditCategory = "INGESTION"
	AuditCategoryGraph         AuditCategory = "GRAPH"
	AuditCategoryDispatch      AuditCategory = "DISPATCH"
	AuditCategoryFinding       AuditCategory = "FINDING"
	AuditCategoryGovernance    AuditCategory = "GOVERNANCE"
	AuditCategoryResponse      AuditCategory = "RESPONSE"
	AuditCategoryAuthorization AuditCategory = "AUTHORIZATION"
	AuditCategorySystem        AuditCategory = "SYSTEM"
)
