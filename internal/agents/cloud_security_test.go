package agents

import (
	"context"
	"testing"

	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
	"github.com/stretchr/testify/assert"
)

func TestCloudSecurityAgent_Analyze_PublicExposure(t *testing.T) {
	// Setup deterministic agent (nil mlClient simulates unavailable ML)
	agent := NewCloudSecurityAgent(nil)
	
	req := &pb.AgentRequest{
		RequestId: "test-req-1",
		ScopedDelta: &pb.GraphDelta{
			UpsertedNodes: []*pb.GraphNode{
				{
					NodeId:   "cloud-resource-1",
					NodeType: pb.NodeType_NODE_TYPE_CLOUD_RESOURCE,
					Properties: map[string]string{
						"public_read": "true",
					},
				},
			},
		},
	}

	findings, err := agent.Analyze(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, pb.FindingType_FINDING_TYPE_CLOUD_MISCONFIGURATION, findings[0].FindingType)
	assert.Equal(t, pb.Severity_SEVERITY_HIGH, findings[0].Severity)
}

func TestCloudSecurityAgent_Analyze_ExcessivePermissions(t *testing.T) {
	agent := NewCloudSecurityAgent(nil)
	
	req := &pb.AgentRequest{
		RequestId: "test-req-2",
		ScopedDelta: &pb.GraphDelta{
			UpsertedNodes: []*pb.GraphNode{
				{
					NodeId:   "principal-1",
					NodeType: pb.NodeType_NODE_TYPE_PRINCIPAL,
				},
				{
					NodeId:   "cloud-resource-2",
					NodeType: pb.NodeType_NODE_TYPE_CLOUD_RESOURCE,
				},
			},
			UpsertedEdges: []*pb.GraphEdge{
				{
					EdgeId:    "edge-1",
					SrcNodeId: "principal-1",
					DstNodeId: "cloud-resource-2",
					EdgeType:  pb.EdgeType_EDGE_TYPE_HAS_PERMISSION,
					Properties: map[string]string{
						"permission": "*",
					},
				},
			},
		},
	}

	findings, err := agent.Analyze(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, pb.FindingType_FINDING_TYPE_CLOUD_MISCONFIGURATION, findings[0].FindingType)
	assert.Equal(t, pb.Severity_SEVERITY_MEDIUM, findings[0].Severity)
}

func TestCloudSecurityAgent_Analyze_ContextualCrownJewel(t *testing.T) {
	agent := NewCloudSecurityAgent(nil)
	
	req := &pb.AgentRequest{
		RequestId: "test-req-3",
		ScopedDelta: &pb.GraphDelta{
			UpsertedNodes: []*pb.GraphNode{
				{
					NodeId:   "cloud-resource-public",
					NodeType: pb.NodeType_NODE_TYPE_CLOUD_RESOURCE,
					Properties: map[string]string{
						"public_read": "true",
					},
				},
				{
					NodeId:   "data-asset-crown",
					NodeType: pb.NodeType_NODE_TYPE_DATA_ASSET,
					Properties: map[string]string{
						"asset.sensitivity": "crown_jewel",
					},
				},
			},
			UpsertedEdges: []*pb.GraphEdge{
				{
					EdgeId:    "edge-link",
					SrcNodeId: "cloud-resource-public",
					DstNodeId: "data-asset-crown",
					EdgeType:  pb.EdgeType_EDGE_TYPE_ACCESSES,
				},
			},
		},
	}

	findings, err := agent.Analyze(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, pb.FindingType_FINDING_TYPE_CLOUD_MISCONFIGURATION, findings[0].FindingType)
	assert.Equal(t, pb.Severity_SEVERITY_CRITICAL, findings[0].Severity) // Elevated severity due to crown jewel
}
