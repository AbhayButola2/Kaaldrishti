// Package domain — graph delta type.
//
// This file defines GraphDelta, which is the incremental change notification
// produced by the ingestion layer and consumed by the AgentDispatcher.
package domain

// GraphDelta carries incremental changes to the graph.
// Produced by the ingestion layer after processing a TelemetryEvent;
// consumed by the AgentDispatcher to route scoped updates to agents.
type GraphDelta struct {
	DeltaID       string
	TimestampMs   int64
	SourceEventID string // Causal TelemetryEvent ID
	UpsertedNodes []*Node
	UpsertedEdges []*Edge
	RemovedNodeIDs []string
	RemovedEdgeIDs []string
}
