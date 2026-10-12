// Package orchestration correlates findings from multiple agents into unified incidents.
//
// When two or more AgentFindings reference the same or adjacent graph entities
// within the correlation window, they are merged into a single CorrelatedIncident.
// This gives the SOC analyst one unified view instead of multiple related alerts.
package orchestration

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/governance"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// CorrelatedIncident is the result of merging related findings.
type CorrelatedIncident struct {
	ID            string
	CorrelationID string
	Findings      []*pb.AgentFinding
	CreatedAt     time.Time
}

// pending tracks findings waiting for correlation.
type pending struct {
	finding   *pb.AgentFinding
	timestamp time.Time
}

// Correlator groups related findings and routes correlated incidents to the governance FSM.
type Correlator struct {
	window  time.Duration
	fsm     *governance.StateMachine
	mu      sync.Mutex
	buffer  []*pending
}

// NewCorrelator creates a correlator with the given time window.
func NewCorrelator(window time.Duration, fsm *governance.StateMachine) *Correlator {
	return &Correlator{
		window: window,
		fsm:    fsm,
	}
}

// Submit adds a finding to the correlation buffer and triggers correlation.
func (c *Correlator) Submit(ctx context.Context, finding *pb.AgentFinding) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.buffer = append(c.buffer, &pending{finding: finding, timestamp: now})

	// Expire old entries outside the correlation window.
	cutoff := now.Add(-c.window)
	fresh := c.buffer[:0]
	for _, p := range c.buffer {
		if p.timestamp.After(cutoff) {
			fresh = append(fresh, p)
		}
	}
	c.buffer = fresh

	// Find findings that share subject nodes or evidence nodes with this new finding.
	related := c.findRelated(finding)

	var correlationID string
	if len(related) > 0 {
		// Reuse the correlation ID from the first related finding.
		correlationID = finding.RequestId // Use request_id prefix as correlation key.
		log.Info().
			Str("finding_id", finding.FindingId).
			Int("related_count", len(related)).
			Str("correlation_id", correlationID).
			Msg("orchestration: correlated findings merged")
	} else {
		correlationID = uuid.NewString()
	}

	return c.fsm.ProcessFinding(ctx, correlationID, finding)
}

// findRelated returns pending findings that share subject node or evidence nodes.
func (c *Correlator) findRelated(finding *pb.AgentFinding) []*pending {
	subjectSet := map[string]struct{}{finding.SubjectNodeId: {}}
	for _, nid := range finding.EvidenceNodeIds {
		subjectSet[nid] = struct{}{}
	}

	var related []*pending
	for _, p := range c.buffer {
		if p.finding.FindingId == finding.FindingId {
			continue // skip self
		}
		if _, ok := subjectSet[p.finding.SubjectNodeId]; ok {
			related = append(related, p)
			continue
		}
		for _, nid := range p.finding.EvidenceNodeIds {
			if _, ok := subjectSet[nid]; ok {
				related = append(related, p)
				break
			}
		}
	}
	return related
}
