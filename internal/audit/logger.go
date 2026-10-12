// Package audit provides an append-only structured audit log.
//
// Every ingestion, finding, state transition, and approval decision generates
// an AuditEvent. The audit log must never be modified after write.
//
// Implementation: JSONL file with one AuditEvent per line. The file is opened
// in O_APPEND|O_CREATE|O_WRONLY mode; writes are serialized by a mutex.
// This satisfies the append-only requirement at the OS level for a single-node
// prototype.
//
// Future: a production implementation would use a write-once distributed log
// (e.g., Apache Kafka with topic retention) behind the same Logger interface.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/domain"
)

// Event is the append-only record of every significant platform action.
// Mirrors proto AuditEvent exactly.
type Event struct {
	AuditID       string                `json:"audit_id"`
	TimestampMs   int64                 `json:"timestamp_ms"`
	CorrelationID string                `json:"correlation_id"`
	RequestID     string                `json:"request_id"`
	Category      domain.AuditCategory  `json:"category"`
	Actor         string                `json:"actor"`
	Action        string                `json:"action"`
	Outcome       string                `json:"outcome"` // "success", "failure", "rejected", "pending", "expired"
	Detail        map[string]any        `json:"detail,omitempty"`
	SubjectNodeID string                `json:"subject_node_id,omitempty"`
	FindingID     string                `json:"finding_id,omitempty"`
	ProposalID    string                `json:"proposal_id,omitempty"`
	AuthRequestID string                `json:"auth_request_id,omitempty"`
}

// Logger writes AuditEvents to an append-only JSONL file.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	log  zerolog.Logger
}

// NewLogger opens (or creates) the audit log at the given path.
// The file is opened in append-only mode. Returns an error if the file
// cannot be opened.
func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log file %q: %w", path, err)
	}
	return &Logger{
		file: f,
		log:  log.With().Str("component", "audit").Logger(),
	}, nil
}

// Log writes an AuditEvent to the append-only log.
// This method is goroutine-safe. It never modifies an existing entry.
func (l *Logger) Log(event Event) error {
	if event.AuditID == "" {
		event.AuditID = uuid.NewString()
	}
	if event.TimestampMs == 0 {
		event.TimestampMs = time.Now().UnixMilli()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write the JSON line followed by a newline.
	// The lock ensures no two goroutines interleave their writes.
	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("audit: write event: %w", err)
	}

	l.log.Debug().
		Str("audit_id", event.AuditID).
		Str("category", string(event.Category)).
		Str("action", event.Action).
		Str("outcome", event.Outcome).
		Msg("audit event written")

	return nil
}

// Close flushes and closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// Builder is a fluent builder for AuditEvent.
type Builder struct {
	event Event
}

// NewEvent starts building an AuditEvent.
func NewEvent(category domain.AuditCategory, actor, action string) *Builder {
	return &Builder{
		event: Event{
			AuditID:   uuid.NewString(),
			Category:  category,
			Actor:     actor,
			Action:    action,
			Outcome:   "success",
		},
	}
}

func (b *Builder) CorrelationID(id string) *Builder { b.event.CorrelationID = id; return b }
func (b *Builder) RequestID(id string) *Builder      { b.event.RequestID = id; return b }
func (b *Builder) Outcome(o string) *Builder          { b.event.Outcome = o; return b }
func (b *Builder) Detail(d map[string]any) *Builder   { b.event.Detail = d; return b }
func (b *Builder) SubjectNode(id string) *Builder     { b.event.SubjectNodeID = id; return b }
func (b *Builder) FindingID(id string) *Builder       { b.event.FindingID = id; return b }
func (b *Builder) ProposalID(id string) *Builder      { b.event.ProposalID = id; return b }
func (b *Builder) AuthRequestID(id string) *Builder   { b.event.AuthRequestID = id; return b }

// Build returns the constructed AuditEvent.
func (b *Builder) Build() Event { return b.event }
