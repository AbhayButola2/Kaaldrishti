// Package config handles configuration loading from environment variables.
//
// Security requirement: no hardcoded credentials or secrets anywhere in the codebase.
// All sensitive configuration is read from environment variables or files at startup.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the Kaaladrishti engine.
// All fields have safe defaults; nothing requires mandatory configuration
// for a development run.
type Config struct {
	// UDSPath is the Unix Domain Socket path for Rust → Go telemetry.
	// Default: /tmp/kaaladrishti.sock (configurable for Windows)
	UDSPath string

	// MLGRPCAddr is the gRPC address of the Python ML analytics service.
	// Default: localhost:50051
	MLGRPCAddr string

	// GraphDBPath is the BoltDB file path for graph snapshot persistence.
	// Default: kaaladrishti_graph.db
	GraphDBPath string

	// APIAddr is the HTTP listen address for the REST/WebSocket API.
	// Default: :8080
	APIAddr string

	// AuditLogPath is the append-only JSONL audit log file path.
	// Default: kaaladrishti_audit.jsonl
	AuditLogPath string

	// ProposalConfidence is the minimum confidence to generate a ResponseProposal.
	// Default: 0.65
	ProposalConfidence float64

	// AgentTimeout is the per-agent analysis deadline.
	// Default: 10s
	AgentTimeout time.Duration

	// DecayFactor is multiplied into recency_decay on each decay cycle.
	// Default: 0.95
	DecayFactor float64

	// DecayInterval is how often the decay cycle runs.
	// Default: 60s
	DecayInterval time.Duration

	// ApprovalExpiry is how long before an unresponded AuthorizationRequest auto-expires.
	// Default: 30min
	ApprovalExpiry time.Duration

	// CorrelationWindow is the time window for cross-agent incident correlation.
	// Default: 5min
	CorrelationWindow time.Duration

	// MLDialTimeout is the timeout for the initial gRPC dial to the Python ML service.
	// Default: 5s
	MLDialTimeout time.Duration

	// MLCallTimeout is the per-RPC deadline for ML service calls.
	// Default: 8s
	MLCallTimeout time.Duration
}

// Load reads configuration from environment variables, applying defaults for
// any unset variables. Returns an error only if a set variable is malformed.
func Load() (*Config, error) {
	cfg := &Config{
		UDSPath:           envOrDefault("KAALADRISHTI_UDS_PATH", "127.0.0.1:9090"),
		MLGRPCAddr:        envOrDefault("KAALADRISHTI_ML_GRPC_ADDR", "localhost:50051"),
		GraphDBPath:       envOrDefault("KAALADRISHTI_GRAPH_DB_PATH", "kaaladrishti_graph.db"),
		APIAddr:           envOrDefault("KAALADRISHTI_API_ADDR", ":8080"),
		AuditLogPath:      envOrDefault("KAALADRISHTI_AUDIT_LOG_PATH", "kaaladrishti_audit.jsonl"),
		AgentTimeout:      10 * time.Second,
		DecayInterval:     60 * time.Second,
		ApprovalExpiry:    30 * time.Minute,
		CorrelationWindow: 5 * time.Minute,
		MLDialTimeout:     5 * time.Second,
		MLCallTimeout:     8 * time.Second,
		ProposalConfidence: 0.65,
		DecayFactor:        0.95,
	}

	var err error

	if v := os.Getenv("KAALADRISHTI_PROPOSAL_CONFIDENCE"); v != "" {
		cfg.ProposalConfidence, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("KAALADRISHTI_PROPOSAL_CONFIDENCE: %w", err)
		}
	}

	if v := os.Getenv("KAALADRISHTI_DECAY_FACTOR"); v != "" {
		cfg.DecayFactor, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("KAALADRISHTI_DECAY_FACTOR: %w", err)
		}
	}

	if v := os.Getenv("KAALADRISHTI_AGENT_TIMEOUT"); v != "" {
		cfg.AgentTimeout, err = time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("KAALADRISHTI_AGENT_TIMEOUT: %w", err)
		}
	}

	if v := os.Getenv("KAALADRISHTI_DECAY_INTERVAL"); v != "" {
		cfg.DecayInterval, err = time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("KAALADRISHTI_DECAY_INTERVAL: %w", err)
		}
	}

	if v := os.Getenv("KAALADRISHTI_APPROVAL_EXPIRY"); v != "" {
		cfg.ApprovalExpiry, err = time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("KAALADRISHTI_APPROVAL_EXPIRY: %w", err)
		}
	}

	if v := os.Getenv("KAALADRISHTI_CORRELATION_WINDOW"); v != "" {
		cfg.CorrelationWindow, err = time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("KAALADRISHTI_CORRELATION_WINDOW: %w", err)
		}
	}

	return cfg, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
