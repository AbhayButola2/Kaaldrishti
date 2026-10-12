// Package ml provides the Go-side gRPC client for the Python ML analytics service.
//
// The client wraps all five MLAnalyticsService RPCs. It is the only component
// that calls Python — no agent or governance code calls Python directly.
//
// Failure isolation: if the Python service is unavailable, all methods return
// a structured error. The caller (agent or governance layer) must handle this
// gracefully and fall back to rule-based analysis. The Go core never blocks
// or crashes due to Python unavailability.
package ml

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// Client wraps the MLAnalyticsService gRPC client.
type Client struct {
	conn   *grpc.ClientConn
	svc    pb.MLAnalyticsServiceClient
	timeout time.Duration
}

// NewClient dials the ML service at addr. Does not block on connection.
// The connection is lazy; it will be established on the first RPC call.
func NewClient(addr string, dialTimeout time.Duration, callTimeout time.Duration) (*Client, error) {
	// PROTOTYPE NOTE: using insecure credentials on localhost.
	// Production: replace with grpc.WithTransportCredentials(credentials.NewTLS(...))
	// See docs/architecture/deferred_work.md.
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, //nolint:staticcheck // DialContext is fine for prototype
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("ml: dial %q: %w", addr, err)
	}

	return &Client{
		conn:    conn,
		svc:     pb.NewMLAnalyticsServiceClient(conn),
		timeout: callTimeout,
	}, nil
}

// NewClientLazy returns a client that does NOT block waiting for the service.
// Connection is established lazily on first RPC. Use this when the ML service
// may not be running at engine startup (acceptable for prototype).
func NewClientLazy(addr string, callTimeout time.Duration) *Client {
	conn, _ := grpc.Dial(addr, //nolint:staticcheck
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	return &Client{
		conn:    conn,
		svc:     pb.NewMLAnalyticsServiceClient(conn),
		timeout: callTimeout,
	}
}

// ScoreRisk calls the GNN-based risk scoring RPC.
// Returns a zero-value response and a descriptive error on ML unavailability.
func (c *Client) ScoreRisk(ctx context.Context, req *pb.RiskScoreRequest) (*pb.RiskScoreResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.svc.ScoreRisk(ctx, req)
	if err != nil {
		return nil, c.wrapRPCError("ScoreRisk", err)
	}
	return resp, nil
}

// ComputeBlastRadius calls the PPR/RWR blast-radius scoring RPC.
func (c *Client) ComputeBlastRadius(ctx context.Context, req *pb.RiskScoreRequest) (*pb.BlastRadius, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.svc.ComputeBlastRadius(ctx, req)
	if err != nil {
		return nil, c.wrapRPCError("ComputeBlastRadius", err)
	}
	return resp, nil
}

// ForecastNextAttack calls the Transformer/LSTM next-technique forecast RPC.
func (c *Client) ForecastNextAttack(ctx context.Context, req *pb.NextAttackForecastRequest) (*pb.NextAttackForecastResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.svc.ForecastNextAttack(ctx, req)
	if err != nil {
		return nil, c.wrapRPCError("ForecastNextAttack", err)
	}
	return resp, nil
}

// ScoreIntentLineage calls the cosine-distance intent drift scoring RPC.
func (c *Client) ScoreIntentLineage(ctx context.Context, req *pb.IntentLineageRequest) (*pb.IntentLineageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.svc.ScoreIntentLineage(ctx, req)
	if err != nil {
		return nil, c.wrapRPCError("ScoreIntentLineage", err)
	}
	return resp, nil
}

// EvaluateDrift calls the CUSUM/ADWIN drift detection RPC.
func (c *Client) EvaluateDrift(ctx context.Context, req *pb.DriftEvaluationRequest) (*pb.DriftEvaluationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.svc.EvaluateDrift(ctx, req)
	if err != nil {
		return nil, c.wrapRPCError("EvaluateDrift", err)
	}
	return resp, nil
}

// IsAvailable performs a lightweight health check by attempting a minimal RPC.
// Returns true if the ML service responds within the call timeout.
func (c *Client) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Minimal risk score request to probe availability.
	_, err := c.svc.ScoreRisk(ctx, &pb.RiskScoreRequest{
		RequestId:      "healthcheck",
		SubjectNodeId:  "probe",
	})
	if err != nil {
		log.Debug().Err(err).Msg("ml: service not available")
		return false
	}
	return true
}

// Close releases the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// wrapRPCError wraps a gRPC error with context for the caller.
func (c *Client) wrapRPCError(rpc string, err error) error {
	if s, ok := status.FromError(err); ok {
		log.Warn().
			Str("rpc", rpc).
			Str("grpc_code", s.Code().String()).
			Str("grpc_message", s.Message()).
			Msg("ml: RPC error (ML service may be unavailable)")
	}
	return fmt.Errorf("ml: %s: %w", rpc, err)
}
