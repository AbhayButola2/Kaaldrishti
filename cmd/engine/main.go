// cmd/engine/main.go — Kaaladrishti engine entrypoint.
//
// Wires together all subsystems:
//   Config → Graph → Ingestion → IPC(UDS) → Dispatcher → Agents
//   → Orchestration → Governance FSM → Audit → API/Dashboard
//
// Graceful shutdown: SIGINT/SIGTERM cancel the root context; all subsystems
// drain within their shutdown timeout before the process exits.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/agents"
	"github.com/kaaladrishti/engine/internal/api"
	"github.com/kaaladrishti/engine/internal/audit"
	"github.com/kaaladrishti/engine/internal/config"
	"github.com/kaaladrishti/engine/internal/dispatcher"
	"github.com/kaaladrishti/engine/internal/governance"
	"github.com/kaaladrishti/engine/internal/graph"
	"github.com/kaaladrishti/engine/internal/ingestion"
	"github.com/kaaladrishti/engine/internal/ipc"
	"github.com/kaaladrishti/engine/internal/ml"
	"github.com/kaaladrishti/engine/internal/orchestration"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

func main() {
	// Structured JSON logging.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	log.Info().Str("component", "engine").Msg("Kaaladrishti engine starting")

	// 1. Load configuration.
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}
	log.Info().
		Str("uds_path", cfg.UDSPath).
		Str("ml_addr", cfg.MLGRPCAddr).
		Str("api_addr", cfg.APIAddr).
		Msg("configuration loaded")

	// 2. Initialize audit logger.
	auditLog, err := audit.NewLogger(cfg.AuditLogPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open audit log")
	}
	defer auditLog.Close()

	// 3. Initialize graph store and load snapshot.
	graphStore := graph.NewInMemoryGraphStore(cfg.GraphDBPath)
	ctx := context.Background()
	if err := graphStore.Load(ctx); err != nil {
		log.Warn().Err(err).Msg("graph snapshot load failed; starting with empty graph")
	}

	// 4. Start decay timer.
	go runDecayCycle(ctx, graphStore, cfg)

	// 5. Initialize ML client (lazy connect — Python service may not be up yet).
	mlClient := ml.NewClientLazy(cfg.MLGRPCAddr, cfg.MLCallTimeout)
	defer mlClient.Close()

	// 6. Initialize governance FSM.
	fsm := governance.NewStateMachine(cfg.ProposalConfidence, cfg.ApprovalExpiry, auditLog)

	// 7. Initialize orchestration correlator.
	correlator := orchestration.NewCorrelator(cfg.CorrelationWindow, fsm)

	// 8. Initialize dispatcher and register agents.
	disp := dispatcher.NewDispatcher(8, cfg.AgentTimeout)
	disp.Register(agents.NewBlastRadiusAgent(mlClient))
	disp.Register(agents.NewIdentityAgent())
	disp.Register(agents.NewZeroDayAgent("http://127.0.0.1:8000"))
	disp.Register(agents.NewCloudSecurityAgent(mlClient))
	disp.Register(agents.NewIntentLineageAgent(mlClient))

	// 9. Initialize ingestion validator.
	validator := ingestion.NewValidator(graphStore, auditLog)

	// 10. IPC event handler: validate → graph → dispatch → correlate.
	eventHandler := func(ctx context.Context, event *pb.TelemetryEvent) error {
		delta, err := validator.ProcessEvent(ctx, event)
		if err != nil {
			log.Error().Err(err).Str("event_id", event.EventId).Msg("ingestion error")
			return nil // Don't propagate; one bad event must not break the loop.
		}
		if delta == nil {
			return nil // Rejected event.
		}

		// Dispatch to all subscribed agents.
		findings, err := disp.Dispatch(ctx, event.EventId, delta)
		if err != nil {
			log.Error().Err(err).Msg("dispatch error")
			return nil
		}

		// Submit findings to correlator → FSM.
		for _, f := range findings {
			if err := correlator.Submit(ctx, f); err != nil {
				log.Error().Err(err).Str("finding_id", f.FindingId).Msg("correlator error")
			}
		}
		return nil
	}

	// 11. Initialize UDS listener.
	udsListener := ipc.NewUDSListener(cfg.UDSPath, eventHandler)

	// 12. Initialize API server.
	apiServer := api.NewServer(fsm, disp, graphStore)

	// 13. Root context with graceful shutdown.
	rootCtx, rootCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer rootCancel()

	// 14. Snapshot timer — periodically persist the graph.
	go runSnapshotTimer(rootCtx, graphStore)

	// 15. Start UDS listener in background.
	go func() {
		if err := udsListener.Start(rootCtx); err != nil {
			log.Error().Err(err).Msg("UDS listener error")
		}
	}()

	// 16. Start API server in background.
	go func() {
		if err := apiServer.Run(rootCtx, cfg.APIAddr); err != nil {
			log.Error().Err(err).Msg("API server error")
		}
	}()

	log.Info().Str("dashboard", "http://localhost"+cfg.APIAddr).Msg("Kaaladrishti engine running")

	// Wait for shutdown signal.
	<-rootCtx.Done()
	log.Info().Msg("shutdown signal received; draining...")

	// Final snapshot on shutdown.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := graphStore.Snapshot(shutCtx); err != nil {
		log.Error().Err(err).Msg("final snapshot failed")
	}

	log.Info().Msg("Kaaladrishti engine stopped")
}

func runDecayCycle(ctx context.Context, store graph.GraphStore, cfg *config.Config) {
	ticker := time.NewTicker(cfg.DecayInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.ApplyDecay(ctx, cfg.DecayFactor, 0.01); err != nil {
				log.Error().Err(err).Msg("decay cycle error")
			}
		}
	}
}

func runSnapshotTimer(ctx context.Context, store graph.GraphStore) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := store.Snapshot(snapCtx); err != nil {
				log.Error().Err(err).Msg("periodic snapshot failed")
			}
			cancel()
		}
	}
}
