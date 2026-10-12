// Package api provides the REST + WebSocket API and serves the static dashboard.
//
// Endpoints:
//   GET  /api/health                     — component health
//   GET  /api/incidents                  — list all incidents
//   GET  /api/incidents/pending          — list incidents awaiting approval
//   POST /api/agents/{agentID}/invoke    — direct agent invocation
//   POST /api/approvals/{authRequestID}/decide — operator approval/denial
//   GET  /api/graph/stats                — graph node/edge counts
//   GET  /ws                             — WebSocket live feed
//   GET  /                               — dashboard static HTML
//
// The WebSocket feed pushes JSON-encoded StateEvent messages when the governance
// FSM changes state (new approval request, decision, etc.).
package api

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	"github.com/kaaladrishti/engine/internal/dispatcher"
	"github.com/kaaladrishti/engine/internal/domain"
	"github.com/kaaladrishti/engine/internal/governance"
	"github.com/kaaladrishti/engine/internal/graph"
	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

//go:embed static
var staticFiles embed.FS

// Server is the HTTP API and WebSocket server.
type Server struct {
	fsm        *governance.StateMachine
	dispatcher *dispatcher.Dispatcher
	store      graph.GraphStore
	upgrader   websocket.Upgrader

	wsClients   map[*websocket.Conn]struct{}
	wsClientsMu sync.Mutex
}

// NewServer creates the API server.
func NewServer(
	fsm *governance.StateMachine,
	disp *dispatcher.Dispatcher,
	store graph.GraphStore,
) *Server {
	return &Server{
		fsm:        fsm,
		dispatcher: disp,
		store:      store,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true }, // PROTOTYPE: allow all origins
		},
		wsClients: make(map[*websocket.Conn]struct{}),
	}
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// API routes.
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/incidents", s.handleListIncidents)
		r.Get("/incidents/pending", s.handlePendingApprovals)
		r.Post("/agents/{agentID}/invoke", s.handleInvokeAgent)
		r.Post("/approvals/{authRequestID}/decide", s.handleDecideApproval)
		r.Get("/graph/stats", s.handleGraphStats)

		// Proxy to Kaalform Agent Gateway (Pillars 4 & 5).
		kaalformTarget, _ := url.Parse("http://127.0.0.1:7070")
		kaalformProxy := httputil.NewSingleHostReverseProxy(kaalformTarget)
		r.Mount("/kaalform", http.StripPrefix("/api/kaalform", kaalformProxy))
	})

	// WebSocket.
	r.Get("/ws", s.handleWebSocket)

	// Static dashboard.
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal().Err(err).Msg("api: failed to sub static filesystem")
	}
	r.Handle("/*", http.FileServer(http.FS(staticFS)))

	return r
}

// Run starts the HTTP server and the FSM event broadcast loop.
func (s *Server) Run(ctx context.Context, addr string) error {
	// Start the FSM event broadcast goroutine.
	go s.broadcastFSMEvents(ctx)

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Info().Str("addr", addr).Msg("api: server starting")

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// --- REST handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"timestamp":  time.Now().UTC(),
		"node_count": s.store.NodeCount(),
		"edge_count": s.store.EdgeCount(),
	})
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	incidents := s.fsm.ListIncidents()
	respond(w, http.StatusOK, map[string]any{
		"incidents": incidents,
		"count":     len(incidents),
	})
}

func (s *Server) handlePendingApprovals(w http.ResponseWriter, r *http.Request) {
	pending := s.fsm.ListPendingApprovals()
	respond(w, http.StatusOK, map[string]any{
		"pending": pending,
		"count":   len(pending),
	})
}

func (s *Server) handleInvokeAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentID")
	// For manual invocations, create a minimal delta with all crown-jewel nodes.
	// PROTOTYPE NOTE: a real implementation would let the caller specify the subgraph.
	emptyDelta := &domain.GraphDelta{
		DeltaID:     uuid.NewString(),
		TimestampMs: time.Now().UnixMilli(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	findings, err := s.dispatcher.DispatchToAgent(ctx, agentID, emptyDelta)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	respond(w, http.StatusOK, map[string]any{
		"agent_id": agentID,
		"findings": findings,
		"count":    len(findings),
	})
}

func (s *Server) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	authRequestID := chi.URLParam(r, "authRequestID")

	var body struct {
		OperatorID string `json:"operator_id"`
		Approved   bool   `json:"approved"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.OperatorID == "" {
		http.Error(w, "operator_id is required", http.StatusBadRequest)
		return
	}

	decision := &pb.AuthorizationDecision{
		AuthRequestId: authRequestID,
		OperatorId:    body.OperatorID,
		TimestampMs:   time.Now().UnixMilli(),
		Approved:      body.Approved,
		Reason:        body.Reason,
	}

	if err := s.fsm.ApproveAction(r.Context(), decision); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	respond(w, http.StatusOK, map[string]any{
		"auth_request_id": authRequestID,
		"approved":        body.Approved,
		"status":          "decision recorded",
	})
}

func (s *Server) handleGraphStats(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]any{
		"node_count": s.store.NodeCount(),
		"edge_count": s.store.EdgeCount(),
		"timestamp":  time.Now().UTC(),
	})
}

// --- WebSocket ---

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("api: websocket upgrade failed")
		return
	}

	s.wsClientsMu.Lock()
	s.wsClients[conn] = struct{}{}
	s.wsClientsMu.Unlock()

	log.Debug().Str("remote", r.RemoteAddr).Msg("api: websocket client connected")

	// Keep connection alive; remove on close.
	defer func() {
		s.wsClientsMu.Lock()
		delete(s.wsClients, conn)
		s.wsClientsMu.Unlock()
		_ = conn.Close()
		log.Debug().Msg("api: websocket client disconnected")
	}()

	// Read loop — we don't expect client messages but must handle pings/close.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// broadcastFSMEvents reads from the FSM event channel and pushes to all WS clients.
func (s *Server) broadcastFSMEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-s.fsm.Events():
			if !ok {
				return
			}
			s.broadcast(event)
		}
	}
}

func (s *Server) broadcast(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Error().Err(err).Msg("api: failed to marshal broadcast message")
		return
	}

	s.wsClientsMu.Lock()
	defer s.wsClientsMu.Unlock()

	for conn := range s.wsClients {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Debug().Err(err).Msg("api: websocket write error; removing client")
			delete(s.wsClients, conn)
		}
	}
}

// respond writes a JSON response.
func respond(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Error().Err(err).Msg("api: response encode error")
	}
}
