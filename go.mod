module github.com/kaaladrishti/engine

go 1.25.0

require (
	// chi — lightweight HTTP router for REST + WebSocket API.
	// Justification: standard Go idiom, no reflection magic, composable middleware.
	github.com/go-chi/chi/v5 v5.0.12

	// google/uuid — UUIDv4 generation for IDs throughout the platform.
	github.com/google/uuid v1.6.0

	// gorilla/websocket — WebSocket upgrade for live dashboard feed.
	// Justification: most widely used, well-maintained WebSocket library for Go.
	github.com/gorilla/websocket v1.5.1

	// rs/zerolog — structured JSON logging with correlation ID support.
	// Justification: zero-allocation, JSON output, compatible with the audit log format.
	github.com/rs/zerolog v1.32.0

	// BoltDB — single-file embedded KV for graph snapshot persistence.
	// Justification: no CGo dependency, simpler cross-platform builds than SQLite.
	go.etcd.io/bbolt v1.3.9
	// protobuf + gRPC — cross-language contract; justified by three-language split
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require github.com/stretchr/testify v1.8.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
