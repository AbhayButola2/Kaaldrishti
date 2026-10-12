// Package ipc provides the Unix Domain Socket listener for the Go engine.
//
// The listener reads length-prefixed protobuf-encoded TelemetryEvent frames
// sent by the Rust telemetry-kernel, decodes them, and passes them to the
// ingestion layer.
//
// Framing protocol (agreed with Rust transport/mod.rs):
//   [4-byte big-endian uint32 length][protobuf bytes]
//
// Failure isolation:
//   - A malformed frame is logged and skipped; the listener continues.
//   - A connection close is logged; the listener waits for a new connection.
//   - The Go engine's ingestion loop is never blocked by a UDS failure.
package ipc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"github.com/rs/zerolog/log"

	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
)

// EventHandler is called with each decoded TelemetryEvent.
// It must be goroutine-safe and return quickly (non-blocking fan-out).
type EventHandler func(ctx context.Context, event *pb.TelemetryEvent) error

// UDSListener listens on a Unix Domain Socket for TelemetryEvent frames.
type UDSListener struct {
	socketPath  string
	handler     EventHandler
	listener    net.Listener
	mu          sync.Mutex
	wg          sync.WaitGroup
}

// NewUDSListener creates a listener that will call handler for each event.
func NewUDSListener(socketPath string, handler EventHandler) *UDSListener {
	return &UDSListener{
		socketPath: socketPath,
		handler:    handler,
	}
}

// Start binds the Unix Domain Socket and begins accepting connections.
// Blocks until ctx is cancelled.
func (l *UDSListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.socketPath)
	if err != nil {
		return fmt.Errorf("ipc: listen on %q: %w", l.socketPath, err)
	}

	l.mu.Lock()
	l.listener = ln
	l.mu.Unlock()

	log.Info().Str("socket_path", l.socketPath).Msg("ipc: UDS listener started")

	// Accept loop in a goroutine; cancel ctx to stop.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return // Normal shutdown
				default:
					log.Error().Err(err).Msg("ipc: accept error")
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			l.wg.Add(1)
			go func(c net.Conn) {
				defer l.wg.Done()
				l.handleConnection(ctx, c)
			}(conn)
		}
	}()

	// Wait for ctx cancellation.
	<-ctx.Done()
	_ = ln.Close()
	<-acceptDone
	l.wg.Wait()
	log.Info().Msg("ipc: UDS listener stopped")
	return nil
}

// handleConnection reads length-prefixed protobuf frames from a single connection.
func (l *UDSListener) handleConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		_ = conn.Close()
		log.Debug().Msg("ipc: connection closed")
	}()

	log.Debug().Str("remote", conn.RemoteAddr().String()).Msg("ipc: new connection")

	lenBuf := make([]byte, 4)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set a read deadline so we don't block forever on a stale connection.
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read 4-byte length prefix.
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				log.Debug().Msg("ipc: connection closed by Rust sender")
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Debug().Msg("ipc: read timeout; continuing")
				continue
			} else {
				log.Error().Err(err).Msg("ipc: read length prefix error")
			}
			return
		}

		msgLen := binary.BigEndian.Uint32(lenBuf)

		// Sanity check: reject absurdly large frames.
		const maxFrameBytes = 4 * 1024 * 1024 // 4 MiB
		if msgLen > maxFrameBytes {
			log.Error().
				Uint32("declared_length", msgLen).
				Msg("ipc: frame exceeds max size; dropping connection")
			return
		}

		// Read the protobuf payload.
		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			log.Error().Err(err).Msg("ipc: read payload error")
			return
		}

		// Decode protobuf.
		var event pb.TelemetryEvent
		if err := proto.Unmarshal(payload, &event); err != nil {
			log.Error().Err(err).Msg("ipc: protobuf decode error; skipping frame")
			continue // Don't close connection — bad frame, not bad connection
		}

		// Pass to handler (non-blocking fan-out).
		if err := l.handler(ctx, &event); err != nil {
			log.Error().Err(err).Str("event_id", event.EventId).Msg("ipc: event handler error")
		}
	}
}

// Close shuts down the listener immediately. Prefer context cancellation for
// graceful shutdown.
func (l *UDSListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}
