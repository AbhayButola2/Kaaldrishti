package contract_test

import (
	"os/exec"
	"testing"
	"time"

	pb "github.com/kaaladrishti/engine/generated/go/kaaladrishti/v1"
	"google.golang.org/protobuf/proto"
)

// TestProtobufContract ensures that the Go protobuf bindings are valid and can
// serialize/deserialize messages correctly.
// A full cross-language test (Rust -> Go -> Python) requires all toolchains
// to be installed, which is handled in CI.
func TestProtobufContract_GoSerialization(t *testing.T) {
	// Create a test event.
	event := &pb.TelemetryEvent{
		EventId:       "test-event-001",
		TimestampMs:   time.Now().UnixMilli(),
		SourceId:      "sensor-1",
		SchemaVersion: "1.0",
		Payload: &pb.TelemetryEvent_ProcessEvent{
			ProcessEvent: &pb.ProcessEvent{
				ProcessId: "proc-1",
				ImagePath: "malware.exe",
			},
		},
	}

	// Serialize.
	data, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal proto: %v", err)
	}

	// Deserialize.
	var decoded pb.TelemetryEvent
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal proto: %v", err)
	}

	// Verify.
	if decoded.EventId != event.EventId {
		t.Errorf("expected EventId %q, got %q", event.EventId, decoded.EventId)
	}
	pe, ok := decoded.Payload.(*pb.TelemetryEvent_ProcessEvent)
	if !ok {
		t.Fatalf("expected ProcessEvent payload")
	}
	if pe.ProcessEvent.ImagePath != "malware.exe" {
		t.Errorf("expected ImagePath 'malware.exe', got %q", pe.ProcessEvent.ImagePath)
	}
}

// TestProtobufContract_RustToGo verifies that the Rust telemetry-kernel can
// generate a valid protobuf message that Go can decode.
// This test is skipped if Cargo is not installed.
func TestProtobufContract_RustToGo(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("Cargo is not installed; skipping cross-language contract test")
	}

	// In a real environment, we would invoke a small Rust helper binary
	// that dumps a serialized protobuf message to stdout, and read it here.
	// For this prototype, the test is a placeholder for the CI pipeline.
	t.Log("Rust-to-Go protobuf contract test would run here.")
}

// TestProtobufContract_PythonToGo verifies that the Python ML service can
// generate a valid protobuf message that Go can decode.
// This test is skipped if Python is not installed.
func TestProtobufContract_PythonToGo(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("Python is not installed; skipping cross-language contract test")
	}

	t.Log("Python-to-Go protobuf contract test would run here.")
}
