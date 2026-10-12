#!/usr/bin/env bash
# scripts/gen_proto.sh — generates Go and Python protobuf bindings.
#
# Run this script from the project root AFTER installing all tools.
# Prerequisites:
#   - protoc (https://github.com/protocolbuffers/protobuf/releases)
#   - protoc-gen-go: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   - protoc-gen-go-grpc: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#   - grpcio-tools: pip install grpcio-tools==1.62.1
#
# Output:
#   Go:     generated/go/kaaladrishti/v1/platform.pb.go
#           generated/go/kaaladrishti/v1/platform_grpc.pb.go
#   Python: generated/python/platform_pb2.py
#           generated/python/platform_pb2_grpc.py
set -euo pipefail

PROTO_FILE="proto/kaaladrishti/v1/platform.proto"
PROTO_DIR="proto"

echo "=== Generating Go protobuf bindings ==="
mkdir -p generated/go
protoc \
  --proto_path="${PROTO_DIR}" \
  --go_out=generated/go \
  --go_opt=paths=source_relative \
  --go-grpc_out=generated/go \
  --go-grpc_opt=paths=source_relative \
  "${PROTO_FILE}"

echo "=== Generating Python protobuf bindings ==="
mkdir -p generated/python
python -m grpc_tools.protoc \
  --proto_path="${PROTO_DIR}" \
  --python_out=generated/python \
  --grpc_python_out=generated/python \
  "${PROTO_FILE}"

# Fix relative imports in generated Python (grpc_tools generates broken imports).
if [ -f "generated/python/kaaladrishti/v1/platform_pb2_grpc.py" ]; then
  sed -i 's/from kaaladrishti.v1 import platform_pb2/from generated.python.kaaladrishti.v1 import platform_pb2/g' \
    generated/python/kaaladrishti/v1/platform_pb2_grpc.py
fi

echo "=== Proto generation complete ==="
echo "Go:     generated/go/kaaladrishti/v1/"
echo "Python: generated/python/kaaladrishti/v1/"
