$ErrorActionPreference = "Stop"

$PROTO_FILE = "proto/kaaladrishti/v1/platform.proto"
$PROTO_DIR = "proto"

Write-Host "=== Generating Go protobuf bindings ==="
New-Item -ItemType Directory -Force -Path "generated/go" | Out-Null
protoc --proto_path="$PROTO_DIR" --go_out="generated/go" --go_opt="paths=source_relative" --go-grpc_out="generated/go" --go-grpc_opt="paths=source_relative" "$PROTO_FILE"

Write-Host "=== Generating Python protobuf bindings ==="
New-Item -ItemType Directory -Force -Path "generated/python" | Out-Null
& "services/ml-analytics/.venv/Scripts/python.exe" -m grpc_tools.protoc --proto_path="$PROTO_DIR" --python_out="generated/python" --grpc_python_out="generated/python" "$PROTO_FILE"

# Fix relative imports in generated Python
$pb2_grpc = "generated/python/kaaladrishti/v1/platform_pb2_grpc.py"
if (Test-Path $pb2_grpc) {
    (Get-Content $pb2_grpc) -replace 'from kaaladrishti.v1 import platform_pb2', 'from generated.python.kaaladrishti.v1 import platform_pb2' | Set-Content $pb2_grpc
}

Write-Host "=== Proto generation complete ==="
Write-Host "Go:     generated/go/kaaladrishti/v1/"
Write-Host "Python: generated/python/kaaladrishti/v1/"
