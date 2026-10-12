$ErrorActionPreference = "Stop"

Write-Host "=== Starting Kaaladrishti ==="

# Define log files
$mlLogOut = "ml_service_out.log"
$mlLogErr = "ml_service_err.log"
$goLogOut = "go_engine_out.log"
$goLogErr = "go_engine_err.log"

Write-Host "1. Starting Python ML Service (gRPC on port 50051)..."
Start-Process -NoNewWindow -FilePath "services\ml-analytics\.venv\Scripts\python.exe" -ArgumentList "-m", "app.grpc_server" -RedirectStandardOutput $mlLogOut -RedirectStandardError $mlLogErr
Start-Sleep -Seconds 3

Write-Host "1.1. Starting PZEDS Zero-Day Backend (Uvicorn on port 8000)..."
Start-Process -NoNewWindow -FilePath "python\python.exe" -ArgumentList "-m", "uvicorn", "main:app", "--port", "8000" -WorkingDirectory "zero_day_exploit\Backend" -RedirectStandardOutput "$PWD\pzeds_out.log" -RedirectStandardError "$PWD\pzeds_err.log"
Start-Sleep -Seconds 3

Write-Host "1.5. Starting Rust Telemetry Kernel (TCP to Go)..."
$env:KAALADRISHTI_SOURCE = "live"
Start-Process -NoNewWindow -FilePath "cargo" -ArgumentList "run", "--manifest-path", "crates\telemetry-kernel\Cargo.toml", "--bin", "telemetry-kernel" -RedirectStandardOutput "rust_kernel_out.log" -RedirectStandardError "rust_kernel_err.log"
Start-Sleep -Seconds 2

Write-Host "2. Starting Go Engine (HTTP on port 8080)..."
$env:KAALADRISHTI_API_ADDR = ":8080"
Start-Process -NoNewWindow -FilePath "go" -ArgumentList "run", ".\cmd\engine" -RedirectStandardOutput $goLogOut -RedirectStandardError $goLogErr
Start-Sleep -Seconds 2

Write-Host "2.5. Starting Kaalform Agent Gateway (HTTP on port 7070)..."
$env:KAALFORM_UPSTREAM_MCP_URL = "http://127.0.0.1:8000"
$env:KAALFORM_REQUIRE_MANIFEST = "false"
Start-Process -NoNewWindow -FilePath "cargo" -ArgumentList "run", "--manifest-path", "crates\kaalform\Cargo.toml", "--bin", "kaalform" -RedirectStandardOutput "kaalform_out.log" -RedirectStandardError "kaalform_err.log"

Write-Host "=== All services started ==="
Write-Host "Dashboard: http://localhost:8080"
Write-Host "Kaalform Gateway: http://localhost:7070"
Write-Host "Logs:"
Write-Host "  - ML Service: Get-Content $mlLogOut -Wait (and $mlLogErr)"
Write-Host "  - PZEDS Backend: Get-Content pzeds_out.log -Wait (and pzeds_err.log)"
Write-Host "  - Go Engine: Get-Content $goLogOut -Wait (and $goLogErr)"
Write-Host "  - Rust Kernel: Get-Content rust_kernel_out.log -Wait (and rust_kernel_err.log)"
Write-Host "  - Kaalform: Get-Content kaalform_out.log -Wait (and kaalform_err.log)"
Write-Host ""
Write-Host "Press Ctrl+C to exit and kill all processes."

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    Write-Host "Stopping processes..."
    Stop-Process -Name "python" -ErrorAction SilentlyContinue
    Stop-Process -Name "engine" -ErrorAction SilentlyContinue
    Stop-Process -Name "telemetry-kernel" -ErrorAction SilentlyContinue
    Stop-Process -Name "kaalform" -ErrorAction SilentlyContinue
}
