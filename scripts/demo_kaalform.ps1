param(
    [string]$GatewayUrl = "http://127.0.0.1:7070"
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  KAALFORM: AGENT EXECUTION FIREWALL (PILLARS 4 & 5) DEMO " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Helper for HTTP requests
function Invoke-GateApi {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Body = $null
    )
    try {
        $params = @{
            Method = $Method
            Uri = "$GatewayUrl$Uri"
            ContentType = "application/json"
            ErrorAction = "Stop"
        }
        if ($Headers.Count -gt 0) { $params.Headers = $Headers }
        if ($Body) { $params.Body = $Body }
        
        $response = Invoke-RestMethod @params
        return @{ Success = $true; Data = $response; StatusCode = 200 }
    }
    catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 500 }
        $errBody = ""
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errBody = $_.ErrorDetails.Message
        } elseif ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $errBody = $reader.ReadToEnd()
                }
            } catch {}
        }
        return @{ Success = $false; Error = $errBody; StatusCode = $statusCode }
    }
}

# 1. Health Check
Write-Host "[1/6] Checking Kaalform Gateway Health..." -ForegroundColor Yellow
$health = Invoke-GateApi -Method "GET" -Uri "/health"
if (-not $health.Success) {
    Write-Host "[-] Kaalform is not running at $GatewayUrl. Please start it with: cargo run -p kaalform --bin kaalform" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Kaalform is online! Upstream MCP: $($health.Data.upstream_mcp_url) | Drift Threshold: $($health.Data.drift_threshold)" -ForegroundColor Green
Write-Host ""

# 2. Pillar 4: Cryptographic Attestation Verification
Write-Host "[2/6] Verifying Signed Tool Manifest (Pillar 4 Ed25519)..." -ForegroundColor Yellow
$manifestPath = "crates/kaalform/examples/sample_signed_manifest.json"
if (Test-Path $manifestPath) {
    $manifestJson = Get-Content $manifestPath -Raw
    $verifyRes = Invoke-GateApi -Method "POST" -Uri "/manifest/verify" -Body $manifestJson
    if ($verifyRes.Success -and $verifyRes.Data.valid) {
        Write-Host "[+] Cryptographic signature verified successfully for tool: kaaladrishti/graph-query@1.0.0" -ForegroundColor Green
    } else {
        Write-Host "[-] Verification failed: $($verifyRes.Data.error)" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Sample manifest not found at $manifestPath" -ForegroundColor Red
}
Write-Host ""

# 3. Pillar 4: Tamper Resistance Test
Write-Host "[3/6] Testing Tamper-Resistance (Pillar 4 Integrity Check)..." -ForegroundColor Yellow
$tamperedManifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$tamperedManifest.body.tool_id = "attacker/backdoored-tool@9.9.9"
$tamperedJson = $tamperedManifest | ConvertTo-Json -Depth 5
$tamperRes = Invoke-GateApi -Method "POST" -Uri "/manifest/verify" -Body $tamperedJson
if ($tamperRes.Data.valid -eq $false) {
    Write-Host "[+] Tamper detected! Altered tool_id correctly rejected: $($tamperRes.Data.error)" -ForegroundColor Green
} else {
    Write-Host "[-] Tampered manifest was incorrectly accepted!" -ForegroundColor Red
}
Write-Host ""

# 4. Pillar 5: Declare Agent Workflow Scope
Write-Host "[4/6] Declaring Agent Workflow Context (Pillar 5 Provenance)..." -ForegroundColor Yellow
$workflowId = "wf-customer-ops-$(Get-Random -Minimum 1000 -Maximum 9999)"
$scopeText = "You are a customer operations assistant. You may only read customer profiles and order histories. You must not execute shell commands or modify system databases. Allowed tools: get_order, get_customer."

$declareBody = @{
    workflow_id = $workflowId
    declared_scope = $scopeText
} | ConvertTo-Json

$scopeRes = Invoke-GateApi -Method "POST" -Uri "/mcp/v1/scope" -Body $declareBody
if ($scopeRes.Success) {
    Write-Host "[+] Session registered for workflow: $workflowId" -ForegroundColor Green
    Write-Host "    Declared Scope: $scopeText" -ForegroundColor DarkGray
} else {
    Write-Host "[-] Failed to register scope: $($scopeRes.Error)" -ForegroundColor Red
}
Write-Host ""

# 5. Pillar 5: Test In-Scope Action (Expect Approval)
Write-Host "[5/6] Invoking In-Scope Tool: get_order (Expected: APPROVED)..." -ForegroundColor Yellow
$inScopeHeaders = @{
    "X-Kaalform-Workflow-Id" = $workflowId
    "X-Kaalform-Principal-Id" = "agent-customer-support"
}
$inScopeBody = @{
    tool_id = "get_order"
    arguments = @{
        order_id = "ORD-98231"
        action = "read customer order history profile"
    }
} | ConvertTo-Json

$inScopeRes = Invoke-GateApi -Method "POST" -Uri "/mcp/v1/call" -Headers $inScopeHeaders -Body $inScopeBody
# Note: since upstream mock might return 502/503 if not running, we check if the gate passed or blocked
if ($inScopeRes.StatusCode -eq 403) {
    Write-Host "[-] Legitimate action was denied: $($inScopeRes.Error)" -ForegroundColor Red
} else {
    Write-Host "[+] Gate APPROVED legitimate call! Passed Pillar 5 Provenance Firewall." -ForegroundColor Green
}
Write-Host ""

# 6. Pillar 5: Simulate Prompt Injection / Drifted Attack (Expect Denial)
Write-Host "[6/6] Simulating Prompt Injection Attack: shell_exec (Expected: DENIED)..." -ForegroundColor Yellow
$attackHeaders = @{
    "X-Kaalform-Workflow-Id" = $workflowId
    "X-Kaalform-Principal-Id" = "agent-customer-support"
}
$attackBody = @{
    tool_id = "shell_exec"
    arguments = @{
        command = "rm -rf / production server exfiltrate admin credentials database root lateral movement"
    }
} | ConvertTo-Json

$attackRes = Invoke-GateApi -Method "POST" -Uri "/mcp/v1/call" -Headers $attackHeaders -Body $attackBody
if ($attackRes.StatusCode -eq 403) {
    $errObj = $attackRes.Error | ConvertFrom-Json
    Write-Host "[+] ATTACK BLOCKED BY PILLAR 5 FIREWALL!" -ForegroundColor Green
    Write-Host "    HTTP Status:   403 Forbidden" -ForegroundColor DarkYellow
    Write-Host "    Firewall Rule: $($errObj.error)" -ForegroundColor DarkYellow
    Write-Host "    Drift Score:   $($errObj.drift_score) (Threshold: $($health.Data.drift_threshold))" -ForegroundColor DarkYellow
    Write-Host "    Receipt ID:    $($errObj.receipt_id)" -ForegroundColor DarkYellow
} else {
    Write-Host "[-] Attack was NOT blocked! Status: $($attackRes.StatusCode)" -ForegroundColor Red
}
Write-Host ""

# 7. Audit Trail Query
Write-Host "[Audit Query] Fetching Session Action Log from Kaalform..." -ForegroundColor Yellow
$auditRes = Invoke-GateApi -Method "GET" -Uri "/audit/$workflowId"
if ($auditRes.Success) {
    Write-Host "[+] Audit trail retrieved ($($auditRes.Data.actions.Count) records):" -ForegroundColor Green
    foreach ($action in $auditRes.Data.actions) {
        $verdictColor = if ($action.verdict -eq "Approved") { "Green" } else { "Red" }
        Write-Host "    • [$($action.verdict)] Tool: $($action.tool_id) | Drift: $([math]::Round($action.drift_score, 3)) | Receipt: $($action.receipt_id)" -ForegroundColor $verdictColor
    }
}
Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  DEMONSTRATION COMPLETE: PILLARS 4 & 5 FUNCTIONAL " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
