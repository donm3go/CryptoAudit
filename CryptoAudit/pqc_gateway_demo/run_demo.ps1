# Orchestrates the hybrid PQC TLS handshake demo:
#   1. Starts a containerized "API Gateway" stand-in running OpenSSL +
#      oqs-provider, offering a hybrid ECDHE+ML-KEM key-exchange group.
#   2. Connects a client inside the same container using that group.
#   3. Pulls the handshake transcript and renders a report.
#
# Prerequisites: Docker Desktop (with WSL2 backend) installed and running.
# See ../RUNBOOK.md for setup instructions.

param(
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

Write-Host "== Starting PQC gateway container ==" -ForegroundColor Cyan
docker compose up -d
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

Write-Host "== Waiting for TLS server to come up on :8443 ==" -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    $log = docker exec pqc-gateway-demo cat /demo/logs/server.log 2>$null
    if ($log -match "ACCEPT") { $ready = $true; break }
}
if (-not $ready) {
    Write-Warning "Server log never showed 'ACCEPT' after 60s; continuing anyway."
}

Write-Host "== Running client handshake ==" -ForegroundColor Cyan
docker exec pqc-gateway-demo sh /demo/scripts/run_client_demo.sh

Write-Host "== Parsing handshake transcript ==" -ForegroundColor Cyan
python (Join-Path $root "scripts\parse_handshake.py") `
    (Join-Path $root "logs\client_handshake.log") `
    (Join-Path $root "logs\selected_group.txt") `
    --output (Join-Path $root "handshake_report.md") `
    --inventory-fragment (Join-Path $root "tls_config_fragment.json")

if (-not $KeepRunning) {
    Write-Host "== Stopping container (pass -KeepRunning to leave it up) ==" -ForegroundColor Cyan
    docker compose down
}

Write-Host "Done. See $root\handshake_report.md" -ForegroundColor Green
