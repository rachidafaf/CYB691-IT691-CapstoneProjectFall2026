# CYB691: build and start the Docker deployment, then run the smoke test (Windows PowerShell).
#   .\deploy\docker\up.ps1            build + start + smoke test
#   .\deploy\docker\up.ps1 -NoSmoke   build + start only
param([switch]$NoSmoke)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$compose = Join-Path $here "docker-compose.yml"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "docker not found on PATH (install Docker Desktop)" }
docker info *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker daemon is not running (start Docker Desktop)" }
$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "py" }

# The handoff-watcher service ingests every new infrastructure\logs\ot_telemetry_handoff_*.tar.gz.
$logs = Join-Path $here "..\..\infrastructure\logs"
foreach ($d in @($logs, (Join-Path $here "..\..\data"), (Join-Path $here "..\..\infrastructure\extracted_handoff"))) {
    if (-not (Test-Path $d -PathType Container)) { New-Item -ItemType Directory -Path $d | Out-Null }
}
$new = @(Get-ChildItem $logs -Filter "ot_telemetry_handoff_*.tar.gz" | Where-Object {
    -not ((Test-Path "$($_.FullName).sha256") -and (Select-String -Path "$($_.FullName).sha256" -Pattern "processed_at_utc" -Quiet)) })
Write-Host "Handoff folder: $((Resolve-Path $logs).Path)  ($($new.Count) new file(s) to ingest: $(($new | ForEach-Object Name) -join ', '))"

& $py (Join-Path $here "init-secrets.py")
if ($LASTEXITCODE -ne 0) { throw "init-secrets failed" }
$env:CYB691_GIT_SHA = (git -C $here rev-parse --short HEAD 2>$null)
docker compose -f $compose up -d --build
if ($LASTEXITCODE -ne 0) { docker compose -f $compose ps -a; throw "docker compose up failed" }
docker compose -f $compose ps
Write-Host "Reporting API: http://127.0.0.1:8080/docs"
if (-not $NoSmoke) { & $py (Join-Path $here "smoke-test.py"); exit $LASTEXITCODE }
