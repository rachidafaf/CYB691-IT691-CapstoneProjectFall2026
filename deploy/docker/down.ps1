# CYB691: stop the Docker deployment.  -Purge also deletes all volumes (database, evidence, edge buffer).
param([switch]$Purge)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$compose = Join-Path $here "docker-compose.yml"
if ($Purge) {
    docker compose -f $compose --profile ml down -v --remove-orphans
    # The database is empty again, so every handoff in infrastructure\logs must be ingested again.
    $py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "py" }
    & $py (Join-Path $here "reset_receipts.py")
}
else        { docker compose -f $compose --profile ml down --remove-orphans }
