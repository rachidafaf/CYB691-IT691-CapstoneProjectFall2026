# CYB691: stop the Docker deployment.  -Purge also deletes all volumes (database, evidence, edge buffer).
param([switch]$Purge)
$compose = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "docker-compose.yml"
if ($Purge) { docker compose -f $compose --profile ml down -v --remove-orphans }
else        { docker compose -f $compose --profile ml down --remove-orphans }
