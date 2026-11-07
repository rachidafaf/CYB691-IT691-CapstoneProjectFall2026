#!/usr/bin/env bash
# CYB691: stop the Docker deployment.  --purge also deletes all volumes (database, evidence, edge buffer).
HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ "${1:-}" == "--purge" ]]; then
  docker compose -f "$HERE/docker-compose.yml" --profile ml down -v --remove-orphans
  python3 "$HERE/reset_receipts.py"     # database is empty again: re-ingest every handoff on the next up
else
  docker compose -f "$HERE/docker-compose.yml" --profile ml down --remove-orphans
fi
