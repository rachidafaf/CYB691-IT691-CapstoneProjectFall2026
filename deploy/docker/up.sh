#!/usr/bin/env bash
# CYB691: build and start the Docker deployment, then run the smoke test (Linux/macOS).
#   deploy/docker/up.sh [--no-smoke]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$HERE/docker-compose.yml")
command -v docker >/dev/null || { echo "docker not found on PATH" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon is not running" >&2; exit 1; }
# The handoff-watcher service ingests every new infrastructure/logs/ot_telemetry_handoff_*.tar.gz.
LOGS="$HERE/../../infrastructure/logs"; mkdir -p "$LOGS" "$HERE/../../data" "$HERE/../../infrastructure/extracted_handoff"
NEW=$(for f in "$LOGS"/ot_telemetry_handoff_*.tar.gz; do [[ -f "$f" ]] || continue
      grep -qs processed_at_utc "$f.sha256" || basename "$f"; done | tr '\n' ' ')
echo "Handoff folder: $LOGS  (new: ${NEW:-none})"
# On Linux the container user (UID 10001) must be able to write to infrastructure/logs (receipts),
# data/ and infrastructure/extracted_handoff/ (pipeline results).
python3 "$HERE/init-secrets.py"
export CYB691_GIT_SHA="$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
"${COMPOSE[@]}" up -d --build || { "${COMPOSE[@]}" ps -a; exit 1; }
"${COMPOSE[@]}" ps
echo "Reporting API: http://127.0.0.1:8080/docs"
[[ "${1:-}" == "--no-smoke" ]] || python3 "$HERE/smoke-test.py"
