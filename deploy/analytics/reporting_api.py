#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Service: reporting-api (read-only dashboard backend)

* Connects with the cyb691_readonly role only (SELECT on views/tables).
* Published by docker-compose.yml on 127.0.0.1:8080 only (loopback of the Docker
  host). This service does no end-user authentication; anything beyond localhost
  must go through an authenticating reverse proxy.
* No endpoint can write, and nothing here can reach the OT network.

Run: uvicorn analytics.reporting_api:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, HTTPException, Query  # noqa: E402

from analytics.pg_connection import ConnectionPool  # noqa: E402

app = FastAPI(title="CYB691 OT Defense Reporting API", version="1.0.0",
              docs_url=None if os.environ.get("CYB691_ENVIRONMENT") == "production" else "/docs",
              redoc_url=None)
_pool = ConnectionPool(max_size=int(os.environ.get("PG_POOL_MAX", "4")))


def _query(sql: str, params: tuple) -> List[Dict[str, Any]]:
    with _pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, [str(v) if v is not None and not isinstance(v, (int, float, str, bool, list, dict))
                               else v for v in row])) for row in cur.fetchall()]


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok"}                          # liveness: process is up (no DB dependency)


@app.get("/readyz")
def readyz() -> Dict[str, str]:
    try:
        _query("SELECT 1 AS ok", ())
    except Exception:
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready"}


@app.get("/api/v1/incidents")
def incidents(status: str = Query("OPEN", pattern="^(OPEN|INVESTIGATING|MITIGATED|RESOLVED|FALSE_POSITIVE)$"),
              limit: int = Query(100, ge=1, le=1000)):
    return _query("SELECT incident_id, severity, rule, title, status, first_seen_utc, last_seen_utc, event_count, "
                  "src_ip, dest_ip, edge_id FROM incidents WHERE status = %s ORDER BY last_seen_utc DESC LIMIT %s",
                  (status, limit))


@app.get("/api/v1/events/daily")
def daily(days: int = Query(7, ge=1, le=90)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return _query("SELECT day_utc, edge_id, event_type, severity, events FROM v_daily_event_counts "
                  "WHERE day_utc >= %s ORDER BY day_utc", (since,))


@app.get("/api/v1/evidence/{manifest_id}")
def evidence(manifest_id: str):
    if len(manifest_id) > 200:
        raise HTTPException(status_code=400, detail="invalid id")
    rows = _query("SELECT * FROM v_evidence_lineage WHERE manifest_id = %s", (manifest_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="not found")
    return rows[0]


@app.get("/api/v1/runs")
def runs(limit: int = Query(50, ge=1, le=500)):
    return _query("SELECT run_id, workload, pipeline_stage, status, started_at, completed_at, records_input, "
                  "records_output, records_failed, records_duplicate, image_ref FROM processing_runs "
                  "ORDER BY started_at DESC LIMIT %s", (limit,))
