#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4
Module: Idempotent PostgreSQL writer for the analytics services (pg_writer.py)
===============================================================================
Every write is safe to repeat:
  * telemetry_events + detail tables:  ON CONFLICT (idempotency_key ...) DO NOTHING
  * evidence_manifests:                ON CONFLICT (manifest_id) DO NOTHING
  * processing_runs:                   upsert by run_id
  * ml_predictions:                    ON CONFLICT (event, model, version) DO NOTHING
  * incidents:                         upsert by deterministic incident_id
  * audit_events:                      append-only

Changes from the previous draft:
  * Password read from a Docker secret file (pg_connection.py); DSN no longer
    built by string interpolation.
  * ON CONFLICT target now matches a real unique constraint on the partitioned
    table (the old UNIQUE(idempotency_key) could not be created).
  * Detail tables and ml_predictions are idempotent too (were plain INSERTs).
  * A MemoryStore with identical semantics is provided for unit tests.
===============================================================================
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


NUL_PLACEHOLDER = "\\u0000"     # the 6-character text  \u0000


def pg_safe(v: Any) -> Any:
    """PostgreSQL cannot store NUL (U+0000) in TEXT or JSONB. Captured Modbus write payloads
    contain NUL bytes (Suricata emits them as "\\u0000"), so they are stored as the literal
    6-character text \\u0000. Only the database copy changes: the raw evidence object in the
    object store, and every SHA-256 / idempotency key (computed at the edge), are untouched."""
    if isinstance(v, str):
        return v.replace("\x00", NUL_PLACEHOLDER) if "\x00" in v else v
    if isinstance(v, dict):
        return {pg_safe(k): pg_safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [pg_safe(x) for x in v]
    return v


def _j(v: Any) -> Optional[str]:
    return None if v is None else json.dumps(pg_safe(v), sort_keys=True, default=str)


class Store(Protocol):
    def write_events(self, envelopes: List[Dict[str, Any]], *, batch_id: Optional[str],
                     manifest_id: Optional[str], run_id: str) -> Tuple[int, int]: ...
    def existing_keys(self, keys: Iterable[str]) -> set: ...
    def manifest_status(self, manifest_id: str) -> Optional[str]: ...
    def save_evidence_manifest(self, m: Dict[str, Any]) -> bool: ...
    def start_run(self, run_id: str, workload: str, stage: str, meta: Dict[str, Any]) -> None: ...
    def finish_run(self, run_id: str, status: str, counts: Dict[str, int], error: Optional[str] = None) -> None: ...
    def save_predictions(self, preds: List[Dict[str, Any]]) -> int: ...
    def upsert_incident(self, inc: Dict[str, Any]) -> None: ...
    def audit(self, actor: str, action: str, target_type: str, target_id: str, outcome: str = "SUCCESS",
              run_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None: ...
    def fetch_events(self, since: datetime, until: datetime, event_types: Optional[List[str]] = None,
                     limit: int = 50000) -> List[Dict[str, Any]]: ...


# ============================================================================
# Row mapping (envelope -> table rows)
# ============================================================================

def detail_rows(env: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Returns {'modbus_transactions': row, 'suricata_alerts': row, 'firewall_drops': row} as applicable."""
    out: Dict[str, Dict[str, Any]] = {}
    key, ts = env["idempotency_key"], env["timestamp_utc"]
    raw = env.get("raw") if isinstance(env.get("raw"), dict) else {}
    mb = env.get("modbus") or {}
    if env["event_type"] in ("MODBUS_DPI", "SURICATA_ALERT") and mb.get("function_code"):
        resp = ((raw.get("modbus") or {}).get("response") or {}) if isinstance(raw.get("modbus"), dict) else {}
        exc = resp.get("exception") if isinstance(resp, dict) else None
        out["modbus_transactions"] = {
            "idempotency_key": key, "event_timestamp_utc": ts, "unit_id": mb.get("unit_id"),
            "function_code": mb["function_code"], "function_name": mb.get("function_name"),
            "category": mb.get("category"), "transaction_id": mb.get("transaction_id"),
            "address": mb.get("address"), "quantity": mb.get("quantity"),
            "is_write": mb.get("category") == "WRITE",
            "exception_code": None if not exc else str(exc.get("code", exc)),
        }
    if env["event_type"] == "SURICATA_ALERT":
        a = raw.get("alert") or {}
        out["suricata_alerts"] = {
            "idempotency_key": key, "event_timestamp_utc": ts, "signature_id": a.get("signature_id"),
            "signature": a.get("signature"), "rev": a.get("rev"), "alert_severity": a.get("severity"),
            "alert_category": a.get("category"), "alert_action": a.get("action"),
            "flow_id": raw.get("flow_id"), "raw_alert": a,
        }
    if env["event_type"] == "FIREWALL_DROP":
        p = raw.get("parsed") or {}
        out["firewall_drops"] = {
            "idempotency_key": key, "event_timestamp_utc": ts, "rule_id": p.get("rule"),
            "interface": p.get("interface"), "direction": p.get("direction"), "action": p.get("action"),
            "src_ip": env.get("src_ip"), "dest_ip": env.get("dest_ip"), "dest_port": env.get("dest_port"),
            "protocol": env.get("protocol"), "raw_line": raw.get("line"),
        }
    return out


# ============================================================================
# PostgreSQL implementation
# ============================================================================

class PgStore:
    def __init__(self, pool=None):
        if pool is None:
            from analytics.pg_connection import ConnectionPool
            pool = ConnectionPool()
        self.pool = pool

    _EV_COLS = ("idempotency_key", "timestamp_utc", "event_uuid", "schema_version", "edge_id", "event_type",
                "severity", "collected_at_utc", "src_ip", "src_port", "dest_ip", "dest_port", "protocol",
                "unit_id", "function_code", "function_category", "sha256_hash", "raw_ref", "raw",
                "batch_id", "evidence_manifest_id", "run_id")

    def write_events(self, envelopes, *, batch_id, manifest_id, run_id) -> Tuple[int, int]:
        """All rows of a batch commit together or not at all. Returns (inserted, duplicates)."""
        if not envelopes:
            return 0, 0
        ev_sql = (f"INSERT INTO telemetry_events ({', '.join(self._EV_COLS)}) VALUES "
                  f"({', '.join(['%s'] * len(self._EV_COLS))}) "
                  "ON CONFLICT (idempotency_key, timestamp_utc) DO NOTHING")
        inserted = 0
        with self.pool.connection() as conn, conn.cursor() as cur:
            for e in envelopes:
                mb = e.get("modbus") or {}
                cur.execute(ev_sql, pg_safe((
                    e["idempotency_key"], e["timestamp_utc"], e["event_uuid"], e["schema_version"], e["edge_id"],
                    e["event_type"], e["severity"], e["collected_at_utc"], e.get("src_ip"), e.get("src_port"),
                    e.get("dest_ip"), e.get("dest_port"), e.get("protocol"), mb.get("unit_id"),
                    mb.get("function_code"), mb.get("category"), e["sha256_hash"], _j(e.get("raw_ref")),
                    _j(e.get("raw")), batch_id, manifest_id, run_id)))
                inserted += cur.rowcount
                for table, row in detail_rows(e).items():
                    cols = list(row.keys())
                    vals = [_j(v) if isinstance(v, (dict, list)) else pg_safe(v) for v in row.values()]
                    # table and column names come from the fixed mapping above, never from input
                    cur.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
                                "ON CONFLICT (idempotency_key) DO NOTHING", vals)
        return inserted, len(envelopes) - inserted

    def existing_keys(self, keys) -> set:
        keys = list(keys)
        if not keys:
            return set()
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT idempotency_key FROM telemetry_events WHERE idempotency_key = ANY(%s)", (keys,))
            return {r[0] for r in cur.fetchall()}

    def manifest_status(self, manifest_id) -> Optional[str]:
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT verification_status FROM evidence_manifests WHERE manifest_id = %s", (manifest_id,))
            r = cur.fetchone()
            return r[0] if r else None

    def save_evidence_manifest(self, m) -> bool:
        cols = ("manifest_id", "kind", "edge_id", "batch_id", "container", "blob_name", "sha256_hash",
                "file_size_bytes", "content_type", "event_count", "verification_status", "is_immutable",
                "retention_until", "run_id", "manifest")
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(f"INSERT INTO evidence_manifests ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
                        "ON CONFLICT (manifest_id) DO NOTHING",
                        [(_j(m.get(c)) if c == "manifest" else m.get(c)) for c in cols])
            return cur.rowcount > 0

    def start_run(self, run_id, workload, stage, meta) -> None:
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO processing_runs (run_id, workload, pipeline_stage, image_ref, git_sha, metadata) "
                        "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (run_id) DO NOTHING",
                        (run_id, workload, stage, meta.get("image_ref"), meta.get("git_sha"), _j(meta)))

    def finish_run(self, run_id, status, counts, error=None) -> None:
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute("UPDATE processing_runs SET status=%s, completed_at=now(), records_input=%s, "
                        "records_output=%s, records_failed=%s, records_duplicate=%s, error_summary=%s "
                        "WHERE run_id=%s",
                        (status, counts.get("input", 0), counts.get("output", 0), counts.get("failed", 0),
                         counts.get("duplicate", 0), (error or "")[:2000] or None, run_id))

    def save_predictions(self, preds) -> int:
        n = 0
        with self.pool.connection() as conn, conn.cursor() as cur:
            for p in preds:
                cur.execute(
                    "INSERT INTO ml_predictions (event_idempotency_key, event_timestamp_utc, model_name, model_version, "
                    "model_sha256, prediction_label, prediction_probability, feature_vector, inference_latency_ms, run_id) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT (event_idempotency_key, model_name, model_version) DO NOTHING",
                    (p["event_idempotency_key"], p["event_timestamp_utc"], p["model_name"], p["model_version"],
                     p["model_sha256"], p["prediction_label"], p.get("prediction_probability"),
                     _j(p["feature_vector"]), p.get("inference_latency_ms"), p.get("run_id")))
                n += cur.rowcount
        return n

    def upsert_incident(self, inc) -> None:
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incidents (incident_id, severity, rule, title, description, first_seen_utc, last_seen_utc, "
                "event_count, event_keys, src_ip, dest_ip, edge_id, created_by_run, metadata) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (incident_id) DO UPDATE SET "
                "last_seen_utc = GREATEST(incidents.last_seen_utc, EXCLUDED.last_seen_utc), "
                "event_count = EXCLUDED.event_count, event_keys = EXCLUDED.event_keys, "
                "severity = EXCLUDED.severity, updated_at = now()",
                (inc["incident_id"], inc["severity"], inc["rule"], inc["title"], inc.get("description"),
                 inc["first_seen_utc"], inc["last_seen_utc"], inc["event_count"], _j(inc["event_keys"]),
                 inc.get("src_ip"), inc.get("dest_ip"), inc.get("edge_id"), inc.get("run_id"),
                 _j(inc.get("metadata", {}))))

    def audit(self, actor, action, target_type, target_id, outcome="SUCCESS", run_id=None, details=None) -> None:
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO audit_events (actor, action, target_type, target_id, outcome, run_id, details) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (actor, action, target_type, target_id, outcome, run_id, _j(details or {})))

    def fetch_events(self, since, until, event_types=None, limit=50000) -> List[Dict[str, Any]]:
        sql = ("SELECT idempotency_key, timestamp_utc, event_uuid, edge_id, event_type, severity, src_ip, "
               "src_port, dest_ip, dest_port, protocol, unit_id, function_code, function_category, raw "
               "FROM telemetry_events WHERE timestamp_utc >= %s AND timestamp_utc < %s")
        params: List[Any] = [since, until]
        if event_types:
            sql += " AND event_type = ANY(%s)"
            params.append(list(event_types))
        sql += " ORDER BY edge_id, timestamp_utc LIMIT %s"
        params.append(limit)
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["timestamp_utc"] = r["timestamp_utc"].astimezone(timezone.utc).isoformat()
            for k in ("src_ip", "dest_ip"):
                r[k] = None if r[k] is None else str(r[k])
            r["modbus"] = ({"function_code": r["function_code"], "unit_id": r["unit_id"],
                            "category": r["function_category"]} if r["function_code"] else None)
        return rows


# ============================================================================
# In-memory implementation (unit tests, identical idempotency semantics)
# ============================================================================

class MemoryStore:
    def __init__(self):
        self.events: Dict[str, Dict[str, Any]] = {}
        self.details: Dict[str, Dict[str, Dict[str, Any]]] = {"modbus_transactions": {}, "suricata_alerts": {},
                                                             "firewall_drops": {}}
        self.manifests: Dict[str, Dict[str, Any]] = {}
        self.runs: Dict[str, Dict[str, Any]] = {}
        self.predictions: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.audits: List[Dict[str, Any]] = []
        self.fail_writes = 0          # simulate PostgreSQL outage

    def _maybe_fail(self):
        if self.fail_writes > 0:
            self.fail_writes -= 1
            raise ConnectionError("simulated PostgreSQL outage")

    def write_events(self, envelopes, *, batch_id, manifest_id, run_id):
        self._maybe_fail()
        staged = {}
        for e in envelopes:                      # all-or-nothing like a transaction
            if e["idempotency_key"] not in self.events and e["idempotency_key"] not in staged:
                staged[e["idempotency_key"]] = dict(e, batch_id=batch_id, evidence_manifest_id=manifest_id,
                                                    run_id=run_id)
        self.events.update(staged)
        for e in staged.values():
            for t, row in detail_rows(e).items():
                self.details[t].setdefault(e["idempotency_key"], row)
        return len(staged), len(envelopes) - len(staged)

    def existing_keys(self, keys):
        return {k for k in keys if k in self.events}

    def manifest_status(self, manifest_id):
        m = self.manifests.get(manifest_id)
        return m["verification_status"] if m else None

    def save_evidence_manifest(self, m):
        self._maybe_fail()
        if m["manifest_id"] in self.manifests:
            return False
        self.manifests[m["manifest_id"]] = dict(m)
        return True

    def start_run(self, run_id, workload, stage, meta):
        self.runs.setdefault(run_id, {"workload": workload, "stage": stage, "status": "RUNNING", "meta": meta})

    def finish_run(self, run_id, status, counts, error=None):
        self.runs[run_id].update(status=status, counts=counts, error=error)

    def save_predictions(self, preds):
        n = 0
        for p in preds:
            k = (p["event_idempotency_key"], p["model_name"], p["model_version"])
            if k not in self.predictions:
                self.predictions[k] = p
                n += 1
        return n

    def upsert_incident(self, inc):
        cur = self.incidents.get(inc["incident_id"])
        if cur:
            cur.update(last_seen_utc=max(cur["last_seen_utc"], inc["last_seen_utc"]),
                       event_count=inc["event_count"], event_keys=inc["event_keys"], severity=inc["severity"])
        else:
            self.incidents[inc["incident_id"]] = dict(inc)

    def audit(self, actor, action, target_type, target_id, outcome="SUCCESS", run_id=None, details=None):
        self.audits.append(dict(actor=actor, action=action, target_type=target_type, target_id=target_id,
                                outcome=outcome, run_id=run_id, details=details or {}))

    def fetch_events(self, since, until, event_types=None, limit=50000):
        out = []
        for e in self.events.values():
            ts = datetime.fromisoformat(e["timestamp_utc"])
            if since <= ts < until and (not event_types or e["event_type"] in event_types):
                out.append(e)
        return sorted(out, key=lambda r: (r["edge_id"], r["timestamp_utc"]))[:limit]


def deterministic_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def new_run_id() -> str:
    return str(uuid.uuid4())
