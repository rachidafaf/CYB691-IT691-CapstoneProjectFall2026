#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: Edge SQLite store-and-forward buffer (edge_database.py)  — schema v2
===============================================================================
Runs ONLY at the OT edge gateway (IDMZ segment). It never talks to PLCs and
never accepts inbound connections. It buffers telemetry and raw evidence files
until the one-way sync service delivers them to the analytics landing drop zone.

Tables
  telemetry_queue   one row per telemetry envelope (see deploy/common/telemetry_schema.py)
  upload_queue      raw evidence files / telemetry batches awaiting upload
  processing_state  collector file offsets + edge pipeline run tracking
  sync_attempts     audit log of every outbound delivery attempt
  schema_versions   applied schema migrations (with checksums)

Changes from v1:
  * FAILED rows were never retried (dequeue only read PENDING) and were EXPIRED
    after 30 days -> silent data loss. v2 retries FAILED rows with backoff and
    never expires unsynced telemetry.
  * Rows left in UPLOADING after a crash were stuck forever. v2 uses leases:
    IN_FLIGHT rows whose lease expired are picked up again.
  * dequeue was not atomic across concurrent workers. v2 uses BEGIN IMMEDIATE.
  * Timestamps were compared as strings although isoformat() drops microseconds
    when they are zero. v2 stores one fixed-width UTC format everywhere.
  * Added idempotency_key / UNIQUE sha256 (edge-side de-duplication), event
    type, severity, src/dest ports, raw-object references, retry counts and
    errors on telemetry rows, bounded capacity, corruption recovery.
===============================================================================
"""

from __future__ import annotations

import json
import logging
import math
import os
import random
import shutil
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.telemetry_schema import SEVERITIES  # noqa: E402

logger = logging.getLogger(__name__)

# REQUIRED_INPUT (per gateway): data directory on the edge host.
DEFAULT_EDGE_DATA_DIR = os.environ.get(
    "CYB691_EDGE_DATA_DIR", os.path.join(os.path.abspath(os.path.dirname(__file__)), "data"))
DEFAULT_EDGE_DB_PATH = os.environ.get(
    "CYB691_EDGE_DB_PATH", os.path.join(DEFAULT_EDGE_DATA_DIR, "edge_queue.db"))

CURRENT_SCHEMA_VERSION = 2

# Retention of rows that were already delivered (they are also in the analytics store).
DEFAULT_RETENTION_DAYS = int(os.environ.get("CYB691_EDGE_RETENTION_DAYS", "14"))
# Capacity bounds. Soft limit: shed INFO/LOW events. Hard limit: refuse writes.
DEFAULT_MAX_PENDING_ROWS = int(os.environ.get("CYB691_EDGE_MAX_PENDING_ROWS", "2000000"))
DEFAULT_MIN_FREE_DISK_BYTES = int(os.environ.get("CYB691_EDGE_MIN_FREE_BYTES", str(512 * 1024 * 1024)))
DEFAULT_LEASE_SECONDS = 300

# Status values
PENDING, IN_FLIGHT, SYNCED, FAILED, DEAD_LETTER = "PENDING", "IN_FLIGHT", "SYNCED", "FAILED", "DEAD_LETTER"
COMPLETED = "COMPLETED"
# Kept for backwards compatibility with v1 callers
SYNC_PENDING, SYNC_SYNCED, SYNC_FAILED = PENDING, SYNCED, FAILED
UPLOAD_PENDING, UPLOAD_COMPLETED, UPLOAD_FAILED = PENDING, COMPLETED, FAILED
PROC_RUNNING, PROC_COMPLETED, PROC_FAILED, PROC_CANCELLED = "RUNNING", "COMPLETED", "FAILED", "CANCELLED"

UPLOAD_KINDS = ("TELEMETRY_BATCH", "EVE_JSON", "FIREWALL_LOG", "PCAP", "CSV", "AUDIT_MANIFEST")

_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


class BufferFullError(RuntimeError):
    """Raised when the hard capacity limit (free disk) is reached."""


# ============================================================================
# Time helpers – one fixed-width UTC representation so string order == time order
# ============================================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed")
    return dt.astimezone(timezone.utc).strftime(_TS_FMT)


def calculate_backoff_seconds(retry_count: int, base_seconds: float = 2.0,
                              max_seconds: float = 900.0, jitter: bool = True) -> float:
    """Exponential backoff: min(max, base * 2^n), with jitter in [0.5, 1.0]."""
    delay = min(max_seconds, base_seconds * math.pow(2, max(0, retry_count)))
    if jitter:
        delay *= random.uniform(0.5, 1.0)
    return round(delay, 3)


def next_retry_timestamp(retry_count: int, now: Optional[datetime] = None, **kw: Any) -> str:
    return iso((now or utcnow()) + timedelta(seconds=calculate_backoff_seconds(retry_count, **kw)))


# ============================================================================
# Connection handling
# ============================================================================

def get_edge_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    target = db_path or DEFAULT_EDGE_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    # isolation_level=None -> we control transactions explicitly (BEGIN IMMEDIATE)
    conn = sqlite3.connect(target, timeout=30, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL;")  # only takes effect on a new, empty DB
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=FULL;")       # durability over speed: this is evidence
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA secure_delete=ON;")
    except sqlite3.Error:
        # A corrupt file fails here. Close the handle before re-raising: on Windows an open
        # handle blocks open_or_recover() from moving the corrupt file aside.
        conn.close()
        raise
    return conn


@contextmanager
def _tx(db_path: Optional[str] = None, immediate: bool = True) -> Iterator[sqlite3.Connection]:
    conn = get_edge_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE;" if immediate else "BEGIN;")
        yield conn
        conn.execute("COMMIT;")
    except Exception:
        try:
            conn.execute("ROLLBACK;")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


# ============================================================================
# Schema
# ============================================================================

_SEV_CHECK = ",".join(f"'{s}'" for s in SEVERITIES)
_KIND_CHECK = ",".join(f"'{k}'" for k in UPLOAD_KINDS)

_DDL = [
    f"""
    CREATE TABLE IF NOT EXISTS telemetry_queue (
        id                TEXT PRIMARY KEY,                 -- event_uuid
        schema_version    TEXT NOT NULL,
        edge_id           TEXT NOT NULL,
        event_type        TEXT NOT NULL CHECK (event_type IN
                              ('MODBUS_DPI','SURICATA_ALERT','FIREWALL_DROP','LOCAL_ALERT')),
        severity          TEXT NOT NULL CHECK (severity IN ({_SEV_CHECK})),
        timestamp_utc     TEXT NOT NULL,
        collected_at_utc  TEXT NOT NULL,
        src_ip            TEXT,
        src_port          INTEGER,
        dest_ip           TEXT,
        dest_port         INTEGER,
        protocol          TEXT,
        unit_id           INTEGER,
        function_code     INTEGER CHECK (function_code IS NULL OR function_code BETWEEN 1 AND 255),
        function_category TEXT,
        raw_ref_json      TEXT,                              -- reference to raw evidence object
        envelope_json     TEXT NOT NULL,                     -- full canonical envelope
        sha256_hash       TEXT NOT NULL UNIQUE,
        idempotency_key   TEXT NOT NULL UNIQUE,
        status            TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN
                              ('PENDING','IN_FLIGHT','SYNCED','FAILED','DEAD_LETTER')),
        retry_count       INTEGER NOT NULL DEFAULT 0,
        next_attempt_at   TEXT,
        lease_expires_at  TEXT,
        batch_id          TEXT,
        last_error        TEXT,
        created_at        TEXT NOT NULL,
        synced_at         TEXT
    );
    """,
    f"""
    CREATE TABLE IF NOT EXISTS upload_queue (
        upload_id         TEXT PRIMARY KEY,
        kind              TEXT NOT NULL CHECK (kind IN ({_KIND_CHECK})),
        local_file_path   TEXT NOT NULL,
        blob_name         TEXT NOT NULL,
        file_size_bytes   INTEGER NOT NULL,
        sha256_hash       TEXT NOT NULL,
        content_type      TEXT,
        manifest_json     TEXT,
        status            TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN
                              ('PENDING','IN_FLIGHT','COMPLETED','FAILED')),
        retry_count       INTEGER NOT NULL DEFAULT 0,
        next_attempt_at   TEXT,
        lease_expires_at  TEXT,
        last_error        TEXT,
        created_at        TEXT NOT NULL,
        completed_at      TEXT,
        UNIQUE (kind, sha256_hash)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS processing_state (
        state_id          TEXT PRIMARY KEY,
        pipeline_stage    TEXT NOT NULL,
        run_id            TEXT,
        started_at        TEXT NOT NULL,
        completed_at      TEXT,
        status            TEXT NOT NULL DEFAULT 'RUNNING' CHECK (status IN
                              ('RUNNING','COMPLETED','FAILED','CANCELLED','STATE')),
        records_processed INTEGER NOT NULL DEFAULT 0,
        records_failed    INTEGER NOT NULL DEFAULT 0,
        error_message     TEXT,
        metadata_json     TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS sync_attempts (
        attempt_id        TEXT PRIMARY KEY,
        target_endpoint   TEXT NOT NULL,
        operation         TEXT NOT NULL,
        upload_id         TEXT,
        batch_id          TEXT,
        started_at        TEXT NOT NULL,
        completed_at      TEXT,
        success           INTEGER NOT NULL DEFAULT 0,
        http_status       INTEGER,
        error_class       TEXT,
        error_message     TEXT,
        retry_number      INTEGER NOT NULL DEFAULT 0,
        backoff_seconds   REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS schema_versions (
        version     INTEGER PRIMARY KEY,
        description TEXT NOT NULL,
        applied_at  TEXT NOT NULL,
        checksum    TEXT
    );
    """,
]

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_tq_ready ON telemetry_queue (status, next_attempt_at, created_at);",
    "CREATE INDEX IF NOT EXISTS idx_tq_lease ON telemetry_queue (status, lease_expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_tq_synced ON telemetry_queue (status, synced_at);",
    "CREATE INDEX IF NOT EXISTS idx_tq_ts ON telemetry_queue (timestamp_utc);",
    "CREATE INDEX IF NOT EXISTS idx_tq_batch ON telemetry_queue (batch_id);",
    "CREATE INDEX IF NOT EXISTS idx_uq_ready ON upload_queue (status, next_attempt_at, created_at);",
    "CREATE INDEX IF NOT EXISTS idx_ps_stage ON processing_state (pipeline_stage, status);",
    "CREATE INDEX IF NOT EXISTS idx_sa_started ON sync_attempts (started_at);",
]


def _schema_checksum() -> str:
    import hashlib
    return hashlib.sha256("\n".join(_DDL + _INDEXES).encode()).hexdigest()


def _columns(conn: sqlite3.Connection, table: str) -> List[str]:
    return [r["name"] for r in conn.execute(f"PRAGMA table_info({table});")]  # table is a constant


def init_edge_db(db_path: Optional[str] = None) -> None:
    """Idempotently creates / migrates the schema to CURRENT_SCHEMA_VERSION.

    A v1 database is preserved: its tables are renamed with a _v1 suffix (never
    dropped) so that already-buffered evidence is not lost during upgrade.
    """
    with _tx(db_path) as conn:
        existing = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table';")}
        if "telemetry_queue" in existing and "idempotency_key" not in _columns(conn, "telemetry_queue"):
            logger.warning("v1 edge schema detected – preserving old tables with _v1 suffix")
            for t in ("telemetry_queue", "upload_queue", "processing_state", "sync_attempts"):
                if t in existing and f"{t}_v1" not in existing:
                    conn.execute(f"ALTER TABLE {t} RENAME TO {t}_v1;")  # constant names only
            # v1 indexes keep their names after the rename; drop them so v2 can reuse names
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL;").fetchall():
                if r["name"].startswith(("idx_tq_", "idx_uq_", "idx_ps_", "idx_sa_")):
                    conn.execute(f'DROP INDEX IF EXISTS "{r["name"]}";')
        for ddl in _DDL:
            conn.execute(ddl)
        for idx in _INDEXES:
            conn.execute(idx)
        conn.execute(
            "INSERT OR IGNORE INTO schema_versions (version, description, applied_at, checksum) "
            "VALUES (?, ?, ?, ?);",
            (CURRENT_SCHEMA_VERSION,
             "v2: leases, retry of FAILED rows, idempotency keys, bounded capacity",
             iso(utcnow()), _schema_checksum()))
    logger.info("Edge database ready at %s (schema v%d)", db_path or DEFAULT_EDGE_DB_PATH,
                CURRENT_SCHEMA_VERSION)


# ============================================================================
# Integrity, corruption recovery, safe shutdown
# ============================================================================

def run_integrity_check(db_path: Optional[str] = None, full: bool = False) -> Tuple[bool, str]:
    try:
        conn = get_edge_connection(db_path)
    except sqlite3.DatabaseError as exc:
        return False, str(exc)
    try:
        row = conn.execute("PRAGMA integrity_check;" if full else "PRAGMA quick_check;").fetchone()
        result = row[0] if row else "unknown"
        return result == "ok", result
    except sqlite3.DatabaseError as exc:
        return False, str(exc)
    finally:
        conn.close()


def open_or_recover(db_path: Optional[str] = None) -> Optional[str]:
    """Checks the database; if corrupt, moves it aside (kept for forensics) and
    creates a fresh one. Returns the quarantine path if recovery happened."""
    target = db_path or DEFAULT_EDGE_DB_PATH
    quarantined = None
    if os.path.exists(target):
        healthy, msg = run_integrity_check(target)
        if not healthy:
            stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
            quarantined = f"{target}.corrupt-{stamp}"
            logger.error("Edge DB corrupt (%s); moving to %s", msg, quarantined)
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(target + suffix):
                    shutil.move(target + suffix, quarantined + suffix)
    init_edge_db(target)
    return quarantined


def safe_shutdown(db_path: Optional[str] = None) -> None:
    """Flushes the WAL into the main DB file. Call from SIGTERM handlers."""
    conn = get_edge_connection(db_path)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        logger.info("WAL checkpoint (TRUNCATE) completed – safe shutdown")
    finally:
        conn.close()


# ============================================================================
# Capacity
# ============================================================================

def free_disk_bytes(db_path: Optional[str] = None) -> int:
    target = os.path.dirname(os.path.abspath(db_path or DEFAULT_EDGE_DB_PATH))
    return shutil.disk_usage(target).free


def _record_counter(conn: sqlite3.Connection, name: str, delta: int = 1) -> None:
    now = iso(utcnow())
    conn.execute(
        "INSERT INTO processing_state (state_id, pipeline_stage, started_at, status, records_processed) "
        "VALUES (?, 'COUNTER', ?, 'STATE', ?) "
        "ON CONFLICT(state_id) DO UPDATE SET records_processed = records_processed + excluded.records_processed, "
        "completed_at = ?;",
        (f"counter:{name}", now, delta, now))


def get_counter(name: str, db_path: Optional[str] = None) -> int:
    conn = get_edge_connection(db_path)
    try:
        row = conn.execute("SELECT records_processed FROM processing_state WHERE state_id = ?;",
                           (f"counter:{name}",)).fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


# ============================================================================
# Telemetry queue
# ============================================================================

def is_known_event(idempotency_key: str, db_path: Optional[str] = None) -> bool:
    """True if an envelope with this content hash is already in the queue (any status)."""
    conn = get_edge_connection(db_path)
    try:
        return conn.execute("SELECT 1 FROM telemetry_queue WHERE idempotency_key = ? LIMIT 1;",
                            (idempotency_key,)).fetchone() is not None
    finally:
        conn.close()


def enqueue_telemetry(envelope: Dict[str, Any], db_path: Optional[str] = None,
                      max_pending_rows: int = DEFAULT_MAX_PENDING_ROWS,
                      min_free_disk_bytes: int = DEFAULT_MIN_FREE_DISK_BYTES) -> Optional[str]:
    """Inserts a validated envelope. Returns its id, or None if it was a duplicate
    or was shed by the soft capacity policy (INFO/LOW only, counted).

    Raises BufferFullError at the hard limit so the caller raises a LOCAL alert.
    """
    if free_disk_bytes(db_path) < min_free_disk_bytes:
        raise BufferFullError("edge buffer hard limit reached (free disk below threshold)")
    mb = envelope.get("modbus") or {}
    now = iso(utcnow())
    with _tx(db_path) as conn:
        backlog = conn.execute(
            "SELECT COUNT(*) FROM telemetry_queue WHERE status IN ('PENDING','IN_FLIGHT','FAILED');"
        ).fetchone()[0]
        if backlog >= max_pending_rows and envelope.get("severity") in ("INFO", "LOW"):
            _record_counter(conn, "shed_low_severity")
            logger.warning("Soft capacity limit reached; shedding %s event", envelope.get("severity"))
            return None
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO telemetry_queue (
                id, schema_version, edge_id, event_type, severity, timestamp_utc,
                collected_at_utc, src_ip, src_port, dest_ip, dest_port, protocol,
                unit_id, function_code, function_category, raw_ref_json,
                envelope_json, sha256_hash, idempotency_key, status, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """,
            (envelope["event_uuid"], envelope["schema_version"], envelope["edge_id"],
             envelope["event_type"], envelope["severity"], envelope["timestamp_utc"],
             envelope["collected_at_utc"], envelope.get("src_ip"), envelope.get("src_port"),
             envelope.get("dest_ip"), envelope.get("dest_port"), envelope.get("protocol"),
             mb.get("unit_id"), mb.get("function_code"), mb.get("category"),
             json.dumps(envelope.get("raw_ref")) if envelope.get("raw_ref") is not None else None,
             json.dumps(envelope, sort_keys=True), envelope["sha256_hash"],
             envelope["idempotency_key"], PENDING, now))
        if cur.rowcount == 0:
            _record_counter(conn, "duplicate_suppressed")
            return None
        return envelope["event_uuid"]


def dequeue_ready_batch(limit: int = 500, db_path: Optional[str] = None,
                        lease_seconds: int = DEFAULT_LEASE_SECONDS,
                        now: Optional[datetime] = None) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """Atomically leases up to `limit` deliverable rows and returns (batch_id, envelopes).

    Deliverable = PENDING, or FAILED whose backoff elapsed, or IN_FLIGHT whose
    lease expired (crash/restart recovery). Oldest first.
    """
    now_dt = now or utcnow()
    now_s = iso(now_dt)
    with _tx(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id FROM telemetry_queue
            WHERE status = 'PENDING'
               OR (status = 'FAILED' AND (next_attempt_at IS NULL OR next_attempt_at <= ?))
               OR (status = 'IN_FLIGHT' AND lease_expires_at <= ?)
            ORDER BY created_at ASC
            LIMIT ?;
            """, (now_s, now_s, limit)).fetchall()
        if not rows:
            return None, []
        ids = [r["id"] for r in rows]
        batch_id = str(uuid.uuid4())
        lease = iso(now_dt + timedelta(seconds=lease_seconds))
        conn.executemany(
            "UPDATE telemetry_queue SET status='IN_FLIGHT', lease_expires_at=?, batch_id=? WHERE id=?;",
            [(lease, batch_id, i) for i in ids])
        qmarks = ",".join("?" for _ in ids)  # placeholders only; values are bound
        envs = [json.loads(r["envelope_json"]) for r in conn.execute(
            f"SELECT envelope_json FROM telemetry_queue WHERE id IN ({qmarks}) ORDER BY created_at;", ids)]
        return batch_id, envs


def mark_batch_synced(batch_id: str, db_path: Optional[str] = None) -> int:
    with _tx(db_path) as conn:
        cur = conn.execute(
            "UPDATE telemetry_queue SET status='SYNCED', synced_at=?, lease_expires_at=NULL, last_error=NULL "
            "WHERE batch_id=? AND status='IN_FLIGHT';", (iso(utcnow()), batch_id))
        return cur.rowcount


def mark_batch_failed(batch_id: str, error: str, db_path: Optional[str] = None,
                      now: Optional[datetime] = None) -> int:
    """Returns rows to FAILED with per-row exponential backoff. Never expires them."""
    now_dt = now or utcnow()
    with _tx(db_path) as conn:
        rows = conn.execute("SELECT id, retry_count FROM telemetry_queue WHERE batch_id=? AND status='IN_FLIGHT';",
                            (batch_id,)).fetchall()
        conn.executemany(
            "UPDATE telemetry_queue SET status='FAILED', retry_count=?, next_attempt_at=?, "
            "lease_expires_at=NULL, last_error=? WHERE id=?;",
            [(r["retry_count"] + 1, next_retry_timestamp(r["retry_count"], now=now_dt), error[:500], r["id"])
             for r in rows])
        return len(rows)


def mark_dead_letter(event_ids: List[str], error: str, db_path: Optional[str] = None) -> int:
    """Non-retryable (e.g. validation) failures. Rows are kept locally, not deleted."""
    with _tx(db_path) as conn:
        conn.executemany("UPDATE telemetry_queue SET status='DEAD_LETTER', last_error=? WHERE id=?;",
                         [(error[:500], i) for i in event_ids])
        return len(event_ids)


# v1-compatible wrappers -------------------------------------------------------
def dequeue_pending_batch(limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    return dequeue_ready_batch(limit, db_path)[1]


# ============================================================================
# Upload queue (raw evidence files and telemetry batch files)
# ============================================================================

def enqueue_upload(kind: str, local_file_path: str, blob_name: str, sha256_hash: str,
                   file_size_bytes: int, content_type: Optional[str] = None,
                   manifest: Optional[Dict[str, Any]] = None,
                   db_path: Optional[str] = None) -> Optional[str]:
    """Returns upload_id, or None if the same (kind, sha256) is already queued."""
    if kind not in UPLOAD_KINDS:
        raise ValueError(f"unknown upload kind {kind!r}")
    upload_id = str(uuid.uuid4())
    with _tx(db_path) as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO upload_queue (upload_id, kind, local_file_path, blob_name, file_size_bytes, "
            "sha256_hash, content_type, manifest_json, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (upload_id, kind, local_file_path, blob_name, file_size_bytes, sha256_hash, content_type,
             json.dumps(manifest, sort_keys=True) if manifest else None, PENDING, iso(utcnow())))
        return upload_id if cur.rowcount else None


def lease_ready_uploads(limit: int = 20, db_path: Optional[str] = None,
                        lease_seconds: int = DEFAULT_LEASE_SECONDS,
                        now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    now_dt = now or utcnow()
    now_s = iso(now_dt)
    with _tx(db_path) as conn:
        rows = [dict(r) for r in conn.execute(
            """
            SELECT * FROM upload_queue
            WHERE status = 'PENDING'
               OR (status = 'FAILED' AND (next_attempt_at IS NULL OR next_attempt_at <= ?))
               OR (status = 'IN_FLIGHT' AND lease_expires_at <= ?)
            ORDER BY created_at ASC LIMIT ?;
            """, (now_s, now_s, limit))]
        lease = iso(now_dt + timedelta(seconds=lease_seconds))
        conn.executemany("UPDATE upload_queue SET status='IN_FLIGHT', lease_expires_at=? WHERE upload_id=?;",
                         [(lease, r["upload_id"]) for r in rows])
        return rows


def get_pending_uploads(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    return lease_ready_uploads(limit, db_path)


def mark_upload_complete(upload_id: str, db_path: Optional[str] = None) -> None:
    with _tx(db_path) as conn:
        conn.execute("UPDATE upload_queue SET status='COMPLETED', completed_at=?, lease_expires_at=NULL, "
                     "last_error=NULL WHERE upload_id=?;", (iso(utcnow()), upload_id))


def mark_upload_failed(upload_id: str, error: str, db_path: Optional[str] = None,
                       now: Optional[datetime] = None) -> None:
    now_dt = now or utcnow()
    with _tx(db_path) as conn:
        row = conn.execute("SELECT retry_count FROM upload_queue WHERE upload_id=?;", (upload_id,)).fetchone()
        if row is None:
            return
        conn.execute("UPDATE upload_queue SET status='FAILED', retry_count=?, next_attempt_at=?, "
                     "lease_expires_at=NULL, last_error=? WHERE upload_id=?;",
                     (row["retry_count"] + 1, next_retry_timestamp(row["retry_count"], now=now_dt),
                      error[:500], upload_id))


# ============================================================================
# Processing state (collector offsets + run tracking)
# ============================================================================

def get_state(key: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_edge_connection(db_path)
    try:
        row = conn.execute("SELECT metadata_json FROM processing_state WHERE state_id=?;",
                           (f"state:{key}",)).fetchone()
        return json.loads(row[0]) if row and row[0] else None
    finally:
        conn.close()


def set_state(key: str, value: Dict[str, Any], db_path: Optional[str] = None) -> None:
    now = iso(utcnow())
    with _tx(db_path) as conn:
        conn.execute(
            "INSERT INTO processing_state (state_id, pipeline_stage, started_at, status, metadata_json) "
            "VALUES (?, 'STATE', ?, 'STATE', ?) ON CONFLICT(state_id) DO UPDATE SET "
            "metadata_json=excluded.metadata_json, completed_at=?;",
            (f"state:{key}", now, json.dumps(value, sort_keys=True), now))


def start_processing_run(pipeline_stage: str, run_id: str, metadata: Optional[Dict[str, Any]] = None,
                         db_path: Optional[str] = None) -> str:
    state_id = str(uuid.uuid4())
    with _tx(db_path) as conn:
        conn.execute("INSERT INTO processing_state (state_id, pipeline_stage, run_id, started_at, status, "
                     "metadata_json) VALUES (?,?,?,?, 'RUNNING', ?);",
                     (state_id, pipeline_stage, run_id, iso(utcnow()),
                      json.dumps(metadata) if metadata else None))
    return state_id


def complete_processing_run(state_id: str, records_processed: int = 0, records_failed: int = 0,
                            status: str = PROC_COMPLETED, error_message: Optional[str] = None,
                            db_path: Optional[str] = None) -> None:
    with _tx(db_path) as conn:
        conn.execute("UPDATE processing_state SET completed_at=?, status=?, records_processed=?, "
                     "records_failed=?, error_message=? WHERE state_id=?;",
                     (iso(utcnow()), status, records_processed, records_failed, error_message, state_id))


# ============================================================================
# Sync attempt audit log
# ============================================================================

def log_sync_attempt(target_endpoint: str, operation: str, success: bool, *,
                     upload_id: Optional[str] = None, batch_id: Optional[str] = None,
                     http_status: Optional[int] = None, error: Optional[BaseException] = None,
                     retry_number: int = 0, backoff_seconds: Optional[float] = None,
                     db_path: Optional[str] = None) -> str:
    """Error messages are truncated; never pass tokens/SAS URLs in target_endpoint."""
    attempt_id = str(uuid.uuid4())
    now = iso(utcnow())
    with _tx(db_path) as conn:
        conn.execute(
            "INSERT INTO sync_attempts (attempt_id, target_endpoint, operation, upload_id, batch_id, started_at, "
            "completed_at, success, http_status, error_class, error_message, retry_number, backoff_seconds) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (attempt_id, target_endpoint.split("?")[0], operation, upload_id, batch_id, now, now,
             1 if success else 0, http_status, type(error).__name__ if error else None,
             str(error)[:500] if error else None, retry_number, backoff_seconds))
    return attempt_id


# ============================================================================
# Retention
# ============================================================================

def cleanup_expired(retention_days: int = DEFAULT_RETENTION_DAYS, db_path: Optional[str] = None,
                    now: Optional[datetime] = None) -> Dict[str, int]:
    """Deletes ONLY rows already delivered (SYNCED / COMPLETED) older than the
    retention window, and old audit rows. Unsynced telemetry is never deleted."""
    cutoff = iso((now or utcnow()) - timedelta(days=retention_days))
    out: Dict[str, int] = {}
    with _tx(db_path) as conn:
        out["telemetry_queue"] = conn.execute(
            "DELETE FROM telemetry_queue WHERE status='SYNCED' AND synced_at < ?;", (cutoff,)).rowcount
        out["upload_queue"] = conn.execute(
            "DELETE FROM upload_queue WHERE status='COMPLETED' AND completed_at < ?;", (cutoff,)).rowcount
        out["sync_attempts"] = conn.execute(
            "DELETE FROM sync_attempts WHERE started_at < ?;", (cutoff,)).rowcount
    conn = get_edge_connection(db_path)
    try:
        conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
        conn.execute("PRAGMA incremental_vacuum;")
    finally:
        conn.close()
    return out


def get_queue_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    conn = get_edge_connection(db_path)
    try:
        stats: Dict[str, Any] = {"telemetry": {}, "uploads": {}}
        for r in conn.execute("SELECT status, COUNT(*) c FROM telemetry_queue GROUP BY status;"):
            stats["telemetry"][r["status"]] = r["c"]
        for r in conn.execute("SELECT status, COUNT(*) c FROM upload_queue GROUP BY status;"):
            stats["uploads"][r["status"]] = r["c"]
        oldest = conn.execute("SELECT MIN(created_at) FROM telemetry_queue WHERE status IN "
                              "('PENDING','IN_FLIGHT','FAILED');").fetchone()[0]
        stats["oldest_unsynced_created_at"] = oldest
        return stats
    finally:
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    q = open_or_recover()
    if q:
        print(f"[!] corrupt DB quarantined at {q}")
    ok, msg = run_integrity_check(full=True)
    print(f"[{'+' if ok else '!'}] integrity: {msg}")
    print(json.dumps(get_queue_stats(), indent=2))
