"""Unit + recovery tests for the edge SQLite store-and-forward buffer."""

import os
import sqlite3
from datetime import timedelta

import pytest

from conftest import make_env, read_jsonl
from edge import edge_database as db
from edge import edge_collector as ec


def test_schema_tables_wal_and_version(edge_db):
    conn = db.get_edge_connection(edge_db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"telemetry_queue", "upload_queue", "processing_state", "sync_attempts", "schema_versions"} <= names
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0] == db.CURRENT_SCHEMA_VERSION
    cols = {r[1] for r in conn.execute("PRAGMA table_info(telemetry_queue)")}
    for c in ("id", "timestamp_utc", "src_ip", "dest_ip", "function_code", "event_type", "severity",
              "raw_ref_json", "sha256_hash", "retry_count", "status", "last_error", "idempotency_key"):
        assert c in cols
    conn.close()
    db.init_edge_db(edge_db)          # idempotent re-init


def test_v1_database_is_preserved_on_upgrade(tmp_path):
    p = str(tmp_path / "v1.db")
    conn = sqlite3.connect(p)
    conn.execute("CREATE TABLE telemetry_queue (id TEXT PRIMARY KEY, sha256_hash TEXT NOT NULL, created_at TEXT)")
    conn.execute("CREATE INDEX idx_tq_sync_status ON telemetry_queue (created_at)")
    conn.execute("INSERT INTO telemetry_queue VALUES ('old-1', 'abc', '2026-01-01')")
    conn.commit()
    conn.close()
    db.init_edge_db(p)
    conn = sqlite3.connect(p)
    assert conn.execute("SELECT COUNT(*) FROM telemetry_queue_v1").fetchone()[0] == 1
    assert "idempotency_key" in {r[1] for r in conn.execute("PRAGMA table_info(telemetry_queue)")}


def test_duplicate_events_suppressed_at_edge(edge_db):
    e = make_env(1)
    assert db.enqueue_telemetry(e, edge_db) == e["event_uuid"]
    again = dict(e, event_uuid="00000000-0000-4000-8000-000000000000")   # re-read of same log line
    assert db.enqueue_telemetry(again, edge_db) is None
    assert db.get_counter("duplicate_suppressed", edge_db) == 1


def test_sql_injection_payload_is_stored_literally(edge_db):
    evil = "'); DROP TABLE telemetry_queue; --"
    e = make_env(2, edge=evil)
    db.enqueue_telemetry(e, edge_db)
    _, batch = db.dequeue_ready_batch(10, edge_db)
    assert batch[0]["edge_id"] == evil
    conn = db.get_edge_connection(edge_db)
    assert conn.execute("SELECT COUNT(*) FROM telemetry_queue").fetchone()[0] == 1


def test_lease_recovery_after_container_restart(edge_db, clock):
    for i in range(5):
        db.enqueue_telemetry(make_env(i), edge_db)
    batch_id, envs = db.dequeue_ready_batch(10, edge_db, lease_seconds=60)
    assert len(envs) == 5
    # process "crashes": rows stay IN_FLIGHT; nothing is deliverable before the lease ends
    assert db.dequeue_ready_batch(10, edge_db)[1] == []
    clock.advance(seconds=61)
    b2, again = db.dequeue_ready_batch(10, edge_db)
    assert len(again) == 5 and b2 != batch_id


def test_failed_rows_are_retried_with_backoff_and_never_expire(edge_db, clock):
    db.enqueue_telemetry(make_env(1), edge_db)
    for attempt in range(12):
        bid, envs = db.dequeue_ready_batch(10, edge_db)
        assert len(envs) == 1, f"row not retried on attempt {attempt}"
        db.mark_batch_failed(bid, "network down", edge_db)
        assert db.dequeue_ready_batch(10, edge_db)[1] == []           # backoff in force
        clock.advance(seconds=901)                                     # > max backoff
    db.cleanup_expired(retention_days=1, db_path=edge_db, now=clock() + timedelta(days=60))
    stats = db.get_queue_stats(edge_db)
    assert stats["telemetry"] == {"FAILED": 1}


def test_backoff_is_exponential_and_capped():
    vals = [db.calculate_backoff_seconds(n, jitter=False) for n in range(15)]
    assert vals[:4] == [2.0, 4.0, 8.0, 16.0]
    assert max(vals) == 900.0
    for n in range(10):
        assert 0.5 * min(900, 2 * 2 ** n) <= db.calculate_backoff_seconds(n) <= min(900, 2 * 2 ** n)


def test_queue_growth_soft_limit_sheds_only_low_severity(edge_db):
    for i in range(5):
        db.enqueue_telemetry(make_env(i, fc=3), edge_db, max_pending_rows=5)
    assert db.enqueue_telemetry(make_env(10, fc=3), edge_db, max_pending_rows=5) is None      # INFO shed
    assert db.enqueue_telemetry(make_env(11, fc=6), edge_db, max_pending_rows=5) is not None  # HIGH kept
    assert db.get_counter("shed_low_severity", edge_db) == 1


def test_disk_exhaustion_raises_and_local_alerting_continues(edge_db, tmp_path, monkeypatch):
    monkeypatch.setattr(db, "free_disk_bytes", lambda *_: 1024)
    with pytest.raises(db.BufferFullError):
        db.enqueue_telemetry(make_env(1), edge_db)
    alerts = str(tmp_path / "alerts.jsonl")
    c = ec.Collector("edge-test-01", db_path=edge_db, alerter=ec.LocalAlerter(alerts),
                     quarantine_path=str(tmp_path / "q.jsonl"))
    c.ingest_envelope(make_env(2, fc=6, src="10.0.1.4"), "eve", "{}")
    rules = [a["rule"] for a in read_jsonl(alerts)]
    assert "UNAUTHORISED_MODBUS_WRITE" in rules and "EDGE_BUFFER_FULL" in rules


def test_corruption_check_and_recovery(tmp_path):
    p = str(tmp_path / "c.db")
    db.init_edge_db(p)
    db.safe_shutdown(p)
    with open(p, "r+b") as f:
        f.seek(0)
        f.write(b"\x00" * 100)        # destroy the header
    ok, _ = db.run_integrity_check(p)
    assert not ok
    quarantined = db.open_or_recover(p)
    assert quarantined and os.path.exists(quarantined)
    assert db.run_integrity_check(p)[0]


def test_retention_deletes_only_synced_rows(edge_db, clock):
    for i in range(3):
        db.enqueue_telemetry(make_env(i), edge_db)
    bid, _ = db.dequeue_ready_batch(2, edge_db)
    db.mark_batch_synced(bid, edge_db)
    out = db.cleanup_expired(retention_days=7, db_path=edge_db, now=clock() + timedelta(days=8))
    assert out["telemetry_queue"] == 2
    assert db.get_queue_stats(edge_db)["telemetry"] == {"PENDING": 1}


def test_fixed_width_timestamps_sort_correctly():
    from datetime import datetime, timezone
    a = db.iso(datetime(2026, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc))
    b = db.iso(datetime(2026, 1, 1, 0, 0, 0, 1, tzinfo=timezone.utc))
    assert len(a) == len(b) and a < b
    with pytest.raises(ValueError):
        db.iso(datetime(2026, 1, 1))


def test_safe_shutdown_checkpoints_wal(edge_db):
    db.enqueue_telemetry(make_env(1), edge_db)
    db.safe_shutdown(edge_db)
    wal = edge_db + "-wal"
    assert not os.path.exists(wal) or os.path.getsize(wal) == 0


def test_failed_connection_setup_closes_handle(tmp_path, monkeypatch):
    """Regression (Windows): a corrupt file made a PRAGMA fail inside get_edge_connection and
    the open handle leaked, so open_or_recover() could not move the file aside."""
    p = tmp_path / "bad.db"
    p.write_bytes(b"\x00" * 4096)
    closed = []
    real_connect = sqlite3.connect

    class Tracked:
        def __init__(self, *a, **k):
            self._c = real_connect(*a, **k)

        def __getattr__(self, name):
            return getattr(self._c, name)

        def __setattr__(self, name, value):
            if name == "_c":
                object.__setattr__(self, name, value)
            else:
                setattr(self._c, name, value)

        def close(self):
            closed.append(True)
            self._c.close()

    monkeypatch.setattr(db.sqlite3, "connect", Tracked)
    with pytest.raises(sqlite3.DatabaseError):
        db.get_edge_connection(str(p))
    assert closed == [True]
