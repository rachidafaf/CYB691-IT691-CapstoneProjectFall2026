"""PostgreSQL integration tests: migrations, idempotent writes, RBAC violations,
append-only audit, SQL-injection safety, partition fallback.

Runs only when CYB691_PG_TEST=1 and psycopg2 is installed. Point PGHOST/PGUSER/
PGPASSWORD (or PGPASSWORD_FILE) at a PostgreSQL 16 database where PGUSER is the
schema owner (svc_migrate in the Compose stack); CI uses a service container.
"""

import os
from datetime import datetime, timezone

import pytest

psycopg2 = pytest.importorskip("psycopg2")
pytestmark = pytest.mark.skipif(os.environ.get("CYB691_PG_TEST") != "1", reason="CYB691_PG_TEST!=1")

from conftest import DEPLOY, make_env  # noqa: E402


@pytest.fixture(scope="module")
def migrated():
    from analytics import migrate
    migrate.run(os.path.join(DEPLOY, "analytics", "migrations"))
    assert migrate.run(os.path.join(DEPLOY, "analytics", "migrations"), verify_only=True) == 0  # repeatable
    return True


@pytest.fixture
def store(migrated):
    from analytics.pg_connection import ConnectionPool
    from analytics.pg_writer import PgStore
    return PgStore(ConnectionPool())


def test_idempotent_batch_write(store):
    from analytics.pg_writer import new_run_id
    run = new_run_id()
    store.start_run(run, "test", "INGEST", {})
    envs = [make_env(i, edge="edge-pg") for i in range(50)]
    assert store.write_events(envs, batch_id=None, manifest_id=None, run_id=run) == (50, 0)
    assert store.write_events(envs, batch_id=None, manifest_id=None, run_id=run) == (0, 50)


def test_nul_bytes_in_raw_payload_are_stored(store):
    """Regression for the captured handoff: Modbus write data contains U+0000."""
    from analytics.pg_writer import new_run_id
    e = make_env(3, fc=6, edge="edge-pg-nul")
    e["raw"] = {"modbus": {"request": {"write": {"address": 0, "data": "\x00\x00"}}}}
    assert store.write_events([e], batch_id=None, manifest_id=None, run_id=new_run_id()) == (1, 0)


def test_out_of_range_timestamp_lands_in_default_partition(store):
    from analytics.pg_writer import new_run_id
    e = make_env(1, edge="edge-pg-old", ts=datetime(2021, 1, 1, tzinfo=timezone.utc))
    assert store.write_events([e], batch_id=None, manifest_id=None, run_id=new_run_id())[0] == 1


def test_sql_injection_is_inert(store):
    from analytics.pg_writer import new_run_id
    e = make_env(7, edge="x'); DROP TABLE telemetry_events; --")
    store.write_events([e], batch_id=None, manifest_id=None, run_id=new_run_id())
    with store.pool.connection() as c, c.cursor() as cur:
        cur.execute("SELECT count(*) FROM telemetry_events WHERE edge_id = %s", (e["edge_id"],))
        assert cur.fetchone()[0] == 1


def test_audit_events_are_append_only(store):
    store.audit("test", "TEST", "x", "1")
    with pytest.raises(psycopg2.Error):
        with store.pool.connection() as c, c.cursor() as cur:
            cur.execute("UPDATE audit_events SET action='TAMPER'")


@pytest.mark.parametrize("role,stmt", [
    ("cyb691_readonly", "INSERT INTO incidents (incident_id, severity, rule, title, first_seen_utc, last_seen_utc) "
                        "VALUES ('x','LOW','r','t',now(),now())"),
    ("cyb691_ingestion", "DELETE FROM telemetry_events"),
    ("cyb691_ingestion", "UPDATE telemetry_events SET severity='INFO'"),
    ("cyb691_analytics", "DELETE FROM ml_predictions"),
    ("cyb691_analytics", "TRUNCATE telemetry_events"),
])
def test_rbac_violations_are_denied(store, role, stmt):
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with store.pool.connection() as c, c.cursor() as cur:
            cur.execute(f"SET ROLE {role}")
            cur.execute(stmt)


def test_migration_checksum_drift_detected(migrated, tmp_path):
    import shutil
    from analytics import migrate
    d = tmp_path / "m"
    shutil.copytree(os.path.join(DEPLOY, "analytics", "migrations"), d)
    p = d / "V003__reporting_views.sql"
    p.write_text(p.read_text() + "\n-- edited after apply\n")
    with pytest.raises(SystemExit, match="checksum drift"):
        migrate.run(str(d), verify_only=True)
