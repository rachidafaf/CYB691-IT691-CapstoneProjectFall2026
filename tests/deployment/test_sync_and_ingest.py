"""Integration (in-process) and recovery tests for the edge -> landing drop zone ->
analytics path: 24 h outage, duplicates/retries, interrupted delivery, PostgreSQL
failure, hash mismatch, unwritable drop zone, container restart, evidence traceability."""

import gzip
import json
import os
from datetime import timedelta

import pytest

from conftest import make_env
from analytics.object_store import FileObjectStore, ObjectTooLarge
from analytics.pg_writer import MemoryStore
from analytics import telemetry_sync as tsmod
from analytics.telemetry_sync import TelemetrySync, bounded_gunzip
from common.telemetry_schema import sha256_bytes
from edge import edge_database as db
from edge import sync_service as ss


@pytest.fixture
def pipeline(tmp_path, edge_db):
    root = str(tmp_path / "objects")
    transport = ss.DropZoneTransport(os.path.join(root, "landing"))
    os.makedirs(transport.root)
    svc = ss.SyncService(transport, "edge-test-01", edge_db, batch_size=100)
    objects = FileObjectStore(root)
    store = MemoryStore()
    return svc, transport, objects, store, TelemetrySync(objects, store)


def test_end_to_end_exactly_once(pipeline, edge_db):
    svc, _, objects, store, analytics = pipeline
    envs = [make_env(i, fc=6 if i % 2 else 3) for i in range(250)]
    for e in envs:
        db.enqueue_telemetry(e, edge_db)
    assert svc.run_cycle() == 250
    r = analytics.run_once()
    assert r["output"] == 250 and r["failed"] == 0
    assert set(store.events) == {e["idempotency_key"] for e in envs}
    assert list(objects.list("landing")) == []
    assert len(store.details["modbus_transactions"]) == 250


def test_analytics_unavailable_24h_no_loss(pipeline, edge_db, clock):
    svc, transport, objects, store, analytics = pipeline
    sent = set()
    # 24 h outage; 1 event every 30 s (2880 events) arriving while every delivery fails
    transport.fail_next = 10 ** 9
    for minute in range(24 * 60):
        for k in range(2):
            e = make_env(minute * 2 + k, ts=clock() - timedelta(hours=1))
            db.enqueue_telemetry(e, edge_db)
            sent.add(e["idempotency_key"])
        if minute % 15 == 0:
            with pytest.raises(ss.TransientError):
                svc.run_cycle()
        clock.advance(minutes=1)
    stats = db.get_queue_stats(edge_db)
    assert sum(stats["telemetry"].values()) == len(sent) == 2880
    assert "SYNCED" not in stats["telemetry"]
    # connectivity restored; let any backoff elapse
    transport.fail_next = 0
    clock.advance(seconds=901)
    delivered = 0
    for _ in range(100):
        delivered += svc.run_cycle()
        if not db.get_queue_stats(edge_db)["telemetry"].get("FAILED") and \
           not db.get_queue_stats(edge_db)["telemetry"].get("PENDING"):
            break
        clock.advance(seconds=901)
    analytics.run_once()
    assert set(store.events) == sent
    assert db.get_queue_stats(edge_db)["telemetry"] == {"SYNCED": 2880}


def test_duplicate_deliveries_and_retries_do_not_duplicate_events(pipeline, edge_db, tmp_path):
    svc, _, objects, store, analytics = pipeline
    envs = [make_env(i) for i in range(20)]
    for e in envs:
        db.enqueue_telemetry(e, edge_db)
    svc.run_cycle()
    # simulate the edge re-sending the same events in a new batch (lost ack)
    landing = os.path.join(str(tmp_path / "objects"), "landing")
    replay = ss.SyncService(ss.DropZoneTransport(landing), "edge-test-01", str(tmp_path / "replay.db"))
    db.init_edge_db(str(tmp_path / "replay.db"))
    import uuid
    for e in envs:   # same raw records re-collected after a restart: new event_uuid, same content hash
        db.enqueue_telemetry(dict(e, event_uuid=str(uuid.uuid4())), str(tmp_path / "replay.db"))
    replay.run_cycle()
    r = analytics.run_once()
    assert len(store.events) == 20
    assert r["output"] == 20 and r["duplicate"] == 20
    assert analytics.run_once()["manifests"] == 0      # re-run is a no-op


def test_byte_identical_batch_redelivery_is_skipped_at_manifest_level(pipeline, edge_db, tmp_path):
    svc, _, objects, store, analytics = pipeline
    envs = [make_env(i) for i in range(5)]
    for e in envs:
        db.enqueue_telemetry(e, edge_db)
    svc.run_cycle()
    analytics.run_once()
    replay_db = str(tmp_path / "replay2.db")
    db.init_edge_db(replay_db)
    for e in envs:
        db.enqueue_telemetry(e, replay_db)
    ss.SyncService(ss.DropZoneTransport(os.path.join(str(tmp_path / "objects"), "landing")),
                   "edge-test-01", replay_db).run_cycle()
    r = analytics.run_once()
    assert r["duplicate"] == 1 and r["output"] == 0 and len(store.events) == 5


def test_delivery_interruption_manifest_missing(pipeline, edge_db, tmp_path):
    svc, transport, objects, store, analytics = pipeline
    for i in range(5):
        db.enqueue_telemetry(make_env(i), edge_db)

    calls = {"n": 0}
    real_put = transport.put

    def flaky(name, *a, **k):
        calls["n"] += 1
        if name.endswith(".manifest.json"):
            raise ss.TransientError("drop zone write interrupted during manifest")
        return real_put(name, *a, **k)

    transport.put = flaky
    with pytest.raises(ss.TransientError):
        svc.run_cycle()
    assert analytics.run_once()["manifests"] == 0          # orphan object without manifest is ignored
    assert store.events == {}
    transport.put = real_put
    bid, envs = db.dequeue_ready_batch(100, edge_db, now=db.utcnow() + timedelta(hours=1))
    db.mark_batch_failed(bid, "x", edge_db, now=db.utcnow() - timedelta(hours=1))
    svc.run_cycle()
    assert analytics.run_once()["output"] == 5


def test_postgresql_failure_keeps_landing_and_recovers(pipeline, edge_db):
    svc, _, objects, store, analytics = pipeline
    for i in range(10):
        db.enqueue_telemetry(make_env(i), edge_db)
    svc.run_cycle()
    store.fail_writes = 1
    r = analytics.run_once()
    assert r["output"] == 0 and store.events == {}
    assert any(n.endswith(".manifest.json") for n in objects.list("landing"))   # retained for retry
    r = analytics.run_once()
    assert r["output"] == 10


def test_hash_mismatch_is_quarantined_not_ingested(pipeline, edge_db, tmp_path):
    svc, _, objects, store, analytics = pipeline
    for i in range(3):
        db.enqueue_telemetry(make_env(i), edge_db)
    svc.run_cycle()
    obj = [n for n in objects.list("landing") if n.endswith(".ndjson.gz")][0]
    path = os.path.join(str(tmp_path / "objects"), "landing", obj)
    with open(path, "ab") as f:
        f.write(b"tampered")
    r = analytics.run_once()
    assert r["failed"] == 1 and store.events == {}
    assert any(m["verification_status"] == "HASH_MISMATCH" for m in store.manifests.values())
    assert any(a["action"] == "EVIDENCE_HASH_MISMATCH" for a in store.audits)
    assert any(n.endswith(".reason.json") for n in objects.list("quarantine"))


def test_invalid_events_inside_valid_batch_are_quarantined(pipeline, edge_db, tmp_path):
    svc, _, objects, store, analytics = pipeline
    good = make_env(1)
    bad = make_env(2)
    bad["modbus"]["function_code"] = 999          # not re-hashed -> invalid twice over
    raw = (json.dumps(good) + "\n" + json.dumps(bad) + "\n").encode()
    data = gzip.compress(raw, mtime=0)
    landing = os.path.join(str(tmp_path / "objects"), "landing", "telemetry", "x")
    os.makedirs(landing)
    open(os.path.join(landing, "b.ndjson.gz"), "wb").write(data)
    open(os.path.join(landing, "b.ndjson.gz.manifest.json"), "w").write(json.dumps(
        {"edge_id": "edge-test-01", "object_sha256": sha256_bytes(data), "object_size_bytes": len(data),
         "batch_id": "00000000-0000-4000-8000-000000000001"}))
    r = analytics.run_once()
    assert r["output"] == 1 and r["failed"] == 1
    assert any(".invalid.ndjson" in n for n in objects.list("quarantine"))


def test_gzip_bomb_is_bounded():
    data = gzip.compress(b"0" * (5 * 1024 * 1024))
    with pytest.raises(ObjectTooLarge):
        bounded_gunzip(data, limit=1024 * 1024)


def test_unmounted_drop_zone_keeps_data_queued(pipeline, edge_db, tmp_path):
    svc, *_ = pipeline
    svc.t = ss.DropZoneTransport(str(tmp_path / "not-mounted"))
    db.enqueue_telemetry(make_env(1), edge_db)
    with pytest.raises(ss.TransientError):
        svc.run_cycle()
    assert db.get_queue_stats(edge_db)["telemetry"] == {"FAILED": 1}
    conn = db.get_edge_connection(edge_db)
    row = conn.execute("SELECT error_class, error_message FROM sync_attempts").fetchone()
    assert row[0] == "TransientError" and "not mounted" in row[1]


def test_drop_zone_never_overwrites_different_content(tmp_path):
    t = ss.DropZoneTransport(str(tmp_path))
    assert t.put("a/b.ndjson.gz", b"one", sha256_bytes(b"one"), "x", {}) is True
    assert t.put("a/b.ndjson.gz", b"one", sha256_bytes(b"one"), "x", {}) is False    # idempotent
    with pytest.raises(ss.ConflictError):
        t.put("a/b.ndjson.gz", b"two", sha256_bytes(b"two"), "x", {})
    with pytest.raises(ss.ConflictError):
        t.put("../escape", b"x", sha256_bytes(b"x"), "x", {})
    assert open(tmp_path / "a" / "b.ndjson.gz", "rb").read() == b"one"


def test_object_store_rejects_path_traversal(tmp_path):
    store = FileObjectStore(str(tmp_path))
    with pytest.raises(ValueError):
        store.write("landing", "../../etc/passwd", b"x")
    assert store.write("quarantine", "x/y.json", b"1") and not store.write("quarantine", "x/y.json", b"2")
    assert store.read("quarantine", "x/y.json") == b"1"


def test_nul_bytes_in_captured_payloads_are_postgres_safe():
    """Regression: the captured handoff has Modbus writes whose Suricata `data` field is
    "\\u0000\\u0000". PostgreSQL JSONB/TEXT reject U+0000, which made every batch roll back."""
    from analytics.pg_writer import _j, pg_safe
    raw = json.loads('{"modbus": {"request": {"write": {"address": 0, "data": "\\u0000\\u0000"}}}}')
    assert "\x00" in raw["modbus"]["request"]["write"]["data"]
    out = _j(raw)
    assert "\x00" not in out and "\\u0000" not in out.replace("\\\\u0000", "")
    assert json.loads(out)["modbus"]["request"]["write"]["data"] == "\\u0000\\u0000"   # literal text
    assert pg_safe(("a\x00", 1, None)) == ["a\\u0000", 1, None]
    env = make_env(1, fc=6)
    env["raw"] = raw
    assert "\x00" not in json.dumps(pg_safe(env), ensure_ascii=False)


def test_local_evidence_hash_mismatch_is_not_uploaded(pipeline, edge_db, tmp_path):
    svc, _, objects, *_ = pipeline
    f = tmp_path / "capture.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    from edge.edge_collector import enqueue_evidence_file
    enqueue_evidence_file(str(f), "PCAP", "edge-test-01", edge_db)
    f.write_bytes(b"changed after hashing")
    assert svc.sync_uploads_once() == 0
    assert list(objects.list("landing")) == []


def test_evidence_traceability(pipeline, edge_db):
    svc, _, objects, store, analytics = pipeline
    for i in range(7):
        db.enqueue_telemetry(make_env(i), edge_db)
    svc.run_cycle()
    analytics.run_once()
    for e in store.events.values():
        m = store.manifests[e["evidence_manifest_id"]]
        assert m["verification_status"] == "VERIFIED" and e["run_id"] in store.runs
        data = objects.read(m["container"], m["blob_name"])
        assert sha256_bytes(data) == m["sha256_hash"]
        assert e["idempotency_key"] in m["manifest"]["event_idempotency_keys"]
        assert objects.exists("audit-manifests", f"{m['container']}/{m['blob_name']}.manifest.json")


def test_raw_evidence_file_path_and_reconciliation(pipeline, edge_db, tmp_path, lab_files):
    svc, _, objects, store, analytics = pipeline
    from edge.edge_collector import Collector, LocalAlerter, snapshot_raw_range
    from analytics import jobs
    eve, fw = lab_files
    c = Collector("edge-test-01", db_path=edge_db, alerter=LocalAlerter(str(tmp_path / "a")),
                  quarantine_path=str(tmp_path / "q"))
    c.poll_once(eve, fw)
    snapshot_raw_range(eve, "EVE_JSON", "edge-test-01", edge_db, str(tmp_path / "out"))
    snapshot_raw_range(fw, "FIREWALL_LOG", "edge-test-01", edge_db, str(tmp_path / "out"))
    svc.run_cycle()
    analytics.run_once()
    r = jobs.log_parser(objects, store)
    assert r["objects"] == 2 and r["output"] == 0 and r["duplicate"] == 23   # raw == normalised
    # delete one normalised event: reconciliation must detect and backfill it
    k = next(k for k, e in store.events.items() if e["event_type"] != "LOCAL_ALERT")
    del store.events[k]
    for name in list(objects.list("audit-manifests", "reconciled/")):
        objects.delete("audit-manifests", name)
    assert jobs.log_parser(objects, store)["output"] == 1


def test_timeline_incidents_are_idempotent(pipeline, edge_db, tmp_path, lab_files):
    svc, _, objects, store, analytics = pipeline
    from edge.edge_collector import Collector, LocalAlerter, LocalDetector
    from analytics import jobs
    eve, fw = lab_files
    Collector("edge-test-01", db_path=edge_db, detector=LocalDetector(["10.0.2.10/32"], {1, 3, 5, 6, 16}),
              alerter=LocalAlerter(str(tmp_path / "a")), quarantine_path=str(tmp_path / "q")).poll_once(eve, fw)
    svc.run_cycle()
    analytics.run_once()
    first = jobs.timeline(objects, store, hours=24 * 3650)
    n = len(store.incidents)
    jobs.timeline(objects, store, hours=24 * 3650)
    assert n == len(store.incidents) == first["output"] and n > 0


def test_container_restart_mid_batch(pipeline, edge_db, clock):
    svc, transport, objects, store, analytics = pipeline
    for i in range(10):
        db.enqueue_telemetry(make_env(i), edge_db)
    db.dequeue_ready_batch(100, edge_db, lease_seconds=300)    # leased, then the container dies
    assert svc.run_cycle() == 0
    clock.advance(seconds=301)
    assert svc.run_cycle() == 10
    analytics.run_once()
    assert len(store.events) == 10
