"""Validation of telemetry (invalid Modbus, timestamp errors, hash mismatch) and
edge collector behaviour (normalisation, quarantine, local fallback detection)."""

from datetime import datetime, timedelta, timezone

import pytest

from conftest import make_env, read_jsonl
from common.telemetry_schema import (ValidationError, compute_sha256, parse_utc, validate_envelope)
from common.normalizers import normalise_firewall_line
from edge import edge_collector as ec
from edge import edge_database as db

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def rehash(e):
    e["sha256_hash"] = e["idempotency_key"] = compute_sha256(e)
    return e


@pytest.mark.parametrize("fc", [0, 256, -1, "6", 3.5, True, None])
def test_invalid_modbus_function_codes_rejected(fc):
    e = make_env(1)
    e["modbus"]["function_code"] = fc
    with pytest.raises(ValidationError):
        validate_envelope(rehash(e), now=NOW)


@pytest.mark.parametrize("field,value", [("unit_id", 300), ("address", 70000), ("quantity", -1)])
def test_invalid_modbus_fields_rejected(field, value):
    e = make_env(1)
    e["modbus"][field] = value
    with pytest.raises(ValidationError):
        validate_envelope(rehash(e), now=NOW)


def test_invalid_ip_and_port_rejected():
    e = make_env(1)
    e["src_ip"] = "10.0.0.999"
    with pytest.raises(ValidationError):
        validate_envelope(rehash(e), now=NOW)
    e = make_env(1)
    e["dest_port"] = 70000
    with pytest.raises(ValidationError):
        validate_envelope(rehash(e), now=NOW)


@pytest.mark.parametrize("ts", ["2019-12-31T23:59:59+00:00",          # before sanity window
                                "2026-10-02T00:10:00+00:00",          # > 5 min in the future
                                "2026-10-01T12:00:00",                # naive (no zone)
                                "yesterday"])
def test_timestamp_errors_rejected(ts):
    e = make_env(1)
    e["timestamp_utc"] = ts
    with pytest.raises(ValidationError):
        validate_envelope(rehash(e), now=NOW)


def test_suricata_offset_format_parsed():
    assert parse_utc("2026-09-26T18:46:26.607796+0000").utcoffset() == timedelta(0)


def test_hash_mismatch_detected():
    e = make_env(1)
    e["src_ip"] = "10.0.1.99"                                        # tampered after hashing
    with pytest.raises(ValidationError, match="sha256"):
        validate_envelope(e, now=NOW)


def test_hash_ignores_ingestion_metadata():
    a, b = make_env(1), make_env(1)
    assert a["event_uuid"] != b["event_uuid"] and a["sha256_hash"] == b["sha256_hash"]


def test_collector_normalises_quarantines_and_alerts(edge_db, tmp_path, lab_files):
    eve, fw = lab_files
    alerts, quarantine = str(tmp_path / "a.jsonl"), str(tmp_path / "q.jsonl")
    c = ec.Collector("edge-test-01", db_path=edge_db,
                     detector=ec.LocalDetector(["10.0.2.10/32"], {1, 2, 3, 4, 5, 6, 15, 16}),
                     alerter=ec.LocalAlerter(alerts), quarantine_path=quarantine)
    n = c.poll_once(eve, fw)
    assert n == 20 + 1 + 2           # 20 Modbus, 1 Suricata alert, 2 firewall drops
    q = read_jsonl(quarantine)
    assert len(q) == 3               # bad timestamp, FC 999, non-JSON line
    rules = [a["rule"] for a in read_jsonl(alerts)]
    assert rules.count("UNAUTHORISED_MODBUS_WRITE") == 12
    assert rules.count("BLOCKED_MODBUS_ATTEMPT") == 2
    assert "SURICATA_HIGH_SEVERITY" in rules
    # restart: offsets persisted -> nothing re-ingested
    assert c.poll_once(eve, fw) == 0


def test_collector_handles_log_rotation(edge_db, tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("")
    c = ec.Collector("edge-test-01", db_path=edge_db, alerter=ec.LocalAlerter(str(tmp_path / "a")),
                     quarantine_path=str(tmp_path / "q"))
    line = '{"timestamp":"2026-10-01T12:00:00.000000+0000","event_type":"modbus","src_ip":"10.0.2.10",' \
           '"dest_ip":"10.0.3.10","dest_port":502,"modbus":{"request":{"function_raw":3,"unit_id":1}}}\n'
    eve.write_text(line)
    assert c.poll_once(str(eve), "/nonexistent") == 1
    eve.unlink()
    eve.write_text(line.replace("12:00:00", "12:00:01"))           # rotated file, new inode
    assert c.poll_once(str(eve), "/nonexistent") == 1


def test_partial_lines_wait_for_writer(edge_db, tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text('{"timestamp":"2026-10-01T12:00:00')
    lines, _ = ec.read_new_lines(str(eve), "k", edge_db)
    assert lines == []


def test_empty_firewall_marker_ignored():
    assert normalise_firewall_line("-- No entries --", "e", {}) is None


def test_burst_detection():
    d = ec.LocalDetector(["10.0.2.10/32"], {3}, burst_window=1.0, burst_threshold=5)
    fired = []
    for i in range(6):
        fired += [a["rule"] for a in d.evaluate(make_env(i, fc=3), now_monotonic=100 + i * 0.01)]
    assert fired.count("MODBUS_BURST") == 1


def test_raw_snapshot_chunks_are_hashed_and_queued(edge_db, tmp_path):
    f = tmp_path / "eve.json"
    f.write_text('{"a":1}\n')
    uid = ec.snapshot_raw_range(str(f), "EVE_JSON", "edge-test-01", edge_db, str(tmp_path / "out"))
    assert uid
    assert ec.snapshot_raw_range(str(f), "EVE_JSON", "edge-test-01", edge_db, str(tmp_path / "out")) is None
    ups = db.lease_ready_uploads(10, edge_db)
    assert len(ups) == 1 and len(ups[0]["sha256_hash"]) == 64


def test_duplicate_raw_records_raise_one_local_alert(edge_db, tmp_path):
    """The captured eve.json logs every Modbus record twice; the edge must alert once per event."""
    import json as _json
    line = _json.dumps({"timestamp": "2026-09-23T03:18:40.337284+0000", "event_type": "modbus", "flow_id": 7,
                        "src_ip": "10.0.1.4", "src_port": 47766, "dest_ip": "172.17.0.2", "dest_port": 5020,
                        "proto": "TCP", "modbus": {"request": {"transaction_id": 5, "unit_id": 1,
                        "function_raw": 5, "function_code": "WrSingleCoil", "write": {"address": 0, "data": 65280}}}})
    eve = tmp_path / "eve.json"
    eve.write_text(line + "\n" + line + "\n")
    fw = tmp_path / "fw.log"
    fw.write_text("")
    alerts = tmp_path / "alerts.jsonl"
    c = ec.Collector("edge-test-01", db_path=edge_db, detector=ec.LocalDetector([], {1, 3, 5, 6, 16}),
                     alerter=ec.LocalAlerter(str(alerts)), quarantine_path=str(tmp_path / "q.jsonl"))
    c.poll_once(str(eve), str(fw))
    assert len(read_jsonl(str(alerts))) == 1
