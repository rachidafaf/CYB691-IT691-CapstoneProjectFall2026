#!/usr/bin/env python3
"""
Unit and Negative-Control Test Suite for CYB691 Team 4 Pipeline.
Verifies all code fixes responding to Professor Feedback:
  - Telemetry normalization preserves read/write function codes from raw EVE JSON
  - Empty firewall log markers ('-- No entries --') are rejected
  - Tar-Slip path traversal protection
  - ML ground truth independence from predictor features
  - ML resampling applied strictly to training folds
  - ML latency separation (training vs prediction)
  - Negative-control checks in STRIDE validator (empty files/objects trigger FAIL)
"""

import os
import sys
import json
import pytest
import numpy as np

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from log_parser import (
    extract_function_code,
    normalize_iptables_drops,
    normalize_suricata_eve_json,
    is_within_directory,
    safe_extract_tarball
)
from ml_detector import (
    extract_features_and_ground_truth,
    resample_training_fold_only,
    evaluate_supervised_models,
    evaluate_unsupervised_isolation_forest
)
from validate_stride_threats import locate_artifact_file


def test_exact_duplicate_records_are_counted_once_but_distinct_ones_are_kept(tmp_path):
    """Only byte-identical records collapse; a record differing in any field (e.g. timestamp) is kept."""
    rec = {"timestamp": "2026-09-23T02:51:42.772834+0000", "flow_id": 1, "event_type": "modbus",
           "src_ip": "10.0.1.4", "dest_ip": "172.17.0.2", "dest_port": 5020,
           "modbus": {"request": {"transaction_id": 1, "unit_id": 1, "function_raw": 6,
                                  "function_code": "WrSingleReg", "write": {"address": 1, "data": 5}}}}
    later = json.loads(json.dumps(rec)); later["timestamp"] = "2026-09-23T02:51:43.000000+0000"
    p = tmp_path / "eve.json"
    p.write_text("\n".join(json.dumps(r) for r in (rec, rec, later)) + "\n")
    stats = {}
    events = normalize_suricata_eve_json(str(p), stats=stats)
    assert len(events) == 2 and stats["exact_duplicates_removed"] == 1


def test_extract_function_code_from_suricata_eve():
    """Verifies that extract_function_code correctly parses modbus.request.function_raw."""
    # EVE JSON structure from raw Suricata
    sample_eve_modbus = {
        "id": 1,
        "request": {
            "transaction_id": 1,
            "unit_id": 1,
            "function_raw": 6,
            "function_code": "WrSingleReg"
        }
    }
    assert extract_function_code(sample_eve_modbus) == 6

    # Read coil function
    sample_read = {
        "id": 2,
        "request": {
            "function_raw": 1,
            "function_code": "RdCoils"
        }
    }
    assert extract_function_code(sample_read) == 1

    # Multiple register write
    sample_multi = {
        "id": 3,
        "request": {
            "function_raw": 16,
            "function_code": "WrMultRegs"
        }
    }
    assert extract_function_code(sample_multi) == 16


def test_normalize_eve_json_counts_each_transaction_once(tmp_path):
    """The 2026-09-26 handoff logs each of its 10 Modbus transactions twice (byte-identical,
    consecutive lines). The parser must count 10 unique events (4 read, 6 write) and report
    the 10 duplicates it removed, without modifying the raw evidence."""
    raw_eve_path = "infrastructure/extracted_handoff/var/log/suricata/eve.json"
    if not os.path.exists(raw_eve_path):
        pytest.skip("Raw eve.json not found in test environment")

    stats = {}
    events = normalize_suricata_eve_json(raw_eve_path, stats=stats)
    assert len(events) == 10
    assert stats["modbus_records_seen"] == 20
    assert stats["exact_duplicates_removed"] == 10
    assert stats["unique_modbus_events"] == 10

    read_events = [e for e in events if e["f_info"]["category"] == "READ"]
    write_events = [e for e in events if e["f_info"]["category"] == "WRITE"]
    unknown_events = [e for e in events if e["f_info"]["category"] == "UNKNOWN"]

    assert len(read_events) == 4
    assert len(write_events) == 6
    assert len(unknown_events) == 0

    # Verify specific function codes
    fcodes = [e["fcode"] for e in events]
    assert 1 in fcodes  # RdCoils
    assert 3 in fcodes  # RdHoldRegs
    assert 5 in fcodes  # WrSingleCoil
    assert 6 in fcodes  # WrSingleReg
    assert 16 in fcodes # WrMultRegs


def test_reject_empty_firewall_log_marker(tmp_path):
    """Verifies that '-- No entries --' produces ZERO drop events."""
    empty_log = tmp_path / "iptables_drops.log"
    empty_log.write_text("-- No entries --\n", encoding="utf-8")

    drops = normalize_iptables_drops(str(empty_log))
    assert len(drops) == 0

    # Also test header comments
    comment_log = tmp_path / "comment_drops.log"
    comment_log.write_text("# Firewall drop log\n== End ==\n", encoding="utf-8")
    assert len(normalize_iptables_drops(str(comment_log))) == 0


def test_accept_valid_firewall_drop(tmp_path):
    """Verifies that genuine packet drops are properly parsed."""
    valid_log = tmp_path / "valid_drops.log"
    valid_log.write_text(
        "Sep 23 02:51:43 firewall kernel: [DROP] IN=eth0 OUT= SRC=10.0.1.4 DST=172.17.0.2 PROTO=TCP SPT=41238 DPT=502\n",
        encoding="utf-8"
    )
    drops = normalize_iptables_drops(str(valid_log))
    assert len(drops) == 1
    assert drops[0]["src_ip"] == "10.0.1.4"
    assert drops[0]["dest_ip"] == "172.17.0.2"
    assert drops[0]["dest_port"] == 502
    assert drops[0]["event_type"] == "FIREWALL_DROP"


def test_tar_slip_directory_traversal_guard(tmp_path):
    """Verifies that path traversal members in tar archives are detected and blocked."""
    extract_target = tmp_path / "safe_dir"
    extract_target.mkdir()

    # Safe path within directory
    safe_target = extract_target / "file.txt"
    assert is_within_directory(str(extract_target), str(safe_target)) is True

    # Traversal escaping directory
    malicious_target = tmp_path / "other_dir" / "secret.txt"
    assert is_within_directory(str(extract_target), str(malicious_target)) is False


def _scenario(*rows):
    return {"actions": [{"action_id": f"A{i}", "run": run, "timestamp_utc": ts, "label": lab}
                        for i, (ts, run, lab) in enumerate(rows, 1)]}


def _rec(eid, ts, fc, threat=0, altering=False, exc=False):
    return {"event_id": eid, "timestamp_iso": ts, "inter_arrival_ms": 100.0,
            "network": {"destination_port": 502},
            "modbus": {"function_code": fc, "unit_id": 1, "payload_raw": "x", "payload_parsed": {}},
            "security": {"has_protocol_exception": exc, "threat_score": threat, "is_state_altering": altering}}


def test_ml_ground_truth_comes_from_scenario_record_not_features():
    """Labels are joined from the scenario/action record by timestamp. Changing a feature
    (function code, threat score, is_state_altering) must not change any label."""
    sc = _scenario(("2026-09-23T02:51:42.772834+00:00", 1, 0), ("2026-09-23T02:51:43.175714+00:00", 1, 1))
    a = [_rec("E1", "2026-09-23T02:51:42.772834+00:00", 3), _rec("E2", "2026-09-23T02:51:43.175714+00:00", 6)]
    # same events with every feature/derived field flipped
    b = [_rec("E1", "2026-09-23T02:51:42.772834+00:00", 6, threat=99, altering=True),
         _rec("E2", "2026-09-23T02:51:43.175714+00:00", 3, threat=0, altering=False)]
    _, ya, names, _ = extract_features_and_ground_truth(a, sc)
    _, yb, _, _ = extract_features_and_ground_truth(b, sc)
    assert list(ya) == list(yb) == [0, 1]
    assert "threat_score" not in names and "is_state_altering" not in names


def test_events_without_a_scenario_action_are_excluded():
    sc = _scenario(("2026-09-23T02:51:42.772834+00:00", 1, 0))
    recs = [_rec("E1", "2026-09-23T02:51:42.772834+00:00", 3), _rec("E9", "2026-09-23T09:00:00+00:00", 6)]
    X, y, _, g = extract_features_and_ground_truth(recs, sc)
    assert len(y) == 1 and X.shape[0] == 1 and list(g) == [1]


def test_primary_features_are_request_time_only():
    from ml_detector import FEATURE_SETS, FEATURE_CATALOG, PRIMARY_FEATURE_SET
    assert all(FEATURE_CATALOG[n]["available"] == "request-time" for n in FEATURE_SETS[PRIMARY_FEATURE_SET])
    assert "has_protocol_exception" not in FEATURE_SETS[PRIMARY_FEATURE_SET]
    assert "payload_length" not in FEATURE_SETS[PRIMARY_FEATURE_SET]       # parser text, encodes the op name


def test_pdu_length_matches_modbus_spec():
    from ml_detector import request_pdu_length
    assert request_pdu_length({"function_code": 3, "payload_parsed": {"quantity": 2}}) == 5
    assert request_pdu_length({"function_code": 6, "payload_parsed": {"value": "1234"}}) == 5
    assert request_pdu_length({"function_code": 16, "payload_parsed": {"value": "\x00\x01\x00\x02"}}) == 10


def test_handoff_scenario_record_covers_every_normalized_event():
    from scenario import load_scenario, join_labels
    norm = os.path.join(os.path.dirname(__file__), "..", "data", "normalized_telemetry.json")
    sc = load_scenario()
    if sc is None or not os.path.exists(norm):
        pytest.skip("scenario record or normalized telemetry not present")
    labels, groups, matched, unmatched = join_labels(json.load(open(norm, encoding="utf-8")), sc)
    assert unmatched == [] and len(matched) == len(sc["actions"]) == 10
    assert sum(labels) == 6 and sorted(set(groups)) == [1, 2, 3]


def test_isolation_forest_does_not_use_labels():
    """Same features, different labels -> identical screening output (labels only score it)."""
    X = np.array([[0, 1], [1, 1], [0, 2], [50, 9], [1, 1], [0, 1]], dtype=float)
    r1 = evaluate_unsupervised_isolation_forest(X, np.array([0, 0, 0, 1, 0, 0]))
    r2 = evaluate_unsupervised_isolation_forest(X, np.array([1, 1, 1, 0, 1, 1]))
    assert r1["outliers_flagged"] == r2["outliers_flagged"] and r1["labels_used_for_fitting"] is False


def test_test_fold_rows_are_never_resampled_into_training():
    """Every transaction is tested exactly once and never appears in its own training fold."""
    from ml_detector import _splits
    X = np.arange(20, dtype=float).reshape(10, 2)
    y = np.array([0, 0, 1, 1, 0, 0, 1, 1, 1, 1])
    g = np.array([1, 1, 1, 1, 2, 2, 2, 2, 3, 3])
    for scheme in ("stratified_kfold", "leave_one_run_out"):
        splits, _ = _splits(X, y, g, scheme)
        tested = sorted(i for _, te in splits for i in te)
        assert tested == list(range(10))
        for tr, te in splits:
            assert not set(tr) & set(te)
            Xr, _ = resample_training_fold_only(X[tr], y[tr])
            assert not {tuple(r) for r in Xr} & {tuple(r) for r in X[te]}
        if scheme == "leave_one_run_out":
            assert all(len(set(g[te])) == 1 and not set(g[tr]) & set(g[te]) for tr, te in splits)


def test_timing_fields_are_separate():
    X = np.array([[i, i % 2] for i in range(12)], dtype=float)
    y = np.array([i % 2 for i in range(12)])
    res = evaluate_supervised_models(X, y, ["a", "b"])
    for m in res.values():
        assert "training_time_avg_ms" in m and "prediction_latency_per_sample_ms" in m


def test_ml_resampling_affects_only_training_data():
    """Verifies that resampling is applied strictly to training sets, leaving test sets intact."""
    X_train = np.array([[10.0, 1], [15.0, 1], [20.0, 3], [25.0, 3], [30.0, 6]])
    y_train = np.array([0, 0, 0, 0, 1])  # 4 benign, 1 attack

    X_resampled, y_resampled = resample_training_fold_only(X_train, y_train, target_samples_per_class=5)

    # Class 1 should now have at least 5 samples in training
    assert np.sum(y_resampled == 1) >= 5
    # The original test fold is never passed to resample_training_fold_only


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _stub_repo(tmp_path, parser_src, normalized, ml_results):
    import shutil
    (tmp_path / "src").mkdir()
    (tmp_path / "data").mkdir()
    shutil.copy(os.path.join(REPO, "Team 4 Threat Model.json"), tmp_path / "Team 4 Threat Model.json")
    (tmp_path / "src" / "log_parser.py").write_text(parser_src, encoding="utf-8")
    (tmp_path / "data" / "normalized_telemetry.json").write_text(json.dumps(normalized), encoding="utf-8")
    (tmp_path / "data" / "ml_evaluation_results.json").write_text(json.dumps(ml_results), encoding="utf-8")
    return str(tmp_path)


def test_validator_negative_control_reproduces_professor_probe(tmp_path):
    """Professor's probe: an empty parser, normalized data holding an empty object and an empty
    model-results object previously all received PASS. Each must now FAIL. The stub parser even
    names the controls in a comment, which the old text-grep check accepted."""
    from validate_stride_threats import run_audit
    stub = "# is_within_directory commonpath '-- No entries --' function_raw extract_function_code\n" * 3
    root = _stub_repo(tmp_path, stub, [{}], {"supervised_models": {}})
    result = run_audit(root=root, write_reports=False)
    by_check = {c["check"]: c["status"] for c in result["checks"]}
    assert by_check["P1 Parser controls"] == "FAIL"
    assert by_check["P2 Normalized vs raw"] == "FAIL"
    assert by_check["P3 ML evaluation"] == "FAIL"
    assert result["status"] == "FAILED"


def test_validator_rejects_feature_derived_labels(tmp_path):
    """ML results whose ground truth is not the scenario record must FAIL, even with perfect metrics."""
    from validate_stride_threats import run_audit
    ml = {"supervised_models": {"Random Forest Classifier": {
              "recall": 100.0, "false_positive_rate": 0.0, "training_time_avg_ms": 1.0,
              "prediction_latency_per_sample_ms": 0.1}},
          "ground_truth": {"source": "function_code rule"}, "dataset_summary": {"total_records": 100}}
    root = _stub_repo(tmp_path, "x = 1\n", [], ml)
    checks = {c["check"]: c for c in run_audit(root=root, write_reports=False)["checks"]}
    assert checks["P3 ML evaluation"]["status"] == "FAIL"
    assert "scenario" in checks["P3 ML evaluation"]["details"]


def test_validator_never_reports_success_with_warnings():
    from validate_stride_threats import run_audit
    if not os.path.exists(os.path.join(REPO, "data", "ml_evaluation_results.json")):
        pytest.skip("pipeline outputs not present")
    result = run_audit(root=REPO, write_reports=False)
    statuses = [c["status"] for c in result["checks"]]
    if "WARN" in statuses:
        assert result["status"] == "PARTIAL"
    assert "FAIL" not in statuses


def test_database_backend_selection_and_safety():
    """SQLite stays the default; a postgresql:// URL selects PostgreSQL. Log lines never show a
    password, placeholders are converted, and NUL characters survive the PostgreSQL text escape."""
    import database as d
    assert not d.is_postgres("data/telemetry.db")
    assert d.is_postgres("postgresql://postgres@localhost:5432/postgres")
    shown = d.describe_target("postgresql://postgres:s3cret@localhost:5432/postgres")
    assert "s3cret" not in shown and "localhost:5432/postgres" in shown
    assert d._sql("INSERT INTO t VALUES (?, ?)", "postgresql://x@h/db") == "INSERT INTO t VALUES (%s, %s)"
    assert d._sql("INSERT INTO t VALUES (?, ?)", "data/x.db") == "INSERT INTO t VALUES (?, ?)"
    raw = "write:addr=0 val=\x00\x01\x00\x02"
    stored = d._pg_text(raw)
    assert "\x00" not in stored and stored.replace(d.NUL_TEXT, "\x00") == raw


def test_sqlite_round_trip_keeps_scenario_labels(tmp_path):
    import database as d
    norm = os.path.join(REPO, "data", "normalized_telemetry.json")
    if not os.path.exists(norm):
        pytest.skip("normalized telemetry not present")
    recs = json.load(open(norm, encoding="utf-8"))
    db = str(tmp_path / "t.db")
    assert d.insert_telemetry_records(recs, db_path=db) == len(recs)
    back = d.load_telemetry_records(db)
    assert [r["modbus"]["payload_parsed"] for r in back] == [r["modbus"]["payload_parsed"] for r in recs]
    X, y, names = d.extract_features_from_db(db)
    assert int(y.sum()) == 6 and len(y) == 10
