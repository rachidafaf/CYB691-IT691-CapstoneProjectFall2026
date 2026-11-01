#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Batch jobs (run as Docker Compose services; long-running ones loop with --every):

  python -m analytics.jobs log-parser        reconcile raw evidence chunks vs. normalised events
  python -m analytics.jobs timeline          group alerts into incidents + forensic timeline report
  python -m analytics.jobs ml-score          score new Modbus events with an approved model
  python -m analytics.jobs ml-train          train a model from a hash-pinned labelled dataset
  python -m analytics.jobs partitions        create upcoming telemetry partitions

All jobs: read-only towards the edge/OT (no network path exists), idempotent,
and every run is recorded in processing_runs with its image reference.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import logging
import os
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.normalizers import (  # noqa: E402
    has_stable_timestamp, legacy_record, normalise_eve, normalise_firewall_line)
from common.telemetry_schema import ValidationError, sha256_bytes, validate_envelope  # noqa: E402
from analytics.object_store import FileObjectStore  # noqa: E402
from analytics.pg_writer import SEV_ORDER, Store, deterministic_id, new_run_id  # noqa: E402
from analytics.telemetry_sync import AUDIT_CONTAINER, alert_log, bounded_gunzip  # noqa: E402

logger = logging.getLogger("cyb691.jobs")
EXPORTS = os.environ.get("CYB691_EXPORTS_CONTAINER", "normalized-exports")
MODELS = os.environ.get("CYB691_MODELS_CONTAINER", "model-artifacts")


def _meta() -> Dict[str, Any]:
    return {"image_ref": os.environ.get("CYB691_IMAGE_REF"), "git_sha": os.environ.get("CYB691_GIT_SHA")}


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================================
# log-parser: raw evidence reconciliation
# ============================================================================

def log_parser(objects: FileObjectStore, store: Store, workload: str = "log-parser") -> Dict[str, int]:
    run_id = new_run_id()
    store.start_run(run_id, workload, "RECONCILE", _meta())
    stats = {"input": 0, "output": 0, "failed": 0, "duplicate": 0, "unverifiable": 0, "objects": 0}
    for container, kind in (("suricata-eve", "EVE_JSON"), ("firewall-logs", "FIREWALL_LOG")):
        for name in list(objects.list(container)):
            marker = f"reconciled/{container}/{name}.json"
            if objects.exists(AUDIT_CONTAINER, marker):
                continue
            manifest = json.loads(objects.read(AUDIT_CONTAINER, f"{container}/{name}.manifest.json"))
            data = objects.read(container, name)
            if sha256_bytes(data) != (manifest.get("sha256") or manifest.get("object_sha256")):
                alert_log("EVIDENCE_TAMPER_SUSPECTED", "CRITICAL", object=f"{container}/{name}")
                store.audit(workload, "EVIDENCE_HASH_MISMATCH", "object", f"{container}/{name}", "FAILURE", run_id)
                stats["failed"] += 1
                continue
            edge_id = manifest["edge_id"]
            envs: List[Dict[str, Any]] = []
            for i, line in enumerate(bounded_gunzip(data).decode("utf-8", "replace").splitlines()):
                ref = {"object": f"{container}/{name}", "line": i}
                try:
                    if kind == "EVE_JSON":
                        env = normalise_eve(json.loads(line), edge_id, ref)
                    elif has_stable_timestamp(line):
                        env = normalise_firewall_line(line, edge_id, ref)
                    else:
                        stats["unverifiable"] += 1
                        continue
                    if env is None:
                        continue
                    validate_envelope(env, now=_now())
                    envs.append(env)
                except (ValueError, ValidationError, TypeError):
                    stats["failed"] += 1
            stats["input"] += len(envs)
            have = store.existing_keys([e["idempotency_key"] for e in envs])
            missing = [e for e in envs if e["idempotency_key"] not in have]
            if missing:
                alert_log("RECONCILIATION_GAP", "HIGH", object=f"{container}/{name}", missing=len(missing))
                ins, dup = store.write_events(missing, batch_id=None,
                                              manifest_id=f"{kind}:{manifest.get('sha256')}", run_id=run_id)
                stats["output"] += ins
            stats["duplicate"] += len(envs) - len(missing)
            objects.write(AUDIT_CONTAINER, marker, json.dumps(
                {"run_id": run_id, "events": len(envs), "backfilled": len(missing)}).encode(),
                content_type="application/json")
            stats["objects"] += 1
    store.finish_run(run_id, "COMPLETED", stats)
    return stats


# ============================================================================
# timeline-generator: incidents + forensic timeline
# ============================================================================

def _rule_of(e: Dict[str, Any]) -> str:
    raw = e.get("raw") if isinstance(e.get("raw"), dict) else {}
    if e["event_type"] == "LOCAL_ALERT":
        return str(raw.get("rule", "LOCAL_ALERT"))
    if e["event_type"] == "SURICATA_ALERT":
        return f"SURICATA_{(raw.get('alert') or {}).get('signature_id', 'UNKNOWN')}"
    return "FIREWALL_BLOCK"


def timeline(objects: FileObjectStore, store: Store, hours: int = 24, workload: str = "timeline-generator") -> Dict[str, int]:
    run_id = new_run_id()
    store.start_run(run_id, workload, "TRIAGE", _meta())
    until = _now()
    events = store.fetch_events(until - timedelta(hours=hours), until,
                                ["LOCAL_ALERT", "SURICATA_ALERT", "FIREWALL_DROP"])
    groups: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        ts = datetime.fromisoformat(e["timestamp_utc"])
        bucket = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        groups[(_rule_of(e), e.get("src_ip"), e.get("dest_ip"), e["edge_id"], bucket)].append(e)
    lines = [f"# Forensic timeline (run {run_id})", "",
             f"Window: {(until - timedelta(hours=hours)).isoformat()} to {until.isoformat()} UTC", "",
             "| First seen (UTC) | Last seen | Rule | Severity | Source | Destination | Events | Incident |",
             "|---|---|---|---|---|---|---|---|"]
    for (rule, src, dst, edge, bucket), evs in sorted(groups.items(), key=lambda kv: kv[0][4]):
        sev = max((e["severity"] for e in evs), key=lambda s: SEV_ORDER[s])
        inc_id = deterministic_id(rule, src, dst, edge, bucket)
        first, last = evs[0]["timestamp_utc"], evs[-1]["timestamp_utc"]
        store.upsert_incident({
            "incident_id": inc_id, "severity": sev, "rule": rule,
            "title": f"{rule} {src or '-'} -> {dst or '-'}", "description": f"{len(evs)} events in hour {bucket}",
            "first_seen_utc": first, "last_seen_utc": last, "event_count": len(evs),
            "event_keys": sorted(e["idempotency_key"] for e in evs), "src_ip": src, "dest_ip": dst,
            "edge_id": edge, "run_id": run_id})
        lines.append(f"| {first} | {last} | {rule} | {sev} | {src} | {dst} | {len(evs)} | {inc_id} |")
    report = ("\n".join(lines) + "\n").encode()
    name = f"reports/{until:%Y/%m/%d}/timeline-{run_id}.md"
    objects.write(EXPORTS, name, report, {"sha256": sha256_bytes(report), "run_id": run_id}, "text/markdown")
    store.save_evidence_manifest({
        "manifest_id": f"REPORT:{sha256_bytes(report)}", "kind": "REPORT", "edge_id": None, "batch_id": None,
        "container": EXPORTS, "blob_name": name, "sha256_hash": sha256_bytes(report),
        "file_size_bytes": len(report), "content_type": "text/markdown", "event_count": len(events),
        "verification_status": "VERIFIED", "is_immutable": False, "retention_until": None, "run_id": run_id,
        "manifest": {"incidents": len(groups), "window_hours": hours}})
    stats = {"input": len(events), "output": len(groups), "failed": 0, "duplicate": 0}
    store.finish_run(run_id, "COMPLETED", stats)
    return stats


# ============================================================================
# ml-detector
# ============================================================================

def _load_model(objects: FileObjectStore, name: str, version: str):
    import joblib
    base = f"models/{name}/{version}"
    manifest = json.loads(objects.read(MODELS, f"{base}/model.manifest.json"))
    data = objects.read(MODELS, f"{base}/model.joblib")
    digest = sha256_bytes(data)
    if digest != manifest["sha256"]:
        # Deserialising an unverified pickle is code execution: refuse.
        raise RuntimeError("model artifact hash mismatch – refusing to load")
    return joblib.load(io.BytesIO(data)), manifest, digest


def _src_ml():
    root = os.environ.get("CYB691_SRC_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))
    if root not in sys.path:
        sys.path.insert(0, root)
    import ml_detector  # the team's existing module (feature definitions reused unchanged)
    return ml_detector


def ml_score(objects: FileObjectStore, store: Store, minutes: int = 60, workload: str = "ml-detector") -> Dict[str, int]:
    name = os.environ.get("CYB691_MODEL_NAME", "random_forest")
    version = os.environ["CYB691_MODEL_VERSION"]          # REQUIRED_INPUT: approved model version
    threshold = float(os.environ.get("CYB691_ALERT_THRESHOLD", "0.9"))
    run_id = new_run_id()
    store.start_run(run_id, workload, "SCORE", {**_meta(), "model": f"{name}:{version}"})
    model, manifest, digest = _load_model(objects, name, version)
    until = _now()
    events = store.fetch_events(until - timedelta(minutes=minutes), until, ["MODBUS_DPI"])
    records, prev = [], {}
    for e in events:                                   # inter-arrival per edge, ordered by time
        ts = datetime.fromisoformat(e["timestamp_utc"])
        delta = 0.0 if e["edge_id"] not in prev else (ts - prev[e["edge_id"]]).total_seconds() * 1000
        prev[e["edge_id"]] = ts
        records.append(legacy_record(e, delta))
    preds = []
    if records:
        X, _, feature_names = _src_ml().extract_features_and_ground_truth(records)
        if feature_names != manifest.get("feature_names"):
            raise RuntimeError("feature schema differs from model manifest")
        t0 = time.perf_counter()
        labels = model.predict(X)
        probs = model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else [None] * len(labels)
        per = (time.perf_counter() - t0) * 1000 / len(records)
        for e, x, lab, p in zip(events, X.tolist(), labels, probs):
            preds.append({"event_idempotency_key": e["idempotency_key"], "event_timestamp_utc": e["timestamp_utc"],
                          "model_name": name, "model_version": version, "model_sha256": digest,
                          "prediction_label": int(lab), "prediction_probability": None if p is None else float(p),
                          "feature_vector": dict(zip(feature_names, x)), "inference_latency_ms": per,
                          "run_id": run_id})
    new = store.save_predictions(preds)
    positives = sum(1 for p in preds if (p["prediction_probability"] or p["prediction_label"]) >= threshold)
    if positives:
        alert_log("ML_ANOMALY", "HIGH", positives=positives, model=f"{name}:{version}", run_id=run_id)
    stats = {"input": len(events), "output": new, "failed": 0, "duplicate": len(preds) - new}
    store.finish_run(run_id, "COMPLETED", stats)
    return stats


def ml_train(objects: FileObjectStore, store: Store, workload: str = "ml-train") -> Dict[str, int]:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    dataset = os.environ["CYB691_TRAINING_OBJECT"]              # REQUIRED_INPUT e.g. training/normalized_telemetry.json
    expected = os.environ["CYB691_TRAINING_SHA256"]           # REQUIRED_INPUT – pins the exact dataset
    version = os.environ["CYB691_MODEL_VERSION"]
    name = os.environ.get("CYB691_MODEL_NAME", "random_forest")
    run_id = new_run_id()
    store.start_run(run_id, workload, "TRAIN", {**_meta(), "dataset": dataset})
    data = objects.read(EXPORTS, dataset)
    if sha256_bytes(data) != expected:
        store.finish_run(run_id, "FAILED", {}, "training dataset hash mismatch")
        raise RuntimeError("training dataset hash mismatch")
    records = json.loads(data)
    X, y, feature_names = _src_ml().extract_features_and_ground_truth(records)
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced").fit(X, y)
    buf = io.BytesIO()
    joblib.dump(model, buf)
    art = buf.getvalue()
    digest = sha256_bytes(art)
    base = f"models/{name}/{version}"
    manifest = {"model_name": name, "model_version": version, "sha256": digest, "feature_names": feature_names,
                "training_object": dataset, "training_sha256": expected, "n_samples": int(len(y)),
                "run_id": run_id, "created_at_utc": _now().isoformat(), **_meta()}
    if not objects.write(MODELS, f"{base}/model.joblib", art, {"sha256": digest}):
        raise RuntimeError(f"model version {version} already exists – versions are immutable")
    mb = json.dumps(manifest, sort_keys=True).encode()
    objects.write(MODELS, f"{base}/model.manifest.json", mb, {"sha256": sha256_bytes(mb)}, "application/json")
    store.save_evidence_manifest({
        "manifest_id": f"MODEL:{digest}", "kind": "MODEL", "edge_id": None, "batch_id": None, "container": MODELS,
        "blob_name": f"{base}/model.joblib", "sha256_hash": digest, "file_size_bytes": len(art),
        "content_type": "application/octet-stream", "event_count": int(len(y)), "verification_status": "VERIFIED",
        "is_immutable": False, "retention_until": None, "run_id": run_id, "manifest": manifest})
    stats = {"input": int(len(y)), "output": 1, "failed": 0, "duplicate": 0}
    store.finish_run(run_id, "COMPLETED", stats)
    return stats


# ============================================================================
# partitions
# ============================================================================

def partitions(months_ahead: int = 3) -> int:
    from analytics.pg_connection import connect
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT ensure_telemetry_partitions(%s)", (months_ahead,))
            n = cur.fetchone()[0]
        conn.commit()
        return n
    finally:
        conn.close()


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)r}')
    ap = argparse.ArgumentParser()
    ap.add_argument("job", choices=["log-parser", "timeline", "ml-score", "ml-train", "partitions"])
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--minutes", type=int, default=60)
    ap.add_argument("--every", type=float, default=0,
                    help="repeat the job every N seconds (0 = run once and exit)")
    a = ap.parse_args()
    if a.job == "partitions":
        fn = lambda: {"created": partitions()}  # noqa: E731
    else:
        from analytics.pg_writer import PgStore
        objects, store = FileObjectStore(), PgStore()
        fn = {"log-parser": lambda: log_parser(objects, store),
              "timeline": lambda: timeline(objects, store, a.hours),
              "ml-score": lambda: ml_score(objects, store, a.minutes),
              "ml-train": lambda: ml_train(objects, store)}[a.job]
    if a.every <= 0:
        print(json.dumps(fn()))
        return
    from common.health import touch
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    while not stop["flag"]:
        try:
            print(json.dumps(fn()), flush=True)
            touch()
        except Exception:
            logger.exception("%s run failed; retrying in %.0fs", a.job, a.every)
        for _ in range(int(a.every)):
            if stop["flag"]:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
