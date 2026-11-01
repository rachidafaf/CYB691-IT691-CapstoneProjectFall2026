#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Service: telemetry-sync (telemetry_sync.py)

Consumes what the edge dropped into the `landing` volume. It never connects to
the edge or the OT network; it only reads the landing volume and writes the
object store + PostgreSQL on the internal Docker network.

For each `*.manifest.json` in landing:
  1. Parse & bound-check the manifest; load the object it describes.
  2. Verify SHA-256 (and size) against the manifest.
       mismatch -> copy to `quarantine`, record HASH_MISMATCH, audit, alert log.
  3. TELEMETRY_BATCH: gunzip (bounded), parse NDJSON, validate every envelope
     (schema, Modbus ranges, timestamps, per-event hash). Invalid events go to
     `quarantine` with the reason; valid ones are written idempotently.
  4. Copy the verified raw object + manifest into its evidence area
     (create-only: evidence is never overwritten) and record evidence_manifests.
  5. Delete the landing objects.
Re-processing the same manifest is a no-op (manifest_id = kind:sha256).
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.telemetry_schema import ValidationError, sha256_bytes, validate_envelope  # noqa: E402
from analytics.object_store import FileObjectStore, ObjectTooLarge  # noqa: E402
from analytics.pg_writer import Store, new_run_id  # noqa: E402

logger = logging.getLogger("telemetry_sync")

LANDING = os.environ.get("CYB691_LANDING_CONTAINER", "landing")
QUARANTINE = os.environ.get("CYB691_QUARANTINE_CONTAINER", "quarantine")
AUDIT_CONTAINER = os.environ.get("CYB691_AUDIT_CONTAINER", "audit-manifests")
EVIDENCE_CONTAINERS = {
    "TELEMETRY_BATCH": os.environ.get("CYB691_EDGE_BATCH_CONTAINER", "normalized-exports"),
    "EVE_JSON": "suricata-eve",
    "FIREWALL_LOG": "firewall-logs",
    "PCAP": "raw-pcap",
    "CSV": "csv-telemetry",
}
PREFIX_KIND = {"telemetry": "TELEMETRY_BATCH", "eve_json": "EVE_JSON", "firewall_log": "FIREWALL_LOG",
               "pcap": "PCAP", "csv": "CSV"}
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = int(os.environ.get("CYB691_MAX_DECOMPRESSED_BYTES", str(1024 * 1024 * 1024)))
RETENTION_DAYS = int(os.environ.get("CYB691_EVIDENCE_RETENTION_DAYS", "365"))
IMMUTABLE = os.environ.get("CYB691_EVIDENCE_IMMUTABLE", "false").lower() == "true"
WORKLOAD = os.environ.get("CYB691_WORKLOAD", "telemetry-sync")
POLL_SECONDS = float(os.environ.get("CYB691_POLL_SECONDS", "15"))


def alert_log(rule: str, severity: str, **detail: Any) -> None:
    """Structured JSON log line (`docker compose logs` / any log shipper can alert on it)."""
    logger.warning(json.dumps({"alert": True, "rule": rule, "severity": severity, **detail}, sort_keys=True))


def bounded_gunzip(data: bytes, limit: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        while True:
            chunk = gz.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
            if out.tell() > limit:
                raise ObjectTooLarge("decompressed size exceeds limit (possible gzip bomb)")
    return out.getvalue()


class TelemetrySync:
    def __init__(self, objects: FileObjectStore, store: Store, now=None):
        self.objects = objects
        self.store = store
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._stop = False

    # ------------------------------------------------------------------
    def pending_manifests(self) -> List[str]:
        return [n for n in self.objects.list(LANDING) if n.endswith(".manifest.json")]

    def _kind_for(self, name: str, manifest: Dict[str, Any]) -> str:
        kind = manifest.get("kind") or PREFIX_KIND.get(name.split("/", 1)[0])
        if kind not in EVIDENCE_CONTAINERS:
            raise ValidationError(f"unknown object kind for {name}")
        return kind

    def _quarantine(self, run_id: str, name: str, data: Optional[bytes], reason: str, extra: Dict[str, Any]) -> None:
        stamp = self._now().strftime("%Y%m%dT%H%M%SZ")
        if data is not None:
            self.objects.write(QUARANTINE, f"{stamp}/{name}", data, {"reason": reason[:200]})
        self.objects.write(QUARANTINE, f"{stamp}/{name}.reason.json",
                         json.dumps({"reason": reason, "run_id": run_id, **extra}, sort_keys=True).encode(),
                         content_type="application/json")

    # ------------------------------------------------------------------
    def process_manifest(self, manifest_name: str, run_id: str) -> Dict[str, int]:
        counts = {"input": 0, "output": 0, "failed": 0, "duplicate": 0}
        object_name = manifest_name[: -len(".manifest.json")]
        mbytes = self.objects.read(LANDING, manifest_name, max_bytes=MAX_MANIFEST_BYTES)
        try:
            manifest = json.loads(mbytes)
            kind = self._kind_for(object_name, manifest)
            expected_sha = manifest.get("object_sha256") or manifest.get("sha256")
            expected_size = manifest.get("object_size_bytes", manifest.get("size_bytes"))
            edge_id = manifest["edge_id"]
            if not isinstance(expected_sha, str) or len(expected_sha) != 64:
                raise ValidationError("manifest lacks a SHA-256")
        except (ValueError, KeyError, ValidationError) as exc:
            self._quarantine(run_id, manifest_name, mbytes, f"invalid manifest: {exc}", {})
            self.objects.delete(LANDING, manifest_name)
            alert_log("INVALID_MANIFEST", "HIGH", object=manifest_name)
            counts["failed"] += 1
            return counts

        manifest_id = f"{kind}:{expected_sha}"
        if self.store.manifest_status(manifest_id) == "VERIFIED":
            # already ingested (e.g. crash after DB commit, before landing delete)
            self.objects.delete(LANDING, object_name)
            self.objects.delete(LANDING, manifest_name)
            counts["duplicate"] += 1
            return counts

        if not self.objects.exists(LANDING, object_name):
            return counts                     # object not uploaded yet (edge retries); try later

        data = self.objects.read(LANDING, object_name)
        actual_sha = sha256_bytes(data)
        if actual_sha != expected_sha or (expected_size is not None and expected_size != len(data)):
            self._quarantine(run_id, object_name, data, "hash mismatch",
                             {"expected": expected_sha, "actual": actual_sha, "manifest": manifest})
            self.store.save_evidence_manifest({
                "manifest_id": f"{kind}:{expected_sha}:mismatch:{actual_sha}", "kind": kind, "edge_id": edge_id,
                "batch_id": manifest.get("batch_id"), "container": QUARANTINE, "blob_name": object_name,
                "sha256_hash": actual_sha, "file_size_bytes": len(data), "content_type": manifest.get("content_type"),
                "event_count": None, "verification_status": "HASH_MISMATCH", "is_immutable": False,
                "retention_until": None, "run_id": run_id, "manifest": manifest})
            self.store.audit(WORKLOAD, "EVIDENCE_HASH_MISMATCH", "object", object_name, "FAILURE", run_id,
                             {"expected": expected_sha, "actual": actual_sha})
            alert_log("EVIDENCE_HASH_MISMATCH", "CRITICAL", object=object_name, edge_id=edge_id)
            self.objects.delete(LANDING, object_name)
            self.objects.delete(LANDING, manifest_name)
            counts["failed"] += 1
            return counts

        event_count = None
        if kind == "TELEMETRY_BATCH":
            valid, invalid = self._parse_batch(data, manifest)
            event_count = len(valid)
            counts["input"] = len(valid) + len(invalid)
            if invalid:
                self._quarantine(run_id, object_name + ".invalid.ndjson",
                                 "".join(json.dumps(i, sort_keys=True) + "\n" for i in invalid).encode(),
                                 f"{len(invalid)} invalid events", {"batch_id": manifest.get("batch_id")})
                alert_log("INVALID_TELEMETRY", "MEDIUM", count=len(invalid), object=object_name)
                counts["failed"] = len(invalid)
            ins, dup = self.store.write_events(valid, batch_id=manifest.get("batch_id"),
                                               manifest_id=manifest_id, run_id=run_id)
            counts["output"], counts["duplicate"] = ins, dup

        container = EVIDENCE_CONTAINERS[kind]
        self.objects.write(container, object_name, data, {"sha256": actual_sha, "run_id": run_id})
        self.objects.write(AUDIT_CONTAINER, f"{container}/{object_name}.manifest.json", mbytes,
                         {"sha256": sha256_bytes(mbytes)}, "application/json")
        self.store.save_evidence_manifest({
            "manifest_id": manifest_id, "kind": kind, "edge_id": edge_id, "batch_id": manifest.get("batch_id"),
            "container": container, "blob_name": object_name, "sha256_hash": actual_sha,
            "file_size_bytes": len(data), "content_type": manifest.get("content_type"),
            "event_count": event_count, "verification_status": "VERIFIED", "is_immutable": IMMUTABLE,
            "retention_until": (self._now() + timedelta(days=RETENTION_DAYS)).isoformat(),
            "run_id": run_id, "manifest": manifest})
        self.store.audit(WORKLOAD, "EVIDENCE_INGESTED", "object", f"{container}/{object_name}", "SUCCESS", run_id,
                         {"sha256": actual_sha, "kind": kind, **counts})
        self.objects.delete(LANDING, object_name)
        self.objects.delete(LANDING, manifest_name)
        return counts

    def _parse_batch(self, data: bytes, manifest: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        valid: List[Dict[str, Any]] = []
        invalid: List[Dict[str, Any]] = []
        now = self._now()
        listed = set(manifest.get("event_idempotency_keys") or [])
        for i, line in enumerate(bounded_gunzip(data).decode("utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                env = json.loads(line)
                validate_envelope(env, now=now)
                if env.get("edge_id") != manifest.get("edge_id"):
                    raise ValidationError("edge_id differs from manifest")
                if listed and env["idempotency_key"] not in listed:
                    raise ValidationError("event not listed in manifest")
                valid.append(env)
            except (ValueError, ValidationError, KeyError, TypeError) as exc:
                invalid.append({"line_no": i, "error": str(exc), "line": line[:8000]})
        return valid, invalid

    # ------------------------------------------------------------------
    def run_once(self) -> Dict[str, int]:
        run_id = new_run_id()
        names = self.pending_manifests()
        total = {"input": 0, "output": 0, "failed": 0, "duplicate": 0, "manifests": len(names)}
        if not names:
            return total
        self.store.start_run(run_id, WORKLOAD, "INGEST", {"image_ref": os.environ.get("CYB691_IMAGE_REF"),
                                                         "git_sha": os.environ.get("CYB691_GIT_SHA")})
        status, err = "COMPLETED", None
        for n in names:
            try:
                c = self.process_manifest(n, run_id)
                for k in ("input", "output", "failed", "duplicate"):
                    total[k] += c[k]
            except ObjectTooLarge as exc:
                alert_log("OBJECT_TOO_LARGE", "HIGH", object=n, error=str(exc))
                status, err = "PARTIAL", str(exc)
            except Exception as exc:   # transient DB/storage problem: leave in landing, retry next run
                logger.exception("processing %s failed; will retry", n)
                status, err = "PARTIAL", f"{exc.__class__.__name__}: {exc}"
        try:
            self.store.finish_run(run_id, status, total, err)
        except Exception:
            logger.exception("could not record run status")
        return total

    def run(self) -> None:
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "_stop", True))
        from common.health import touch
        while not self._stop:
            try:
                r = self.run_once()
                touch()                      # liveness: loop is alive and storage/DB reachable
                if r["manifests"]:
                    logger.info(json.dumps({"run": r}))
            except Exception:
                logger.exception("cycle failed")
            time.sleep(POLL_SECONDS)


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)r}')
    from analytics.pg_writer import PgStore
    TelemetrySync(FileObjectStore(), PgStore()).run()


if __name__ == "__main__":
    main()
