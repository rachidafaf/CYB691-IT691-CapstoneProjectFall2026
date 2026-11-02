#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Module: Edge-to-analytics delivery service (sync_service.py)

ONE-WAY, WRITE-ONLY. The edge pushes; nothing on the analytics side ever
connects to the edge or to the OT network.

Docker deployment: the edge-sync container runs with `network_mode: none` (no
network interface except loopback) and delivers by writing into the `landing`
drop zone, a Docker volume it shares with the analytics `telemetry-sync`
container. It mounts nothing else from the analytics tier, and the analytics
tier has no route to the edge.

Delivery protocol per batch
  1. lease rows from SQLite (edge_database.dequeue_ready_batch)
  2. serialise to NDJSON, gzip deterministically, SHA-256 the bytes
  3. create  telemetry/edge=<id>/yyyy=../mm=../dd=../<batch_id>.ndjson.gz   (create-only, atomic)
  4. create  same name + ".manifest.json" (hashes of object and every event key)
  5. mark rows SYNCED. On any failure -> FAILED with exponential backoff.
The analytics side only processes batches whose manifest exists and whose hash
matches, so a half-written batch is never ingested. Events are de-duplicated
in PostgreSQL by idempotency key, so re-sending a batch is harmless.
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
from datetime import datetime
from typing import Dict, Optional, Protocol

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.atomic_file import create_only_write  # noqa: E402
from common.telemetry_schema import batch_manifest, sha256_bytes, sha256_file, utcnow  # noqa: E402
from edge import edge_database as db  # noqa: E402

logger = logging.getLogger("edge_sync")

EDGE_ID = os.environ.get("CYB691_EDGE_ID", "")                                   # REQUIRED_INPUT
LANDING_DIR = os.environ.get("CYB691_LANDING_DIR", "/landing")                  # shared drop-zone volume
BATCH_SIZE = int(os.environ.get("CYB691_SYNC_BATCH_SIZE", "500"))
IDLE_SECONDS = float(os.environ.get("CYB691_SYNC_IDLE_SECONDS", "10"))
MAX_BACKOFF_SECONDS = float(os.environ.get("CYB691_SYNC_MAX_BACKOFF", "900"))


class TransientError(Exception):
    """Drop zone missing, full or read-only: retry later, keep data queued."""


class ConflictError(Exception):
    """Object already exists with DIFFERENT content: never overwrite evidence."""


class Transport(Protocol):
    endpoint: str

    def put(self, name: str, data: bytes, sha256: str, content_type: str,
            metadata: Dict[str, str]) -> bool: ...

    def put_file(self, name: str, path: str, sha256: str, content_type: str,
                 metadata: Dict[str, str]) -> bool: ...


# ============================================================================
# Transport
# ============================================================================

class DropZoneTransport:
    """Writes objects into the shared `landing` volume. Create-only and atomic.

    `fail_next` makes the next N deliveries raise TransientError (outage simulation in tests).
    """

    def __init__(self, root: str, fail_next: int = 0):
        self.root = os.path.realpath(root)
        self.endpoint = f"dropzone:{self.root}"
        self.fail_next = fail_next

    def _path(self, name: str) -> str:
        p = os.path.realpath(os.path.join(self.root, name))
        if not p.startswith(self.root + os.sep):
            raise ConflictError(f"path traversal rejected: {name}")
        return p

    def put(self, name, data, sha256, content_type, metadata) -> bool:
        if self.fail_next > 0:
            self.fail_next -= 1
            raise TransientError("simulated drop-zone outage")
        if not os.path.isdir(self.root):
            raise TransientError(f"drop zone not mounted: {self.root}")
        path = self._path(name)
        try:
            if create_only_write(path, data):
                return True
            # Same name already delivered (lost ack / restart). Names embed batch UUIDs or
            # content hashes, so identical bytes mean an idempotent duplicate.
            if sha256_file(path)[0] == sha256:
                return False
        except FileNotFoundError:
            # telemetry-sync ingested and removed the object between our checks: it was delivered
            return False
        except OSError as exc:            # ENOSPC, EROFS, volume unmounted ...
            raise TransientError(f"drop zone write failed: {exc.__class__.__name__}: {exc.strerror}")
        raise ConflictError(name)         # different content under the same name: never overwrite evidence

    def put_file(self, name, path, sha256, content_type, metadata) -> bool:
        with open(path, "rb") as f:
            return self.put(name, f.read(), sha256, content_type, metadata)


# ============================================================================
# Sync logic
# ============================================================================

def _object_prefix(kind: str, edge_id: str, now: datetime) -> str:
    return f"{kind}/edge={edge_id}/yyyy={now:%Y}/mm={now:%m}/dd={now:%d}"


def serialise_batch(envelopes: list) -> bytes:
    raw = "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in envelopes).encode()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:   # deterministic bytes
        gz.write(raw)
    return buf.getvalue()


class SyncService:
    def __init__(self, transport: Transport, edge_id: str, db_path: Optional[str] = None,
                 batch_size: int = BATCH_SIZE):
        if not edge_id:
            raise SystemExit("CYB691_EDGE_ID is required (REQUIRED_INPUT)")
        self.t = transport
        self.edge_id = edge_id
        self.db_path = db_path
        self.batch_size = batch_size
        self.consecutive_failures = 0
        self._stop = False

    # -- telemetry batches ---------------------------------------------------
    def sync_telemetry_once(self) -> int:
        batch_id, envs = db.dequeue_ready_batch(self.batch_size, self.db_path)
        if not envs:
            return 0
        now = utcnow()
        data = serialise_batch(envs)
        digest = sha256_bytes(data)
        name = f"{_object_prefix('telemetry', self.edge_id, now)}/{batch_id}.ndjson.gz"
        manifest = batch_manifest(
            batch_id=batch_id, edge_id=self.edge_id, object_name=name, object_sha256=digest,
            object_size=len(data), event_count=len(envs), content_type="application/x-ndjson+gzip",
            event_keys=[e["idempotency_key"] for e in envs],
            first_ts=min(e["timestamp_utc"] for e in envs), last_ts=max(e["timestamp_utc"] for e in envs))
        mbytes = json.dumps(manifest, sort_keys=True).encode()
        meta = {"edge_id": self.edge_id, "batch_id": batch_id, "schema_version": envs[0]["schema_version"],
                "event_count": str(len(envs))}
        try:
            self.t.put(name, data, digest, "application/gzip", meta)
            self.t.put(name + ".manifest.json", mbytes, sha256_bytes(mbytes), "application/json", meta)
        except (TransientError, ConflictError, OSError) as exc:
            db.mark_batch_failed(batch_id, str(exc), self.db_path)
            db.log_sync_attempt(self.t.endpoint, "PUT_TELEMETRY_BATCH", False, batch_id=batch_id,
                                error=exc, retry_number=self.consecutive_failures, db_path=self.db_path)
            raise
        db.mark_batch_synced(batch_id, self.db_path)
        db.log_sync_attempt(self.t.endpoint, "PUT_TELEMETRY_BATCH", True, batch_id=batch_id,
                            db_path=self.db_path)
        return len(envs)

    # -- raw evidence files --------------------------------------------------
    def sync_uploads_once(self) -> int:
        done = 0
        for up in db.lease_ready_uploads(20, self.db_path):
            try:
                if not os.path.exists(up["local_file_path"]):
                    raise FileNotFoundError(up["local_file_path"])
                digest, size = sha256_file(up["local_file_path"])
                if digest != up["sha256_hash"] or size != up["file_size_bytes"]:
                    # local evidence changed after it was hashed: do not upload, alert locally
                    raise ConflictError(f"local hash mismatch for {up['local_file_path']}")
                meta = {"edge_id": self.edge_id, "kind": up["kind"], "upload_id": up["upload_id"]}
                self.t.put_file(up["blob_name"], up["local_file_path"], digest,
                                up["content_type"] or "application/octet-stream", meta)
                if up.get("manifest_json"):
                    mb = up["manifest_json"].encode()
                    self.t.put(up["blob_name"] + ".manifest.json", mb, sha256_bytes(mb), "application/json", meta)
            except (TransientError, ConflictError, OSError) as exc:
                db.mark_upload_failed(up["upload_id"], str(exc), self.db_path)
                db.log_sync_attempt(self.t.endpoint, f"PUT_{up['kind']}", False, upload_id=up["upload_id"],
                                    error=exc, db_path=self.db_path)
                if isinstance(exc, TransientError):
                    raise
                continue
            db.mark_upload_complete(up["upload_id"], self.db_path)
            db.log_sync_attempt(self.t.endpoint, f"PUT_{up['kind']}", True, upload_id=up["upload_id"],
                                db_path=self.db_path)
            done += 1
        return done

    def run_cycle(self) -> int:
        """One delivery cycle. Returns items delivered; raises TransientError on outage."""
        n = 0
        while True:
            k = self.sync_telemetry_once()
            n += k
            if k < self.batch_size:
                break
        n += self.sync_uploads_once()
        return n

    def run(self) -> None:
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "_stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "_stop", True))
        while not self._stop:
            try:
                n = self.run_cycle()
                self.consecutive_failures = 0
                time.sleep(IDLE_SECONDS if n == 0 else 0.1)
            except TransientError as exc:
                self.consecutive_failures += 1
                delay = db.calculate_backoff_seconds(self.consecutive_failures, max_seconds=MAX_BACKOFF_SECONDS)
                stats = db.get_queue_stats(self.db_path)
                logger.warning("analytics drop zone unavailable (%s); backlog=%s; retry in %.1fs",
                               exc, stats["telemetry"], delay)
                time.sleep(delay)
        db.safe_shutdown(self.db_path)


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    db.open_or_recover()
    transport = DropZoneTransport(LANDING_DIR)
    SyncService(transport, EDGE_ID).run()


if __name__ == "__main__":
    main()
