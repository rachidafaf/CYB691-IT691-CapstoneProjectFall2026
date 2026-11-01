#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Module: Edge telemetry collector + local fallback detection (edge_collector.py)

Runs on the edge gateway in the IDMZ segment. It is READ-ONLY with respect to
the OT network: it tails log files written by Suricata (eve.json) and pfSense /
iptables (firewall log) and never opens a socket to a PLC, HMI or TCP/502.

Responsibilities
  1. Tail EVE JSON and firewall logs (offsets persisted -> restart-safe).
  2. Normalise each record into a hashed envelope (deploy/common/telemetry_schema.py).
  3. Validate; invalid records go to a local quarantine file (evidence kept).
  4. Buffer valid envelopes in SQLite (edge_database.py).
  5. Local fallback detection & alerting that works with NO analytics tier connectivity.
  6. Periodically snapshot raw log ranges into hashed evidence chunks and queue
     them for delivery (raw evidence for the analytics object store).

Immediate blocking is NOT done here. It stays in pfSense ACLs and Suricata IPS
(drop rules) at the OT edge. This module only observes and alerts.
"""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import logging
import logging.handlers
import os
import signal
import sys
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.telemetry_schema import (  # noqa: E402
    ValidationError, build_envelope, sha256_file, utcnow, validate_envelope)
from common.normalizers import normalise_eve, normalise_firewall_line  # noqa: E402,F401
from edge import edge_database as db  # noqa: E402

logger = logging.getLogger("edge_collector")

# ---------------------------------------------------------------------------
# Configuration (environment). Values marked REQUIRED_INPUT have no safe default.
# ---------------------------------------------------------------------------
EDGE_ID = os.environ.get("CYB691_EDGE_ID", "")                       # REQUIRED_INPUT
EVE_PATH = os.environ.get("CYB691_EVE_PATH", "/var/log/suricata/eve.json")
FIREWALL_LOG_PATH = os.environ.get("CYB691_FIREWALL_LOG_PATH", "/var/log/firewall/filter.log")
OUTBOX_DIR = os.environ.get("CYB691_OUTBOX_DIR", os.path.join(db.DEFAULT_EDGE_DATA_DIR, "outbox"))
ALERT_LOG_PATH = os.environ.get("CYB691_ALERT_LOG", os.path.join(db.DEFAULT_EDGE_DATA_DIR, "local_alerts.jsonl"))
QUARANTINE_PATH = os.environ.get("CYB691_QUARANTINE_LOG",
                                 os.path.join(db.DEFAULT_EDGE_DATA_DIR, "quarantine.jsonl"))
# Authorised Modbus writers (engineering workstation / HMI). REQUIRED_INPUT per site.
ALLOWED_WRITER_CIDRS = [c for c in os.environ.get("CYB691_ALLOWED_WRITER_CIDRS", "").split(",") if c.strip()]
ALLOWED_FUNCTION_CODES = {int(x) for x in os.environ.get(
    "CYB691_ALLOWED_FUNCTION_CODES", "1,2,3,4,5,6,15,16").split(",") if x.strip()}
BURST_WINDOW_SECONDS = float(os.environ.get("CYB691_BURST_WINDOW_SECONDS", "1.0"))
BURST_THRESHOLD = int(os.environ.get("CYB691_BURST_THRESHOLD", "50"))
SYSLOG_ADDRESS = os.environ.get("CYB691_LOCAL_SYSLOG", "")             # optional local SIEM, host:port
SNAPSHOT_INTERVAL_SECONDS = int(os.environ.get("CYB691_SNAPSHOT_INTERVAL", "900"))
POLL_SECONDS = float(os.environ.get("CYB691_POLL_SECONDS", "1.0"))


# ============================================================================
# Local fallback detection (works offline)
# ============================================================================

class LocalDetector:
    """Simple deterministic rules evaluated at the edge. Independent of the analytics tier."""

    def __init__(self, allowed_writer_cidrs: Iterable[str], allowed_fcs: Iterable[int],
                 burst_window: float = BURST_WINDOW_SECONDS, burst_threshold: int = BURST_THRESHOLD):
        self.allowed_writers = [ipaddress.ip_network(c.strip(), strict=False) for c in allowed_writer_cidrs]
        self.allowed_fcs = set(allowed_fcs)
        self.burst_window = burst_window
        self.burst_threshold = burst_threshold
        self._recent: Deque[float] = deque()

    def _is_allowed_writer(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.allowed_writers)

    def evaluate(self, env: Dict[str, Any], now_monotonic: Optional[float] = None) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        mb = env.get("modbus") or {}
        fc = mb.get("function_code")
        if env["event_type"] == "MODBUS_DPI" and isinstance(fc, int):
            if mb.get("category") == "WRITE" and not self._is_allowed_writer(env.get("src_ip")):
                alerts.append({"rule": "UNAUTHORISED_MODBUS_WRITE", "severity": "CRITICAL",
                               "detail": f"FC{fc} from non-allowlisted {env.get('src_ip')}"})
            if fc not in self.allowed_fcs:
                alerts.append({"rule": "UNEXPECTED_FUNCTION_CODE", "severity": "HIGH",
                               "detail": f"FC{fc} not in allowed set"})
            t = now_monotonic if now_monotonic is not None else time.monotonic()
            self._recent.append(t)
            while self._recent and t - self._recent[0] > self.burst_window:
                self._recent.popleft()
            if len(self._recent) == self.burst_threshold:
                alerts.append({"rule": "MODBUS_BURST", "severity": "HIGH",
                               "detail": f">={self.burst_threshold} Modbus requests in {self.burst_window}s"})
        if env["event_type"] == "SURICATA_ALERT" and env["severity"] in ("HIGH", "CRITICAL"):
            alerts.append({"rule": "SURICATA_HIGH_SEVERITY", "severity": env["severity"],
                           "detail": str((env.get("raw") or {}).get("alert", {}).get("signature", ""))[:200]})
        if env["event_type"] == "FIREWALL_DROP" and env.get("dest_port") == 502:
            alerts.append({"rule": "BLOCKED_MODBUS_ATTEMPT", "severity": "HIGH",
                           "detail": f"blocked {env.get('src_ip')} -> {env.get('dest_ip')}:502"})
        return alerts


class LocalAlerter:
    """Writes alerts to a local JSONL file and, optionally, to a LOCAL syslog/SIEM.
    Never depends on the analytics tier."""

    def __init__(self, path: str = ALERT_LOG_PATH, syslog_address: str = SYSLOG_ADDRESS):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.sys = None
        if syslog_address:
            host, _, port = syslog_address.partition(":")
            self.sys = logging.getLogger("cyb691.local_alerts")
            self.sys.addHandler(logging.handlers.SysLogHandler(address=(host, int(port or 514))))
            self.sys.setLevel(logging.WARNING)

    def emit(self, alert: Dict[str, Any]) -> None:
        line = json.dumps(alert, sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        logger.warning("LOCAL ALERT %s", line)
        if self.sys:
            self.sys.warning(line)


# ============================================================================
# File tailing with persisted offsets
# ============================================================================

def _head_fingerprint(path: str, n: int) -> str:
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read(n)).hexdigest()


def read_new_lines(path: str, state_key: str, db_path: Optional[str] = None,
                   max_lines: int = 5000) -> Tuple[List[Tuple[int, str]], Dict[str, Any]]:
    """Returns [(byte_offset, line)] appended since last call.

    Rotation/truncation is detected by inode change, size shrink, OR a changed
    fingerprint of the file's first bytes (covers inode reuse and copytruncate).
    """
    if not os.path.exists(path):
        return [], {}
    st = os.stat(path)
    state = db.get_state(state_key, db_path) or {}
    offset = state.get("offset", 0)
    head_len = state.get("head_len", 0)
    if (state.get("inode") != st.st_ino or st.st_size < offset or
            (head_len and _head_fingerprint(path, head_len) != state.get("head"))):
        offset = 0
    out: List[Tuple[int, str]] = []
    with open(path, "rb") as f:
        f.seek(offset)
        while len(out) < max_lines:
            pos = f.tell()
            raw = f.readline()
            if not raw or not raw.endswith(b"\n"):     # partial line: wait for writer
                break
            out.append((pos, raw.decode("utf-8", errors="replace")))
            offset = f.tell()
    new_head_len = min(256, offset)
    return out, {"inode": st.st_ino, "offset": offset, "path": path, "head_len": new_head_len,
                 "head": _head_fingerprint(path, new_head_len) if new_head_len else None}


# ============================================================================
# Raw evidence snapshots
# ============================================================================

def snapshot_raw_range(path: str, kind: str, edge_id: str, db_path: Optional[str] = None,
                       outbox_dir: str = OUTBOX_DIR) -> Optional[str]:
    """Copies the bytes appended since the last snapshot into a gzip chunk,
    hashes it and queues it for upload. Returns upload_id or None."""
    if not os.path.exists(path):
        return None
    key = f"snapshot:{kind}:{path}"
    st = os.stat(path)
    state = db.get_state(key, db_path) or {}
    start = state.get("offset", 0) if state.get("inode") == st.st_ino and st.st_size >= state.get("offset", 0) else 0
    if st.st_size <= start:
        return None
    os.makedirs(outbox_dir, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%S%fZ")
    ext = {"EVE_JSON": "eve.json.gz", "FIREWALL_LOG": "filter.log.gz"}.get(kind, "bin.gz")
    local = os.path.join(outbox_dir, f"{kind.lower()}-{stamp}-{start}-{st.st_size}.{ext}")
    with open(path, "rb") as src, gzip.GzipFile(local, "wb", mtime=0) as dst:
        src.seek(start)
        remaining = st.st_size - start
        while remaining > 0:
            chunk = src.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
    digest, size = sha256_file(local)
    upload_id = enqueue_evidence_file(local, kind, edge_id, db_path, digest=digest, size=size,
                                      extra={"source_path": path, "byte_range": [start, st.st_size]})
    db.set_state(key, {"inode": st.st_ino, "offset": st.st_size}, db_path)
    return upload_id


def enqueue_evidence_file(local_path: str, kind: str, edge_id: str, db_path: Optional[str] = None,
                          digest: Optional[str] = None, size: Optional[int] = None,
                          extra: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Queues a raw evidence file (PCAP, CSV, log chunk) for upload."""
    if digest is None or size is None:
        digest, size = sha256_file(local_path)
    now = utcnow()
    name = os.path.basename(local_path)
    blob_name = (f"{kind.lower()}/edge={edge_id}/yyyy={now:%Y}/mm={now:%m}/dd={now:%d}/"
                 f"{digest[:16]}-{name}")
    manifest = {"kind": kind, "edge_id": edge_id, "file_name": name, "sha256": digest,
                "size_bytes": size, "collected_at_utc": now.isoformat(), **(extra or {})}
    return db.enqueue_upload(kind, local_path, blob_name, digest, size,
                             content_type="application/gzip" if name.endswith(".gz") else "application/octet-stream",
                             manifest=manifest, db_path=db_path)


# ============================================================================
# Collector loop
# ============================================================================

class Collector:
    def __init__(self, edge_id: str, db_path: Optional[str] = None,
                 detector: Optional[LocalDetector] = None, alerter: Optional[LocalAlerter] = None,
                 quarantine_path: str = QUARANTINE_PATH):
        if not edge_id:
            raise SystemExit("CYB691_EDGE_ID is required (REQUIRED_INPUT)")
        self.edge_id = edge_id
        self.db_path = db_path
        self.detector = detector or LocalDetector(ALLOWED_WRITER_CIDRS, ALLOWED_FUNCTION_CODES)
        self.alerter = alerter or LocalAlerter()
        self.quarantine_path = quarantine_path
        self._stop = False

    def _quarantine(self, source: str, line: str, error: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.quarantine_path)), exist_ok=True)
        with open(self.quarantine_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"at": utcnow().isoformat(), "source": source, "error": error,
                                "line": line[:4000]}) + "\n")

    def ingest_envelope(self, env: Dict[str, Any], source: str, line: str) -> bool:
        try:
            validate_envelope(env)
        except ValidationError as exc:
            self._quarantine(source, line, str(exc))
            return False
        if db.is_known_event(env["idempotency_key"], self.db_path):
            # Same content already collected (e.g. Suricata wrote the record twice, or the file was
            # re-read after rotation/replay): the queue would drop it anyway, so don't alert twice.
            return False
        for a in self.detector.evaluate(env):
            alert_env = build_envelope(
                edge_id=self.edge_id, event_type="LOCAL_ALERT", timestamp_utc=env["timestamp_utc"],
                severity=a["severity"], src_ip=env.get("src_ip"), dest_ip=env.get("dest_ip"),
                dest_port=env.get("dest_port"), protocol=env.get("protocol"),
                modbus=env.get("modbus"), raw={"rule": a["rule"], "detail": a["detail"],
                                               "trigger_idempotency_key": env["idempotency_key"]},
                raw_ref={"trigger_event_uuid": env["event_uuid"]})
            self.alerter.emit({"rule": a["rule"], "severity": a["severity"], "detail": a["detail"],
                               "event_timestamp_utc": env["timestamp_utc"], "edge_id": self.edge_id,
                               "trigger_idempotency_key": env["idempotency_key"]})
            self._enqueue(alert_env)
        self._enqueue(env)
        return True

    def _enqueue(self, env: Dict[str, Any]) -> None:
        try:
            db.enqueue_telemetry(env, self.db_path)
        except db.BufferFullError as exc:
            # Local alerting continues even when the buffer is full.
            self.alerter.emit({"rule": "EDGE_BUFFER_FULL", "severity": "CRITICAL", "detail": str(exc),
                               "edge_id": self.edge_id, "at": utcnow().isoformat()})

    def poll_once(self, eve_path: str = EVE_PATH, fw_path: str = FIREWALL_LOG_PATH) -> int:
        n = 0
        lines, st = read_new_lines(eve_path, f"tail:{eve_path}", self.db_path)
        for off, line in lines:
            try:
                rec = json.loads(line)
                env = normalise_eve(rec, self.edge_id, {"file": eve_path, "offset": off})
            except (json.JSONDecodeError, ValidationError, ValueError, TypeError) as exc:
                self._quarantine("eve", line, f"parse error: {exc}")
                continue
            if env is not None and self.ingest_envelope(env, "eve", line):
                n += 1
        if st:
            db.set_state(f"tail:{eve_path}", st, self.db_path)
        lines, st = read_new_lines(fw_path, f"tail:{fw_path}", self.db_path)
        for off, line in lines:
            try:
                env = normalise_firewall_line(line, self.edge_id, {"file": fw_path, "offset": off})
            except (ValidationError, ValueError) as exc:
                self._quarantine("firewall", line, f"parse error: {exc}")
                continue
            if env is not None and self.ingest_envelope(env, "firewall", line):
                n += 1
        if st:
            db.set_state(f"tail:{fw_path}", st, self.db_path)
        return n

    def run(self) -> None:
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "_stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "_stop", True))
        last_snapshot = 0.0
        while not self._stop:
            self.poll_once()
            if time.monotonic() - last_snapshot >= SNAPSHOT_INTERVAL_SECONDS:
                snapshot_raw_range(EVE_PATH, "EVE_JSON", self.edge_id, self.db_path)
                snapshot_raw_range(FIREWALL_LOG_PATH, "FIREWALL_LOG", self.edge_id, self.db_path)
                db.cleanup_expired(db_path=self.db_path)
                last_snapshot = time.monotonic()
            time.sleep(POLL_SECONDS)
        db.safe_shutdown(self.db_path)
        logger.info("collector stopped cleanly")


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    ap = argparse.ArgumentParser(description="CYB691 edge collector (read-only, local alerting)")
    ap.add_argument("--once", action="store_true", help="poll once and exit")
    ap.add_argument("--enqueue-file", nargs=2, metavar=("KIND", "PATH"),
                    help="queue a raw evidence file, e.g. PCAP /data/pcap/log.pcap.1")
    args = ap.parse_args()
    q = db.open_or_recover()
    if q:
        LocalAlerter().emit({"rule": "EDGE_DB_CORRUPTION_RECOVERED", "severity": "HIGH",
                             "detail": f"quarantined {q}", "edge_id": EDGE_ID})
    c = Collector(EDGE_ID)
    if args.enqueue_file:
        print(enqueue_evidence_file(args.enqueue_file[1], args.enqueue_file[0], EDGE_ID))
    elif args.once:
        print(c.poll_once())
    else:
        c.run()


if __name__ == "__main__":
    main()
