#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Module: Shared telemetry envelope, validation and hashing (telemetry_schema.py)

Used by BOTH the OT edge (collector / sync service) and the analytics
services so that hashing, idempotency keys and validation rules are identical
on both sides of the trust boundary.

Envelope fields (schema_version "1.0"):
    event_uuid        UUID4 assigned at the edge when first collected
    schema_version    "1.0"
    edge_id           Identifier of the edge gateway (REQUIRED_INPUT per site)
    event_type        MODBUS_DPI | SURICATA_ALERT | FIREWALL_DROP | LOCAL_ALERT
    timestamp_utc     ISO-8601 UTC timestamp of the observed event
    collected_at_utc  ISO-8601 UTC timestamp when the edge collected it
    severity          INFO | LOW | MEDIUM | HIGH | CRITICAL
    src_ip/src_port/dest_ip/dest_port/protocol
    modbus            {unit_id, function_code, function_name, category, ...} or None
    raw_ref           Reference to the raw evidence object (file + offset/line)
    raw               The raw source record (dict or str) – kept for evidence
    sha256_hash       SHA-256 of the canonical content (see canonical_content)
    idempotency_key   == sha256_hash (content-addressed; stable across retries,
                      collector restarts and re-reads of the same log line)

Design note: the existing src/log_parser.py assigns positional event IDs
("MODBUS-EVT-0001"), which change between runs. They must NOT be used for
de-duplication. The content hash is used instead.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "1.0"

EVENT_TYPES = {"MODBUS_DPI", "SURICATA_ALERT", "FIREWALL_DROP", "LOCAL_ALERT"}
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Modbus public function codes we expect in this lab; anything else in 1..127 is
# "valid but unexpected" (flagged), and anything outside 1..255 is invalid.
READ_FCS = {1, 2, 3, 4}
WRITE_FCS = {5, 6, 15, 16}
DIAG_FCS = {7, 8, 11, 12, 17, 20, 21, 22, 23, 24, 43}

# Timestamp sanity window. Events older than this, or further in the future than
# MAX_FUTURE_SKEW, are rejected as timestamp errors (clock drift / tampering).
MIN_VALID_TIMESTAMP = datetime(2020, 1, 1, tzinfo=timezone.utc)
MAX_FUTURE_SKEW = timedelta(minutes=5)

# Fields that make up the hashed content. Ingestion metadata (event_uuid,
# collected_at_utc) is deliberately excluded so re-collection of the same raw
# record produces the same hash.
_HASHED_FIELDS = (
    "schema_version", "edge_id", "event_type", "timestamp_utc", "severity",
    "src_ip", "src_port", "dest_ip", "dest_port", "protocol", "modbus", "raw",
)


class ValidationError(ValueError):
    """Raised when a telemetry envelope fails validation."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_utc(value: Any) -> datetime:
    """Parses an ISO-8601 timestamp and returns an aware UTC datetime.

    Accepts Suricata's "+0000" offset form. Naive timestamps are rejected,
    because silently assuming a zone is a common source of timeline errors.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value:
        s = value.strip().replace("Z", "+00:00")
        # Suricata emits +0000 (no colon); fromisoformat on 3.10 needs +00:00
        if len(s) > 5 and (s[-5] in "+-") and s[-4:].isdigit() and s[-3] != ":":
            s = s[:-2] + ":" + s[-2:]
        try:
            dt = datetime.fromisoformat(s)
        except ValueError as exc:
            raise ValidationError(f"unparseable timestamp: {value!r}") from exc
    else:
        raise ValidationError(f"missing timestamp: {value!r}")
    if dt.tzinfo is None:
        raise ValidationError(f"timestamp has no timezone: {value!r}")
    return dt.astimezone(timezone.utc)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for hashing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def canonical_content(envelope: Dict[str, Any]) -> Dict[str, Any]:
    return {k: envelope.get(k) for k in _HASHED_FIELDS}


def compute_sha256(envelope: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(canonical_content(envelope)).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1024 * 1024) -> Tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            size += len(b)
            h.update(b)
    return h.hexdigest(), size


def classify_function_code(fc: int) -> Tuple[str, str]:
    """Returns (category, default_severity) for a Modbus function code."""
    if fc in READ_FCS:
        return "READ", "INFO"
    if fc in (15, 16):
        return "WRITE", "CRITICAL"
    if fc in (5, 6):
        return "WRITE", "HIGH"
    if fc in DIAG_FCS:
        return "DIAGNOSTIC", "MEDIUM"
    if fc >= 128:
        return "EXCEPTION_RESPONSE", "MEDIUM"
    return "UNKNOWN", "MEDIUM"


def _validate_ip(name: str, value: Any, required: bool) -> None:
    if value in (None, ""):
        if required:
            raise ValidationError(f"{name} is required")
        return
    try:
        ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise ValidationError(f"{name} is not a valid IP address: {value!r}") from exc


def _validate_port(name: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 65535):
        raise ValidationError(f"{name} out of range: {value!r}")


def validate_envelope(envelope: Dict[str, Any], now: Optional[datetime] = None,
                      verify_hash: bool = True) -> Dict[str, Any]:
    """Validates an envelope in place and returns it.

    Raises ValidationError describing the first problem found. Callers send
    invalid records to a quarantine path rather than dropping them, so evidence
    of malformed or hostile input is preserved.
    """
    now = now or utcnow()
    if envelope.get("schema_version") != SCHEMA_VERSION:
        raise ValidationError(f"unsupported schema_version: {envelope.get('schema_version')!r}")
    try:
        uuid.UUID(str(envelope.get("event_uuid")))
    except ValueError as exc:
        raise ValidationError("event_uuid is not a UUID") from exc
    if not envelope.get("edge_id") or not isinstance(envelope["edge_id"], str):
        raise ValidationError("edge_id is required")
    if envelope.get("event_type") not in EVENT_TYPES:
        raise ValidationError(f"unknown event_type: {envelope.get('event_type')!r}")
    if envelope.get("severity") not in SEVERITIES:
        raise ValidationError(f"unknown severity: {envelope.get('severity')!r}")

    ts = parse_utc(envelope.get("timestamp_utc"))
    if ts < MIN_VALID_TIMESTAMP:
        raise ValidationError(f"timestamp before {MIN_VALID_TIMESTAMP.date()}: {ts.isoformat()}")
    if ts > now + MAX_FUTURE_SKEW:
        raise ValidationError(f"timestamp in the future beyond allowed skew: {ts.isoformat()}")
    parse_utc(envelope.get("collected_at_utc"))

    _validate_ip("src_ip", envelope.get("src_ip"), required=envelope["event_type"] != "LOCAL_ALERT")
    _validate_ip("dest_ip", envelope.get("dest_ip"), required=envelope["event_type"] != "LOCAL_ALERT")
    _validate_port("src_port", envelope.get("src_port"))
    _validate_port("dest_port", envelope.get("dest_port"))

    mb = envelope.get("modbus")
    if envelope["event_type"] == "MODBUS_DPI" and not mb:
        raise ValidationError("MODBUS_DPI event requires a modbus object")
    if mb is not None:
        if not isinstance(mb, dict):
            raise ValidationError("modbus must be an object")
        fc = mb.get("function_code")
        if isinstance(fc, bool) or not isinstance(fc, int) or not (1 <= fc <= 255):
            raise ValidationError(f"invalid Modbus function code: {fc!r}")
        unit = mb.get("unit_id")
        if unit is not None and (isinstance(unit, bool) or not isinstance(unit, int) or not (0 <= unit <= 255)):
            raise ValidationError(f"invalid Modbus unit_id: {unit!r}")
        for key in ("address", "quantity"):
            v = mb.get(key)
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or not (0 <= v <= 65535)):
                raise ValidationError(f"invalid Modbus {key}: {v!r}")

    if verify_hash:
        expected = compute_sha256(envelope)
        if envelope.get("sha256_hash") != expected:
            raise ValidationError("sha256_hash mismatch (content altered or mis-hashed)")
        if envelope.get("idempotency_key") != expected:
            raise ValidationError("idempotency_key must equal sha256_hash")
    return envelope


def build_envelope(*, edge_id: str, event_type: str, timestamp_utc: Any, severity: str,
                   src_ip: Optional[str] = None, src_port: Optional[int] = None,
                   dest_ip: Optional[str] = None, dest_port: Optional[int] = None,
                   protocol: Optional[str] = None, modbus: Optional[Dict[str, Any]] = None,
                   raw: Any = None, raw_ref: Optional[Dict[str, Any]] = None,
                   collected_at_utc: Optional[datetime] = None) -> Dict[str, Any]:
    """Creates a hashed envelope. Does not validate (call validate_envelope)."""
    ts = parse_utc(timestamp_utc).isoformat()
    env: Dict[str, Any] = {
        "event_uuid": str(uuid.uuid4()),
        "schema_version": SCHEMA_VERSION,
        "edge_id": edge_id,
        "event_type": event_type,
        "timestamp_utc": ts,
        "collected_at_utc": (collected_at_utc or utcnow()).isoformat(),
        "severity": severity,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "protocol": protocol,
        "modbus": modbus,
        "raw_ref": raw_ref,
        "raw": raw,
    }
    digest = compute_sha256(env)
    env["sha256_hash"] = digest
    env["idempotency_key"] = digest
    return env


def batch_manifest(*, batch_id: str, edge_id: str, object_name: str, object_sha256: str,
                   object_size: int, event_count: int, content_type: str,
                   event_keys: List[str], first_ts: Optional[str], last_ts: Optional[str]) -> Dict[str, Any]:
    """Manifest uploaded next to every batch/archive (evidence traceability)."""
    return {
        "manifest_version": "1.0",
        "schema_version": SCHEMA_VERSION,
        "batch_id": batch_id,
        "edge_id": edge_id,
        "object_name": object_name,
        "object_sha256": object_sha256,
        "object_size_bytes": object_size,
        "content_type": content_type,
        "event_count": event_count,
        "event_idempotency_keys": event_keys,
        "first_event_utc": first_ts,
        "last_event_utc": last_ts,
        "created_at_utc": utcnow().isoformat(),
    }
