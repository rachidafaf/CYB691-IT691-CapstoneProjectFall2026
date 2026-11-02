#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Module: Shared raw-record normalisers (normalizers.py)

Used by the edge collector (live tailing) AND by the analytics log-parser job
(re-parsing raw evidence chunks from the object store for reconciliation). Because
both sides produce byte-identical content hashes for the same raw record, the
analytics tier can prove that every raw Suricata/firewall record has a matching
normalised event (and backfill any that are missing).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from common.telemetry_schema import (
    ValidationError, build_envelope, classify_function_code, parse_utc, utcnow)


# ============================================================================
# Normalisers
# ============================================================================

def _int_or_none(v: Any) -> Optional[int]:
    try:
        return int(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def normalise_eve(record: Dict[str, Any], edge_id: str, raw_ref: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Maps one Suricata EVE record to an envelope; returns None for event types we ignore."""
    et = str(record.get("event_type", "")).lower()
    if et not in ("modbus", "alert", "drop"):
        return None
    mb_src = record.get("modbus") or {}
    req = mb_src.get("request") if isinstance(mb_src.get("request"), dict) else {}
    fc = _int_or_none(req.get("function_raw", mb_src.get("function_code") if isinstance(
        mb_src.get("function_code"), int) else mb_src.get("function_raw")))
    modbus = None
    severity = "INFO"
    if fc is not None:
        category, severity = classify_function_code(fc)
        read = req.get("read") if isinstance(req.get("read"), dict) else {}
        write = req.get("write") if isinstance(req.get("write"), dict) else {}
        modbus = {
            "unit_id": _int_or_none(req.get("unit_id", mb_src.get("unit_id"))),
            "function_code": fc,
            "function_name": str(req.get("function_code", mb_src.get("func_string", f"FC{fc}"))),
            "category": category,
            "transaction_id": _int_or_none(req.get("transaction_id", mb_src.get("transaction_id"))),
            "address": _int_or_none(read.get("address", write.get("address", mb_src.get("address")))),
            "quantity": _int_or_none(read.get("quantity", write.get("quantity"))),
        }
    if et == "alert":
        sev_num = _int_or_none((record.get("alert") or {}).get("severity")) or 3
        severity = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(sev_num, "LOW")
        event_type = "SURICATA_ALERT"
    elif et == "drop":
        event_type, severity = "FIREWALL_DROP", "MEDIUM"
    else:
        event_type = "MODBUS_DPI"
        if modbus is None:
            # an explicit modbus event without a parsable function code is itself suspicious
            modbus = {"function_code": 0}
    return build_envelope(
        edge_id=edge_id, event_type=event_type, timestamp_utc=record.get("timestamp"), severity=severity,
        src_ip=record.get("src_ip"), src_port=_int_or_none(record.get("src_port")),
        dest_ip=record.get("dest_ip"), dest_port=_int_or_none(record.get("dest_port")),
        protocol=record.get("proto"), modbus=modbus, raw=record, raw_ref=raw_ref)


def _parse_pfsense_filterlog(line: str) -> Optional[Dict[str, Any]]:
    # pfSense filterlog CSV (IPv4 TCP/UDP). Field positions per pfSense docs.
    if "filterlog" not in line:
        return None
    csv_part = line.split("filterlog", 1)[1].split(":", 1)[-1].strip()
    f = csv_part.split(",")
    if len(f) < 22 or f[8] != "4":
        return None
    return {"action": f[6], "direction": f[7], "interface": f[4], "rule": f[0], "proto": f[16].upper(),
            "src": f[18], "dst": f[19], "spt": _int_or_none(f[20]), "dpt": _int_or_none(f[21])}


def _parse_iptables(line: str) -> Optional[Dict[str, Any]]:
    if "SRC=" not in line or "DST=" not in line:
        return None
    kv = dict(tok.split("=", 1) for tok in line.split() if "=" in tok)
    return {"action": "block", "direction": "in", "interface": kv.get("IN"), "rule": kv.get("PREFIX"),
            "proto": kv.get("PROTO"), "src": kv.get("SRC"), "dst": kv.get("DST"),
            "spt": _int_or_none(kv.get("SPT")), "dpt": _int_or_none(kv.get("DPT"))}


def normalise_firewall_line(line: str, edge_id: str, raw_ref: Dict[str, Any],
                            observed_at: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line.startswith("--"):          # e.g. "-- No entries --" markers
        return None
    p = _parse_pfsense_filterlog(line) or _parse_iptables(line)
    if not p or str(p.get("action", "")).lower() not in ("block", "drop", "reject"):
        return None
    sev = "HIGH" if p.get("dpt") == 502 else "MEDIUM"
    # Prefer an RFC 5424 / ISO timestamp at the start of the line (stable hash on
    # re-read). Legacy BSD syslog lacks year/zone: fall back to observation time
    # and keep the raw line for forensic re-interpretation.
    ts: Any = observed_at or utcnow()
    for token in line.split()[:2]:
        try:
            ts = parse_utc(token)
            break
        except ValidationError:
            continue
    return build_envelope(
        edge_id=edge_id, event_type="FIREWALL_DROP", timestamp_utc=ts, severity=sev,
        src_ip=p.get("src"), src_port=p.get("spt"), dest_ip=p.get("dst"), dest_port=p.get("dpt"),
        protocol=p.get("proto"), modbus=None,
        raw={"line": line, "parsed": p}, raw_ref=raw_ref)




def has_stable_timestamp(line: str) -> bool:
    """True if a firewall log line carries its own ISO/RFC 5424 timestamp, so that
    re-normalising it later yields the same content hash (reconcilable)."""
    for token in line.strip().split()[:2]:
        try:
            parse_utc(token)
            return True
        except ValidationError:
            continue
    return False


def legacy_record(env: Dict[str, Any], inter_arrival_ms: float) -> Dict[str, Any]:
    """Maps an envelope to the record shape used by src/ml_detector.py and
    src/timeline_generator.py, so the analytics jobs reuse the team's existing code
    and feature definitions unchanged."""
    raw = env.get("raw") if isinstance(env.get("raw"), dict) else {}
    mbraw = raw.get("modbus") if isinstance(raw.get("modbus"), dict) else {}
    req = mbraw.get("request") if isinstance(mbraw.get("request"), dict) else {}
    resp = mbraw.get("response") if isinstance(mbraw.get("response"), dict) else {}
    mb = env.get("modbus") or {}
    fc = mb.get("function_code") or 0
    if isinstance(req.get("read"), dict):
        r = req["read"]
        payload_raw = f"read:addr={r.get('address', 0)} qty={r.get('quantity', 1)}"
    elif isinstance(req.get("write"), dict):
        w = req["write"]
        payload_raw = f"write:addr={w.get('address', 0)} val={w.get('data', w.get('value', ''))}"
    else:
        payload_raw = f"FC={fc}"
    exc = resp.get("exception") if isinstance(resp, dict) else None
    return {
        "event_id": env.get("idempotency_key"),
        "timestamp_iso": env.get("timestamp_utc"),
        "inter_arrival_ms": round(float(inter_arrival_ms), 2),
        "network": {"source_ip": env.get("src_ip"), "dest_ip": env.get("dest_ip"),
                    "destination_port": env.get("dest_port") or 502, "protocol": "Modbus_TCP"},
        "modbus": {"unit_id": mb.get("unit_id") if mb.get("unit_id") is not None else 1,
                   "function_code": fc, "function_name": mb.get("function_name"),
                   "category": mb.get("category"), "payload_raw": payload_raw,
                   "exception_code": "None" if not exc else str(exc)},
        "security": {"has_protocol_exception": bool(exc), "is_state_altering": mb.get("category") == "WRITE"},
    }
