#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: Dynamic Telemetry Normalization & Ingestion Engine (log_parser.py)
Author: Rachid Afaf (Security Architect / Lead Analyst)
===============================================================================
Description:
  Dynamically locates, extracts, and ingests OT telemetry handoff archives 
  (ot_telemetry_handoff_*.tar.gz or extracted folders). Parses Suricata EVE 
  JSON Modbus DPI events and iptables/pfSense firewall drops into a standardized 
  ISO 8601 JSON schema with inter-arrival delta times (dt) and threat scoring.
  Paths resolve dynamically relative to the repository root for portability.
  
  Key Security & Normalization Enhancements:
    1. Preserves raw Modbus function codes (modbus.request.function_raw)
       to retain the critical read/write distinction (FC01/FC03 vs FC05/FC06/FC16).
    2. Filters Suricata EVE JSON strictly for explicit Modbus DPI events 
       (event_type == 'modbus'), avoiding ingestion of unrelated alerts/frames.
    3. Rejects empty firewall log markers ("-- No entries --") to prevent
       spurious firewall-drop records.
    4. Enforces Tar-Slip path traversal security during archive extraction.
    5. Verifies cryptographic SHA-256 sidecar hashes when present.
===============================================================================
"""

import os
import sys
import glob
import json
import hashlib
import tarfile
import argparse
import pandas as pd
from datetime import datetime, timezone

from jinja2.exceptions import SecurityError

try:
    from src.database import insert_telemetry_records, describe_target, DEFAULT_DB_PATH
except ImportError:
    from database import insert_telemetry_records, describe_target, DEFAULT_DB_PATH

# Canonical project directories dynamically resolved relative to repo root
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(REPO_ROOT, "data")
DEFAULT_INFRA_DIR = os.path.join(REPO_ROOT, "infrastructure")

# Modbus Function Code Taxonomy & Risk Mapping
MODBUS_FUNCTION_MAP = {
    1: {"name": "Read Coils", "category": "READ", "risk_level": "LOW"},
    2: {"name": "Read Discrete Inputs", "category": "READ", "risk_level": "LOW"},
    3: {"name": "Read Holding Registers", "category": "READ", "risk_level": "LOW"},
    4: {"name": "Read Input Registers", "category": "READ", "risk_level": "LOW"},
    5: {"name": "Write Single Coil", "category": "WRITE", "risk_level": "HIGH"},
    6: {"name": "Write Single Register", "category": "WRITE", "risk_level": "HIGH"},
    15: {"name": "Write Multiple Coils", "category": "WRITE", "risk_level": "CRITICAL"},
    16: {"name": "Write Multiple Registers", "category": "WRITE", "risk_level": "CRITICAL"}
}

# String name to Modbus Function Code lookup
FUNCTION_NAME_TO_CODE = {
    "rdcoils": 1,
    "read_coils": 1,
    "rddiscinputs": 2,
    "read_discrete_inputs": 2,
    "rdholdregs": 3,
    "read_holding_registers": 3,
    "rdinpregs": 4,
    "read_input_registers": 4,
    "wrsinglecoil": 5,
    "write_single_coil": 5,
    "wrsinglereg": 6,
    "write_single_register": 6,
    "wrmultcoils": 15,
    "write_multiple_coils": 15,
    "wrmultregs": 16,
    "write_multiple_registers": 16
}


def parse_payload_string(payload_str):
    """Parses key-value metadata from payload strings (e.g. 'addr:0 val:1234')."""
    parsed = {}
    if not isinstance(payload_str, str) or not payload_str.strip():
        return parsed
    for part in payload_str.strip().split():
        if ":" in part:
            k, v = part.split(":", 1)
            parsed[k] = v
    return parsed


def is_within_directory(directory, target):
    """Guards against Tar-Slip directory traversal vulnerability."""
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    try:
        common = os.path.commonpath([abs_directory, abs_target])
        return common == abs_directory
    except ValueError:
        return False


def safe_extract_tarball(tar_path, extract_dir):
    """Extracts tarball securely after enforcing path traversal bounds."""
    os.makedirs(extract_dir, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            member_path = os.path.join(extract_dir, member.name)
            if not is_within_directory(extract_dir, member_path):
                raise SecurityError(f"Tar-Slip Path Traversal Attack Detected in {member.name}")
            if member.issym() or member.islnk() or member.isdev():
                # a link's *target* can point outside extract_dir even when its own path is inside
                raise SecurityError(f"Link or device member rejected in telemetry archive: {member.name}")
        try:
            tar.extractall(path=extract_dir, filter="data")   # stdlib safety filter (Python 3.12+ / patched 3.8+)
        except TypeError:                                     # older interpreter without extraction filters
            tar.extractall(path=extract_dir)


def sha256_of_file(path):
    """SHA-256 of a file, streamed."""
    hasher = hashlib.sha256()
    with open(path, 'rb') as fh:
        while chunk := fh.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_sha256_sidecar(target_path):
    """Verifies SHA-256 sidecar hash if a .sha256 sidecar file exists."""
    sidecar_path = target_path + ".sha256"
    if not os.path.exists(sidecar_path):
        sidecar_path = os.path.splitext(target_path)[0] + ".sha256"
    
    if os.path.exists(sidecar_path):
        print(f"[*] Verifying cryptographic sidecar hash: {sidecar_path}")
        with open(sidecar_path, 'r', encoding='utf-8') as sf:
            expected_hash = sf.read().strip().split()[0].lower()
        
        hasher = hashlib.sha256()
        with open(target_path, 'rb') as tf:
            while chunk := tf.read(65536):
                hasher.update(chunk)
        calculated_hash = hasher.hexdigest().lower()

        if calculated_hash == expected_hash:
            print(f"[+] SHA-256 Checksum Verified: {calculated_hash[:16]}...")
            return True
        else:
            print(f"[!] WARNING: SHA-256 Checksum Mismatch! Expected {expected_hash[:16]}, got {calculated_hash[:16]}")
            return False
    return None


def find_latest_handoff_target(search_base=None):
    """Finds the latest ot_telemetry_handoff_*.tar.gz archive dynamically."""
    if search_base and os.path.exists(search_base):
        if os.path.isfile(search_base) or search_base.endswith('.tar.gz'):
            return search_base
        if os.path.isdir(search_base):
            return search_base

    possible_roots = [
        DEFAULT_INFRA_DIR,
        os.path.join(REPO_ROOT, "infrastructure"),
        "infrastructure",
        DEFAULT_DATA_DIR,
        "data",
        REPO_ROOT,
        "."
    ]

    found_targets = []
    for root in possible_roots:
        if os.path.exists(root):
            tar_matches = glob.glob(os.path.join(root, "ot_telemetry_handoff_*.tar.gz"))
            found_targets.extend(tar_matches)
            
            dir_matches = [
                d for d in glob.glob(os.path.join(root, "ot_telemetry_handoff_*")) 
                if os.path.isdir(d)
            ]
            found_targets.extend(dir_matches)

    if not found_targets:
        return None

    # Deduplicate while preserving sort order
    unique_targets = list(set(found_targets))
    unique_targets.sort(reverse=True)
    return unique_targets[0]


def extract_tarball_if_needed(target_path, extract_dir):
    """Extracts .tar.gz archive safely if target_path is a compressed tarball."""
    if os.path.isfile(target_path) and (target_path.endswith('.tar.gz') or target_path.endswith('.tgz')):
        print(f"[*] Extracting compressed handoff archive: {target_path}")
        verify_sha256_sidecar(target_path)
        safe_extract_tarball(target_path, extract_dir)
        print(f"[+] Archive safely extracted to: {extract_dir}")
        return extract_dir
    return target_path


def discover_logs_in_dir(target_dir):
    """Recursively locates eve.json and iptables_drops.log in target directory."""
    found_files = {"eve_json": None, "iptables_log": None}
    
    if os.path.isfile(target_dir):
        if target_dir.endswith('.json'):
            found_files["eve_json"] = target_dir
        elif target_dir.endswith('.log'):
            found_files["iptables_log"] = target_dir
        return found_files

    for root, _, files in os.walk(target_dir):
        for f in files:
            full_p = os.path.join(root, f)
            if f == "eve.json":
                found_files["eve_json"] = full_p
            elif f == "iptables_drops.log" or f.endswith("_drops.log"):
                found_files["iptables_log"] = full_p

    return found_files


def extract_function_code(mb_data):
    """
    Extracts integer Modbus function code from Suricata EVE JSON modbus dictionary.
    Accurately extracts modbus.request.function_raw and preserves read/write distinction.
    """
    if not isinstance(mb_data, dict):
        return 0

    req = mb_data.get('request', {}) if isinstance(mb_data.get('request'), dict) else {}
    raw_code = req.get('function_raw', 
               mb_data.get('function_raw', 
               req.get('function_code', 
               mb_data.get('function_code', 0))))

    if isinstance(raw_code, int):
        return raw_code

    if isinstance(raw_code, str):
        clean = raw_code.strip()
        if clean.startswith(('0x', '0X')):
            try:
                return int(clean, 16)
            except ValueError:
                pass
        elif clean.isdigit():
            return int(clean)
        else:
            normalized_name = clean.lower().replace(" ", "").replace("_", "")
            if normalized_name in FUNCTION_NAME_TO_CODE:
                return FUNCTION_NAME_TO_CODE[normalized_name]

    return 0


def _canonical_record_key(item):
    """Canonical form of a raw EVE record (sorted keys, no whitespace). Two records
    with the same key are byte-for-byte the same observation logged more than once."""
    return json.dumps(item, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def normalize_suricata_eve_json(json_path, stats=None):
    """
    Parses Suricata EVE JSON events into unified event dictionaries.
    Strictly filters for explicit Modbus DPI events (event_type == 'modbus'),
    preserving function codes, payloads, and protocol exception states.

    Exact duplicate records are counted once. The 2026-09-26 handoff's eve.json logs
    every Modbus transaction twice on consecutive lines (identical timestamp, flow_id,
    transaction_id and payload); counting both copies inflated the event counts and
    placed copies of the same transaction in both ML training and test folds. Only
    records whose full canonical JSON is identical are collapsed; the raw evidence file
    is never modified. Pass a dict as `stats` to receive the de-duplication audit.
    """
    if not os.path.exists(json_path):
        return []

    raw_events = []
    with open(json_path, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if content.startswith('['):
            raw_events = json.loads(content)
        else:
            for line in content.splitlines():
                if line.strip():
                    try:
                        raw_events.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue

    parsed_items = []
    seen_keys = set()
    audit = {"eve_records_total": len(raw_events), "modbus_records_seen": 0,
             "exact_duplicates_removed": 0, "duplicates": []}
    for item in raw_events:
        event_type = str(item.get('event_type', '')).lower()
        
        # Strictly select explicit Modbus telemetry events
        if event_type != 'modbus':
            continue

        audit["modbus_records_seen"] += 1
        record_key = _canonical_record_key(item)
        if record_key in seen_keys:
            audit["exact_duplicates_removed"] += 1
            audit["duplicates"].append({
                "timestamp": item.get('timestamp'),
                "flow_id": item.get('flow_id'),
                "transaction_id": (item.get('modbus', {}).get('request') or {}).get('transaction_id'),
                "sha256": hashlib.sha256(record_key.encode('utf-8')).hexdigest(),
            })
            continue
        seen_keys.add(record_key)

        mb_data = item.get('modbus', {})
        if not mb_data:
            continue

        ts_str = item.get('timestamp')
        if not ts_str:
            continue
        try:
            dt = pd.to_datetime(ts_str)
        except Exception:
            dt = datetime.now(timezone.utc)

        src_ip = item.get('src_ip', item.get('source_ip', '10.0.1.4'))
        dest_ip = item.get('dest_ip', item.get('destination_ip', '172.17.0.2'))
        dest_port = item.get('dest_port', item.get('destination_port', 502))

        fcode = extract_function_code(mb_data)
        req = mb_data.get('request', {}) if isinstance(mb_data.get('request'), dict) else {}
        resp = mb_data.get('response', {}) if isinstance(mb_data.get('response'), dict) else {}

        raw_name = req.get('function_code', mb_data.get('function_name', f'Modbus FC{fcode}'))
        f_info = MODBUS_FUNCTION_MAP.get(fcode, {
            "name": raw_name,
            "category": "WRITE" if fcode in [5, 6, 15, 16] else ("READ" if fcode in [1, 2, 3, 4] else "UNKNOWN"),
            "risk_level": "CRITICAL" if fcode in [15, 16] else ("HIGH" if fcode in [5, 6] else ("LOW" if fcode in [1, 2, 3, 4] else "UNKNOWN"))
        })

        unit_id = req.get('unit_id', mb_data.get('unit_id', 1))

        # Parse request read/write payload details
        payload_meta = {}
        if 'read' in req and isinstance(req['read'], dict):
            read_info = req['read']
            payload_meta = {"operation": "read", "address": read_info.get('address', 0), "quantity": read_info.get('quantity', 1)}
            payload_raw = f"read:addr={read_info.get('address', 0)} qty={read_info.get('quantity', 1)}"
        elif 'write' in req and isinstance(req['write'], dict):
            write_info = req['write']
            val = write_info.get('data', write_info.get('value', ''))
            addr = write_info.get('address', 0)
            payload_meta = {"operation": "write", "address": addr, "value": str(val)}
            payload_raw = f"write:addr={addr} val={val}"
        else:
            payload_raw = mb_data.get('payload_raw', f"FC={fcode}")
            payload_meta = parse_payload_string(payload_raw)

        # Parse response exception details
        exception_code = "None"
        if isinstance(resp, dict) and 'exception' in resp and isinstance(resp['exception'], dict):
            exception_code = str(resp['exception'].get('code', resp['exception'].get('raw', 'None')))
        elif 'exception_code' in mb_data:
            exception_code = str(mb_data['exception_code'])

        is_write = f_info['category'] == 'WRITE'
        has_exc = exception_code not in ['', 'None', '0', 'NoError']

        # Threat scoring calculation based on operation type and exception
        risk_score = 10
        if is_write:
            risk_score += 50
        if f_info['risk_level'] == 'CRITICAL':
            risk_score += 25
        if has_exc:
            risk_score += 15

        action_taken = "monitored_captured"

        parsed_items.append({
            "dt": dt,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "unit_id": unit_id,
            "fcode": fcode,
            "f_info": f_info,
            "payload_raw": payload_raw,
            "payload_meta": payload_meta,
            "exception_code": exception_code,
            "is_write_op": is_write,
            "has_exception": has_exc,
            "risk_score": min(risk_score, 100),
            "action_taken": action_taken,
            "event_type": "SURICATA_MODBUS_DPI"
        })

    audit["unique_modbus_events"] = len(parsed_items)
    if stats is not None:
        stats.update(audit)
    return parsed_items


def normalize_iptables_drops(log_path):
    """
    Parses iptables/pfSense firewall drop syslog entries.
    Explicitly rejects empty-log markers ('-- No entries --') to ensure
    no false drop events are generated from clean/empty log files.
    """
    if not os.path.exists(log_path):
        return []

    parsed_items = []
    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            clean_line = line.strip()
            # Explicitly reject empty log markers, header bars, and non-packet lines
            if not clean_line or "-- No entries --" in clean_line or "No entries" in clean_line:
                continue
            if clean_line.startswith("#") or clean_line.startswith("==") or clean_line.startswith("---"):
                continue
            
            parts = clean_line.split()
            src_ip = None
            dest_ip = None
            dest_port = 502
            
            for part in parts:
                if part.startswith("SRC="):
                    src_ip = part.split("=")[1]
                elif part.startswith("DST="):
                    dest_ip = part.split("=")[1]
                elif part.startswith("DPT="):
                    try:
                        dest_port = int(part.split("=")[1])
                    except ValueError:
                        pass

            # Ignore lines that do not represent valid IP packet drops
            if not src_ip or not dest_ip:
                continue

            dt = datetime.now(timezone.utc)

            parsed_items.append({
                "dt": dt,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "unit_id": 1,
                "fcode": 0,
                "f_info": {"name": "Firewall Boundary Drop", "category": "FIREWALL_DROP", "risk_level": "CRITICAL"},
                "payload_raw": "INBOUND_ACL_DROP",
                "payload_meta": {"status": "BLOCKED"},
                "exception_code": "AccessDenied",
                "is_write_op": False,
                "has_exception": True,
                "risk_score": 90,
                "action_taken": "blocked_dropped",
                "event_type": "FIREWALL_DROP"
            })

    return parsed_items


def main():
    parser = argparse.ArgumentParser(description="Dynamic OT Telemetry Normalization Engine")
    parser.add_argument("-i", "--input", help="Path to handoff .tar.gz archive or extracted directory", default=None)
    parser.add_argument("-o", "--output", help="Path for output normalized JSON file", default=None)
    parser.add_argument("--db", help="SQLite file path or postgresql:// URL (default: $CYB691_DATABASE_URL, else data/telemetry.db)", default=DEFAULT_DB_PATH)
    args = parser.parse_args()

    target_handoff = find_latest_handoff_target(args.input)
    
    if not target_handoff:
        print("[-] No valid telemetry handoff folder or .tar.gz archive found.")
        sys.exit(1)

    print(f"[*] Selected telemetry handoff target: {target_handoff}")
    
    extract_dir = os.path.join(DEFAULT_INFRA_DIR, "extracted_handoff")
    working_dir = extract_tarball_if_needed(target_handoff, extract_dir)

    logs = discover_logs_in_dir(working_dir)
    all_events = []
    
    integrity = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
                 "handoff_target": os.path.relpath(target_handoff, REPO_ROOT)}
    if os.path.isfile(target_handoff):
        integrity["handoff_sha256"] = sha256_of_file(target_handoff)

    if logs["eve_json"]:
        print(f"[*] Ingesting Suricata EVE JSON: {logs['eve_json']}")
        eve_stats = {}
        all_events.extend(normalize_suricata_eve_json(logs["eve_json"], stats=eve_stats))
        integrity["eve_json"] = {"path": os.path.relpath(logs["eve_json"], REPO_ROOT),
                                 "sha256": sha256_of_file(logs["eve_json"]), **eve_stats}
        if eve_stats.get("exact_duplicates_removed"):
            print(f"[!] Removed {eve_stats['exact_duplicates_removed']} exact duplicate Modbus records "
                  f"({eve_stats['modbus_records_seen']} seen -> {eve_stats['unique_modbus_events']} unique). "
                  f"Raw evidence unchanged.")

    if logs["iptables_log"]:
        print(f"[*] Ingesting Firewall Drop log: {logs['iptables_log']}")
        all_events.extend(normalize_iptables_drops(logs["iptables_log"]))

    all_events.sort(key=lambda x: x['dt'])
    
    normalized_records = []
    for idx, item in enumerate(all_events):
        delta_t_ms = 0.0 if idx == 0 else (item['dt'] - all_events[idx-1]['dt']).total_seconds() * 1000.0

        normalized_records.append({
            "event_id": f"MODBUS-EVT-{idx+1:04d}",
            "timestamp_iso": item['dt'].isoformat(),
            "inter_arrival_ms": round(float(delta_t_ms), 2),
            "network": {
                "source_ip": str(item['src_ip']),
                "dest_ip": str(item['dest_ip']),
                "destination_port": int(item['dest_port']),
                "protocol": "Modbus_TCP"
            },
            "modbus": {
                "unit_id": int(item['unit_id']),
                "function_code": int(item['fcode']),
                "function_name": item['f_info']['name'],
                "category": item['f_info']['category'],
                "risk_level": item['f_info']['risk_level'],
                "payload_raw": str(item['payload_raw']),
                "payload_parsed": item['payload_meta'],
                "exception_code": str(item['exception_code'])
            },
            "security": {
                "action_taken": str(item['action_taken']),
                "is_state_altering": item['is_write_op'],
                "has_protocol_exception": item['has_exception'],
                "threat_score": int(item['risk_score'])
            }
        })

    output_path = args.output or os.path.join(DEFAULT_DATA_DIR, "normalized_telemetry.json")
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(normalized_records, f, indent=2)

    integrity["normalized_events_written"] = len(normalized_records)
    integrity_path = os.path.join(os.path.dirname(os.path.abspath(output_path)), "parser_integrity_report.json")
    with open(integrity_path, 'w', encoding='utf-8') as f:
        json.dump(integrity, f, indent=2)
    print(f"[+] Parser integrity report (hashes + de-duplication audit): {integrity_path}")

    print(f"[+] Successfully normalized {len(normalized_records)} combined OT/Firewall events.")
    print(f"[+] Output written to: {output_path}")

    # Export to the database (SQLite file or PostgreSQL URL)
    db_file = args.db or DEFAULT_DB_PATH
    inserted = insert_telemetry_records(normalized_records, db_path=db_file)
    print(f"[+] Synced {inserted} records to {describe_target(db_file)}")


if __name__ == "__main__":
    main()
