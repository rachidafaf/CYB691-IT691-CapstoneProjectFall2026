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
  JSON alerts, iptables firewall drops, and Modbus CSV captures into 
  a standardized ISO 8601 JSON schema with delta timing (dt) and threat scores.
===============================================================================
"""

import os
import sys
import glob
import json
import tarfile
import argparse
import pandas as pd
from datetime import datetime, timezone

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


def find_latest_handoff_target(search_base=None):
    """Finds the latest ot_telemetry_handoff_*.tar.gz archive or uncompressed folder."""
    if search_base and os.path.exists(search_base):
        if os.path.isfile(search_base) or search_base.endswith('.tar.gz'):
            return search_base
        if os.path.isdir(search_base):
            return search_base

    possible_roots = [
        r"C:\Users\rachi\PycharmProjects\CYB691-IT691-CapstoneProjectFall2026\infrastructure",
        "infrastructure",
        "..\\infrastructure",
        "data",
        "/workspace/knowledge",
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
            
            csv_matches = glob.glob(os.path.join(root, "*.csv"))
            found_targets.extend(csv_matches)

    if not found_targets:
        return None

    found_targets.sort(reverse=True)
    return found_targets[0]


def extract_tarball_if_needed(target_path, extract_dir):
    """Extracts .tar.gz archive if target_path is a compressed tarball."""
    if os.path.isfile(target_path) and (target_path.endswith('.tar.gz') or target_path.endswith('.tgz')):
        print(f"[*] Extracting compressed handoff archive: {target_path}")
        os.makedirs(extract_dir, exist_ok=True)
        with tarfile.open(target_path, "r:gz") as tar:
            tar.extractall(path=extract_dir)
        print(f"[+] Archive extracted to: {extract_dir}")
        return extract_dir
    return target_path


def discover_logs_in_dir(target_dir):
    """Recursively locates eve.json, iptables_drops.log, and .csv files in target directory."""
    found_files = {"eve_json": None, "iptables_log": None, "csv_files": []}
    
    if os.path.isfile(target_dir):
        if target_dir.endswith('.json'):
            found_files["eve_json"] = target_dir
        elif target_dir.endswith('.log'):
            found_files["iptables_log"] = target_dir
        elif target_dir.endswith('.csv'):
            found_files["csv_files"].append(target_dir)
        return found_files

    for root, _, files in os.walk(target_dir):
        for f in files:
            full_p = os.path.join(root, f)
            if f == "eve.json":
                found_files["eve_json"] = full_p
            elif f == "iptables_drops.log" or f.endswith("_drops.log"):
                found_files["iptables_log"] = full_p
            elif f.endswith(".csv"):
                found_files["csv_files"].append(full_p)

    return found_files


def normalize_suricata_eve_json(json_path):
    """Parses Suricata EVE JSON events into unified event dictionaries."""
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
    for item in raw_events:
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

        mb_data = item.get('modbus', {})
        alert_data = item.get('alert', {})

        fcode = mb_data.get('function_code', mb_data.get('function', 0))
        if isinstance(fcode, str) and fcode.isdigit():
            fcode = int(fcode)
        elif not isinstance(fcode, int):
            fcode = 0

        f_info = MODBUS_FUNCTION_MAP.get(fcode, {
            "name": mb_data.get('function_name', alert_data.get('signature', 'Modbus DPI Alert')),
            "category": "WRITE" if fcode in [5, 6, 15, 16] else ("READ" if fcode in [1, 2, 3, 4] else "UNKNOWN"),
            "risk_level": "HIGH" if fcode in [5, 6] else ("CRITICAL" if fcode in [15, 16] else "LOW")
        })

        unit_id = mb_data.get('unit_id', mb_data.get('slave_id', 1))
        payload_raw = mb_data.get('payload_raw', f"addr:{mb_data.get('address', 0)} val:{mb_data.get('value', '')}")
        payload_meta = parse_payload_string(payload_raw)
        exception_code = mb_data.get('exception_code', alert_data.get('category', 'None'))

        is_write = f_info['category'] == 'WRITE'
        has_exc = str(exception_code).strip() not in ['', 'None', '0', 'NoError']

        risk_score = 10
        if is_write:
            risk_score += 50
        if f_info['risk_level'] == 'CRITICAL':
            risk_score += 25
        if has_exc or alert_data:
            risk_score += 15

        action_taken = alert_data.get('action', item.get('action_taken', 'monitored_alerted'))

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
            "event_type": "SURICATA_DPI"
        })

    return parsed_items


def normalize_iptables_drops(log_path):
    """Parses iptables/pfSense firewall drop syslog entries."""
    if not os.path.exists(log_path):
        return []

    parsed_items = []
    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            
            parts = line.strip().split()
            src_ip = "10.0.1.4"
            dest_ip = "172.17.0.2"
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


def normalize_modbus_csv(csv_path):
    """Parses raw Modbus CSV captures."""
    if not os.path.exists(csv_path):
        return []

    df = pd.read_csv(csv_path)
    df['dt'] = pd.to_datetime(df['timestamp'])
    
    parsed_items = []
    for idx, row in df.iterrows():
        fcode = int(row['function_code'])
        f_info = MODBUS_FUNCTION_MAP.get(fcode, {
            "name": row.get('function_name', 'Unknown'),
            "category": "UNKNOWN",
            "risk_level": "MEDIUM"
        })
        payload_meta = parse_payload_string(str(row.get('payload', '')))
        is_write = f_info['category'] == 'WRITE'
        has_exc = str(row.get('exception_code', '')).strip() not in ['', 'None', '0', 'NoError']
        
        risk_score = 10
        if is_write:
            risk_score += 50
        if f_info['risk_level'] == 'CRITICAL':
            risk_score += 25
        if has_exc:
            risk_score += 15

        parsed_items.append({
            "dt": row['dt'],
            "src_ip": str(row['source_ip']),
            "dest_ip": str(row['dest_ip']),
            "dest_port": 502,
            "unit_id": int(row['unit_id']),
            "fcode": fcode,
            "f_info": f_info,
            "payload_raw": str(row['payload']),
            "payload_meta": payload_meta,
            "exception_code": str(row['exception_code']),
            "is_write_op": is_write,
            "has_exception": has_exc,
            "risk_score": min(risk_score, 100),
            "action_taken": str(row['action_taken']),
            "event_type": "MODBUS_CSV"
        })

    return parsed_items


def main():
    parser = argparse.ArgumentParser(description="Dynamic OT Telemetry Normalization Engine")
    parser.add_argument("-i", "--input", help="Path to handoff .tar.gz archive or extracted directory", default=None)
    parser.add_argument("-o", "--output", help="Path for output normalized JSON file", default=None)
    args = parser.parse_args()

    target_handoff = find_latest_handoff_target(args.input)
    
    if not target_handoff:
        print("[-] No valid telemetry handoff folder or .tar.gz archive found.")
        sys.exit(1)

    print(f"[*] Selected telemetry handoff target: {target_handoff}")
    
    extract_dir = r"C:\Users\rachi\PycharmProjects\CYB691-IT691-CapstoneProjectFall2026\infrastructure\extracted_handoff"
    working_dir = extract_tarball_if_needed(target_handoff, extract_dir)

    logs = discover_logs_in_dir(working_dir)
    all_events = []
    
    if logs["eve_json"]:
        print(f"[*] Ingesting Suricata EVE JSON: {logs['eve_json']}")
        all_events.extend(normalize_suricata_eve_json(logs["eve_json"]))

    if logs["iptables_log"]:
        print(f"[*] Ingesting Firewall Drop log: {logs['iptables_log']}")
        all_events.extend(normalize_iptables_drops(logs["iptables_log"]))

    for csv_file in logs["csv_files"]:
        print(f"[*] Ingesting raw Modbus CSV: {csv_file}")
        all_events.extend(normalize_modbus_csv(csv_file))

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

    default_out = r"C:\Users\rachi\PycharmProjects\CYB691-IT691-CapstoneProjectFall2026\data\normalized_telemetry.json"
    output_path = args.output or (default_out if os.path.exists(r"C:\Users\rachi\PycharmProjects\CYB691-IT691-CapstoneProjectFall2026") else "data/normalized_telemetry.json")
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(normalized_records, f, indent=2)

    print(f"[+] Successfully normalized {len(normalized_records)} combined OT/Firewall events.")
    print(f"[+] Output written to: {output_path}")


if __name__ == "__main__":
    main()
