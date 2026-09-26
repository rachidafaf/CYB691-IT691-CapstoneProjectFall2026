#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: Telemetry Normalization & Ingestion Engine (log_parser.py)
Author: Rachid Afaf (Security Architect / Lead Analyst)
===============================================================================
Description:
  Ingests raw Modbus TCP packet captures, normalizes protocol fields into a
  standardized ISO 8601 JSON schema, calculates inter-arrival delta times,
  and computes security threat scores.
===============================================================================
"""

import os
import sys
import json
import argparse
import pandas as pd

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


def normalize_modbus_csv(csv_path):
    """Ingests raw Modbus CSV telemetry and calculates inter-arrival times and threat scores."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Source CSV file not found at: {csv_path}")

    df = pd.read_csv(csv_path)
    df['dt'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by='dt').reset_index(drop=True)

    # Calculate inter-arrival time (delta_t in milliseconds)
    df['delta_t_ms'] = df['dt'].diff().dt.total_seconds() * 1000.0
    df['delta_t_ms'] = df['delta_t_ms'].fillna(0.0)

    normalized_records = []

    for idx, row in df.iterrows():
        fcode = int(row['function_code'])
        f_info = MODBUS_FUNCTION_MAP.get(fcode, {
            "name": row.get('function_name', 'Unknown'),
            "category": "UNKNOWN",
            "risk_level": "MEDIUM"
        })

        payload_meta = parse_payload_string(str(row.get('payload', '')))
        is_write_op = f_info['category'] == 'WRITE'
        has_exception = str(row.get('exception_code', '')).strip() not in ['', 'None', '0', 'NoError']

        # Calculate Threat Score (0-100)
        risk_score = 10
        if is_write_op:
            risk_score += 50
        if f_info['risk_level'] == 'CRITICAL':
            risk_score += 25
        if has_exception:
            risk_score += 15

        record = {
            "event_id": f"MODBUS-EVT-{idx + 1:04d}",
            "timestamp_iso": row['dt'].isoformat(),
            "inter_arrival_ms": round(float(row['delta_t_ms']), 2),
            "network": {
                "source_ip": str(row['source_ip']),
                "dest_ip": str(row['dest_ip']),
                "destination_port": 502,
                "protocol": "Modbus_TCP"
            },
            "modbus": {
                "unit_id": int(row['unit_id']),
                "function_code": fcode,
                "function_name": f_info['name'],
                "category": f_info['category'],
                "risk_level": f_info['risk_level'],
                "payload_raw": str(row['payload']),
                "payload_parsed": payload_meta,
                "exception_code": str(row['exception_code'])
            },
            "security": {
                "action_taken": str(row['action_taken']),
                "is_state_altering": is_write_op,
                "has_protocol_exception": has_exception,
                "threat_score": min(risk_score, 100)
            }
        }
        normalized_records.append(record)

    return normalized_records


def resolve_input_path(custom_path=None):
    """Resolves the input dataset path using CLI args, PyCharm Windows paths, or local fallbacks."""
    if custom_path:
        return custom_path

    # Candidate paths ordered by priority
    candidates = [
        r"C:\Users\rachi\PycharmProjects\CYB691-IT691-CapstoneProjectFall2026\data\modbus_telemetry_dataset.csv",
        os.path.join("data", "modbus_telemetry_dataset.csv"),
        os.path.join("..", "data", "modbus_telemetry_dataset.csv"),
        "/workspace/knowledge/modbus_telemetry_dataset.csv",
        "modbus_telemetry_dataset.csv"
    ]

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    return candidates[0]


def resolve_output_path(custom_path=None, input_path=None):
    """Resolves the output JSON destination path."""
    if custom_path:
        return custom_path

    if input_path and os.path.isabs(input_path) and "PycharmProjects" in input_path:
        base_dir = os.path.dirname(input_path)
        return os.path.join(base_dir, "normalized_telemetry.json")

    if os.path.exists("data"):
        return os.path.join("data", "normalized_telemetry.json")

    return "/workspace/scratch/normalized_telemetry.json"


def main():
    parser = argparse.ArgumentParser(description="Modbus Telemetry Normalization Engine")
    parser.add_argument("--input", "-i", help="Path to input CSV telemetry file", default=None)
    parser.add_argument("--output", "-o", help="Path to output normalized JSON file", default=None)
    args = parser.parse_args()

    input_file = resolve_input_path(args.input)
    output_file = resolve_output_path(args.output, input_file)

    print(f"[*] Ingesting raw OT telemetry from: {input_file}")
    records = normalize_modbus_csv(input_file)

    out_dir = os.path.dirname(output_file)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2)

    print(f"[+] Successfully normalized {len(records)} Modbus events.")
    print(f"[+] Output written to: {output_file}")


if __name__ == "__main__":
    main()
