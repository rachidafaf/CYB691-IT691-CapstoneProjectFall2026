#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: Incident Triage & Timeline Generator (timeline_generator.py)
Author: Rachid Afaf (Security Architect / Lead Analyst)
===============================================================================
Description:
  Ingests normalized OT telemetry JSON frames, computes security metrics, 
  and generates a structured JSON report and Markdown Incident Timeline.
  Paths resolve dynamically relative to the repository root for portability.
===============================================================================
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone

try:
    from src.database import save_incident_metrics_to_db, describe_target, DEFAULT_DB_PATH
except ImportError:
    from database import save_incident_metrics_to_db, describe_target, DEFAULT_DB_PATH

# Dynamic repository path resolution
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(REPO_ROOT, "data")


def _utc(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _is_fw(r):
    return r.get('modbus', {}).get('category') == 'FIREWALL_DROP'


def generate_incident_metrics(records):
    """Computes summary security metrics from normalized telemetry records.
    Firewall drops are counted on their own, never as Modbus frames or protocol exceptions."""
    modbus = [r for r in records if not _is_fw(r)]
    drops = [r for r in records if _is_fw(r)]
    read_count = sum(1 for r in modbus if r.get('modbus', {}).get('category') == 'READ')
    writes = [r for r in modbus if r.get('modbus', {}).get('category') == 'WRITE']
    exception_count = sum(1 for r in modbus if r.get('security', {}).get('has_protocol_exception'))
    high_threat_count = sum(1 for r in records if r.get('security', {}).get('threat_score', 0) >= 75)

    unique_sources = sorted(set(r.get('network', {}).get('source_ip', 'Unknown') for r in records))
    unique_dests = sorted(set(r.get('network', {}).get('dest_ip', 'Unknown') for r in records))
    times = [t for t in (_utc(r.get('timestamp_iso')) for r in records) if t]

    return {
        "total_telemetry_events": len(records),
        "modbus_frames": len(modbus),
        "firewall_drops": len(drops),
        "time_window": {"start": min(times).isoformat() if times else "N/A",
                        "end": max(times).isoformat() if times else "N/A"},
        "traffic_distribution": {
            "read_operations": read_count,
            "write_operations": len(writes),
            "read_to_write_ratio": round(read_count / max(len(writes), 1), 2)
        },
        "security_flags": {
            "protocol_exceptions": exception_count,
            "unauthorized_write_attempts": len(writes),
            "firewall_drops": len(drops),
            "high_threat_events": high_threat_count
        },
        "participating_hosts": {
            "source_ips": unique_sources,
            "destination_ips": unique_dests,
            "write_sources": sorted(set(r.get('network', {}).get('source_ip', 'Unknown') for r in writes)),
            "write_targets": sorted(set(r.get('network', {}).get('dest_ip', 'Unknown') for r in writes)),
            "blocked_sources": sorted(set(r.get('network', {}).get('source_ip', 'Unknown') for r in drops)),
        }
    }


def synthesize_markdown_timeline(metrics, records, output_md_path):
    """Generates an executive Markdown Incident Timeline report for security analysts."""
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    md = []
    md.append("# OT Cyber-Physical Incident Triage & Timeline Report")
    md.append("**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)")
    md.append(f"**Generated Date:** {now_str}")
    md.append("**Lead Security Architect:** Rachid Afaf\n")
    md.append("---")
    
    md.append("## Executive Incident Summary")
    md.append("During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, ")
    hosts = metrics['participating_hosts']
    fmt = lambda ips: ", ".join(f"`{ip}`" for ip in ips) or "none"
    md.append(f"the normalization pipeline analyzed **{metrics['modbus_frames']} Modbus TCP telemetry frames** "
              f"and **{metrics['firewall_drops']} firewall drop records** ")
    md.append(f"between `{metrics['time_window']['start']}` and `{metrics['time_window']['end']}` (UTC).")
    md.append(f"The analysis isolated **{metrics['security_flags']['unauthorized_write_attempts']} state-altering write command attempts** "
              f"from {fmt(hosts['write_sources'])} targeting {fmt(hosts['write_targets'])} (port 502), ")
    md.append(f"**{metrics['security_flags']['protocol_exceptions']} protocol exception responses**, and "
              f"**{metrics['firewall_drops']} firewall drops** of traffic from {fmt(hosts['blocked_sources'])}.\n")

    md.append("### Key Metrics Breakdown")
    md.append(f"- **Total Telemetry Ingested:** {metrics['total_telemetry_events']} records")
    md.append(f"- **Read Commands (Polling):** {metrics['traffic_distribution']['read_operations']} ({metrics['traffic_distribution']['read_to_write_ratio']} Read/Write Ratio)")
    md.append(f"- **State-Altering Write Commands:** {metrics['traffic_distribution']['write_operations']}")
    md.append(f"- **Modbus Protocol Exceptions:** {metrics['security_flags']['protocol_exceptions']}")
    md.append(f"- **Firewall Drops:** {metrics['firewall_drops']}")
    md.append(f"- **High-Threat Incident Alerts (Score >= 75):** {metrics['security_flags']['high_threat_events']}\n")

    md.append("---")
    md.append("## Chronological Incident Event Timeline\n")
    
    md.append("| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

    ordered = sorted(records, key=lambda r: _utc(r.get('timestamp_iso')) or datetime.max.replace(tzinfo=timezone.utc))
    for r in ordered:
        evt_id = r.get('event_id', 'N/A')
        ts = str(r.get('timestamp_iso', '')).replace("T", " ")
        src = r.get('network', {}).get('source_ip', 'N/A')
        dst = r.get('network', {}).get('dest_ip', 'N/A')
        fn_code = r.get('modbus', {}).get('function_code', 0)
        fn_name = r.get('modbus', {}).get('function_name', 'Unknown')
        fn_str = f"0x{fn_code:02X} ({fn_name})"
        cat = r.get('modbus', {}).get('category', 'N/A')
        risk = r.get('modbus', {}).get('risk_level', 'N/A')
        score = r.get('security', {}).get('threat_score', 0)
        payload_raw = r.get('modbus', {}).get('payload_raw', '')
        exc = r.get('modbus', {}).get('exception_code', '')
        payload = f"`{payload_raw}` [{exc}]"

        md.append(f"| {evt_id} | {ts} | `{src}` | `{dst}` | {fn_str} | **{cat}** | {risk} | **{score}** | {payload} |")

    md.append("\n---\n")
    md.append("## Defensive Recommendations & Containment Actions")
    md.append(f"1. **Inbound ACL Enforcement:** Restrict port 502 to authorized engineering workstations only; review write traffic from {fmt(hosts['write_sources'])}.")
    md.append("2. **Suricata DPI Rule Tuning:** Enforce Modbus rule SID 1000004 to drop state-altering function codes (`FC05`, `FC06`, `FC15`, `FC16`) originating outside the Control Zone.")
    md.append("3. **Machine Learning Anomaly Quarantine:** Ingest high-threat events into `ml_detector.py` to trigger automated microsegmentation isolation.")

    os.makedirs(os.path.dirname(os.path.abspath(output_md_path)), exist_ok=True)
    with open(output_md_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md))

    print(f"[+] Successfully generated Incident Timeline Markdown report: {output_md_path}")


def resolve_input_path(custom_path=None):
    """Resolves normalized JSON input file path dynamically across environments."""
    if custom_path and os.path.exists(custom_path):
        return custom_path

    possible_paths = [
        os.path.join(DEFAULT_DATA_DIR, "normalized_telemetry.json"),
        os.path.join("data", "normalized_telemetry.json"),
        os.path.join("..", "data", "normalized_telemetry.json"),
        "normalized_telemetry.json"
    ]

    for p in possible_paths:
        if os.path.exists(p):
            return p

    return os.path.join(DEFAULT_DATA_DIR, "normalized_telemetry.json")


def main():
    parser = argparse.ArgumentParser(description="OT Telemetry Incident Triage & Timeline Generator")
    parser.add_argument("-i", "--input", help="Path to normalized_telemetry.json", default=None)
    parser.add_argument("-o", "--output-json", help="Path for incident_report.json output", default=None)
    parser.add_argument("-m", "--output-md", help="Path for incident_timeline.md output", default=None)
    args = parser.parse_args()

    json_input = resolve_input_path(args.input)
    report_json_output = args.output_json or os.path.join(DEFAULT_DATA_DIR, "incident_report.json")
    timeline_md_output = args.output_md or os.path.join(DEFAULT_DATA_DIR, "incident_timeline.md")

    if not os.path.exists(json_input):
        print(f"[-] Input file missing: {json_input}")
        print("[-] Please run log_parser.py first to generate normalized_telemetry.json!")
        sys.exit(1)

    print(f"[*] Ingesting normalized telemetry from: {json_input}")
    with open(json_input, 'r', encoding='utf-8') as f:
        records = json.load(f)

    print(f"[*] Processing {len(records)} normalized records for incident correlation...")
    metrics = generate_incident_metrics(records)

    incident_report = {
        "report_metadata": {
            "title": "OT Cyber-Physical Incident Triage Report",
            "author": "Rachid Afaf (Security Architect)",
            "course": "CYB691 Capstone Team 4",
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "metrics": metrics,
        "correlated_events": records
    }

    os.makedirs(os.path.dirname(os.path.abspath(report_json_output)), exist_ok=True)
    with open(report_json_output, 'w', encoding='utf-8') as f:
        json.dump(incident_report, f, indent=2)
    print(f"[+] Written structured incident report JSON: {report_json_output}")

    # Archive metrics to the database (SQLite file or PostgreSQL URL)
    try:
        rep_id = save_incident_metrics_to_db(metrics)
        print(f"[+] Saved incident triage metrics to {describe_target()} (Report: {rep_id})")
    except Exception as e:
        print(f"[-] Warning: Could not save incident metrics to {describe_target()}: {e}")

    synthesize_markdown_timeline(metrics, records, timeline_md_output)


if __name__ == "__main__":
    main()
