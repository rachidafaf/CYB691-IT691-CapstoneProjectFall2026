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
===============================================================================
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone


def generate_incident_metrics(records):
    """Computes summary security metrics from normalized telemetry records."""
    total_events = len(records)
    read_count = sum(1 for r in records if r.get('modbus', {}).get('category') == 'READ')
    write_count = sum(1 for r in records if r.get('modbus', {}).get('category') == 'WRITE')
    exception_count = sum(1 for r in records if r.get('security', {}).get('has_protocol_exception'))
    high_threat_count = sum(1 for r in records if r.get('security', {}).get('threat_score', 0) >= 75)

    unique_sources = list(set(r.get('network', {}).get('source_ip', 'Unknown') for r in records))
    unique_dests = list(set(r.get('network', {}).get('dest_ip', 'Unknown') for r in records))

    time_start = records[0].get('timestamp_iso', 'N/A') if records else "N/A"
    time_end = records[-1].get('timestamp_iso', 'N/A') if records else "N/A"

    return {
        "total_telemetry_events": total_events,
        "time_window": {"start": time_start, "end": time_end},
        "traffic_distribution": {
            "read_operations": read_count,
            "write_operations": write_count,
            "read_to_write_ratio": round(read_count / max(write_count, 1), 2)
        },
        "security_flags": {
            "protocol_exceptions": exception_count,
            "unauthorized_write_attempts": write_count,
            "high_threat_events": high_threat_count
        },
        "participating_hosts": {
            "source_ips": unique_sources,
            "destination_ips": unique_dests
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
    md.append(
        f"the normalization pipeline analyzed **{metrics['total_telemetry_events']} Modbus TCP telemetry frames** ")
    md.append(f"between `{metrics['time_window']['start']}` and `{metrics['time_window']['end']}`.")
    md.append(
        f"The analysis isolated **{metrics['security_flags']['unauthorized_write_attempts']} unauthorized state-altering write command attempts** ")
    md.append(
        f"and **{metrics['security_flags']['protocol_exceptions']} protocol exception alerts** originating from workstation `10.0.1.4` ")
    md.append("targeting Industrial PLC `172.17.0.2` (Port 502).\n")

    md.append("### Key Metrics Breakdown")
    md.append(f"- **Total Telemetry Ingested:** {metrics['total_telemetry_events']} records")
    md.append(
        f"- **Read Commands (Polling):** {metrics['traffic_distribution']['read_operations']} ({metrics['traffic_distribution']['read_to_write_ratio']} Read/Write Ratio)")
    md.append(f"- **State-Altering Write Commands:** {metrics['traffic_distribution']['write_operations']}")
    md.append(f"- **Illegal Data Address Exceptions:** {metrics['security_flags']['protocol_exceptions']}")
    md.append(f"- **High-Threat Incident Alerts (Score >= 75):** {metrics['security_flags']['high_threat_events']}\n")

    md.append("---")
    md.append("## Chronological Incident Event Timeline\n")

    md.append(
        "| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

    for r in records:
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

        md.append(f"| {evt_id} | {ts} | {src} | {dst} | {fn_str} | {cat} | {risk} | **{score}** | {payload} |")

    md.append("\n---")
    md.append("## Defensive Triage Recommendations & Security Controls")
    md.append(
        "1. **Enforce Purdue Model Microsegmentation (pfSense):** Restrict Modbus Port 502 ingress traffic targeting PLC `172.17.0.2` strictly to authorized HMI subnets. Drop non-whitelisted workstation traffic (`10.0.1.4`).")
    md.append(
        "2. **Deploy Stateful Deep Packet Inspection (Suricata/Zeek):** Enforce signature rules that block Modbus Function Codes `0x05` (Write Single Coil), `0x06` (Write Single Register), and `0x10` (Write Multiple Registers) originating outside authorized engineering workstations.")
    md.append(
        "3. **Automate SIEM/Triage Alerting:** Ingest standardized JSON event frames into downstream ML anomaly models (Bhavesh Dalal) to detect anomalous inter-arrival command bursts.")

    os.makedirs(os.path.dirname(os.path.abspath(output_md_path)), exist_ok=True)
    with open(output_md_path, 'w') as f:
        f.write("\n".join(md))

    print(f"[+] Successfully generated Incident Timeline Markdown report: {output_md_path}")


def resolve_input_path(custom_path=None):
    """Resolves normalized JSON input file path across environments."""
    if custom_path and os.path.exists(custom_path):
        return custom_path

    possible_paths = [
        r"C:\Users\rachi\PycharmProjects\CYB691-IT691-CapstoneProjectFall2026\data\normalized_telemetry.json",
        os.path.join("data", "normalized_telemetry.json"),
        os.path.join("..", "data", "normalized_telemetry.json"),
        "normalized_telemetry.json",
        "/workspace/scratch/normalized_telemetry.json",
        "/workspace/artifacts/normalized_telemetry.json"
    ]

    for p in possible_paths:
        if os.path.exists(p):
            return p

    return possible_paths[0]


def main():
    parser = argparse.ArgumentParser(description="OT Telemetry Incident Triage & Timeline Generator")
    parser.add_argument("-i", "--input", help="Path to normalized_telemetry.json", default=None)
    parser.add_argument("-o", "--output-json", help="Path for incident_report.json output", default=None)
    parser.add_argument("-m", "--output-md", help="Path for incident_timeline.md output", default=None)
    args = parser.parse_args()

    json_input = resolve_input_path(args.input)

    # Determine default output paths based on resolved input location
    if args.output_json:
        report_json_output = args.output_json
    else:
        input_dir = os.path.dirname(json_input)
        report_json_output = os.path.join(input_dir, "incident_report.json") if input_dir else "incident_report.json"

    if args.output_md:
        timeline_md_output = args.output_md
    else:
        input_dir = os.path.dirname(json_input)
        timeline_md_output = os.path.join(input_dir, "incident_timeline.md") if input_dir else "incident_timeline.md"

    if not os.path.exists(json_input):
        print(f"[-] Input file missing: {json_input}")
        print("[-] Please run log_parser.py first to generate normalized_telemetry.json!")
        sys.exit(1)

    print(f"[*] Ingesting normalized telemetry from: {json_input}")
    with open(json_input, 'r') as f:
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
    with open(report_json_output, 'w') as f:
        json.dump(incident_report, f, indent=2)
    print(f"[+] Written structured incident report JSON: {report_json_output}")

    synthesize_markdown_timeline(metrics, records, timeline_md_output)


if __name__ == "__main__":
    main()
