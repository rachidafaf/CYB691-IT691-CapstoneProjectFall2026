#!/usr/bin/env python3
"""
===============================================================================
CYB691 / IT691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: OT Testbed Traffic Generator (traffic_generator.py)
Author: Erick Espinosa (Infrastructure, Emulation & Data Generation Lead)
===============================================================================
Purpose
  Generate labelled Modbus/TCP test traffic for IDS / ML evaluation against the
  lab pymodbus PLC (vm-plc, 10.0.3.10:502). Produces the scenario ground-truth
  CSV and the on-the-wire traffic that Suricata and the firewall observe.

Case families
  * C1-C6  source-separable baseline (reads + writes). Authorised when issued
           from the HMI (10.0.1.10), unauthorised from the workstation
           (10.0.1.20). Payloads are byte-identical across sources, so only the
           source IP distinguishes them.
  * A1-A5  content-distinguishable "insider" anomalies, issued FROM the
           authorised HMI, so the source-based firewall allows them and only a
           content-aware layer (Suricata DPI / ML) can catch them. See
           docs/content-anomaly-capture-spec.md.

Design rules (from the Step 7 spec)
  * Labels are DECLARED via --authorized, never derived from source IP. An
    insider anomaly therefore runs with --source-ip 10.0.1.10 --authorized 0.
  * The address / value / anomaly_class columns are recorded for LABELLING and
    VERIFICATION only; the ML must read content features from the observed
    Suricata eve.json (request.write.*), not from this CSV (avoids label leakage).
  * Each action is logged BEFORE it is sent, so firewall-blocked attempts are
    still recorded.

Implementation note
  Raw-socket Modbus/TCP (standard library only) so the generator runs on hosts
  without pymodbus installed. This is the version deployed on vm-hmi / vm-ws;
  keep this repo copy and the deployed copy identical.
===============================================================================
"""

import os
import sys
import csv
import time
import socket
import struct
import argparse
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Scenario CSV logging (extended Step 7 schema). Call BEFORE each request.
# ---------------------------------------------------------------------------
def log_action(csv_path, run_id, topology, case_id, source_ip, dest_ip, function_code,
               authorized, anomaly_class="normal", address="", quantity="", value="",
               inter_arrival_ms=""):
    new_file = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["timestamp_utc", "run_id", "topology", "case_id", "source_ip",
                        "dest_ip", "unit_id", "function_code", "address", "quantity",
                        "value", "inter_arrival_ms", "authorized", "anomaly_class"])
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        w.writerow([ts, run_id, topology, case_id, source_ip, dest_ip, 1, int(function_code),
                    address, quantity, value, inter_arrival_ms, int(bool(authorized)),
                    anomaly_class])
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# Raw Modbus/TCP send (stdlib only). Response is read and discarded; outcome is
# verified separately by read-back (verify_readback.py), not logged here.
# ---------------------------------------------------------------------------
def send_native_modbus(ip, port, unit_id, fc, payload_body):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        pdu = bytes([fc]) + payload_body
        mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit_id)   # transaction, protocol, length, unit
        s.sendall(mbap + pdu)
        s.recv(1024)
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Case table: case_id -> (function_code, pdu_payload, address, quantity,
#                         value_str, default_anomaly_class)
# C3 writes 0xFF00 (coil ON). A1-A5 are "out of range" relative to the
# legitimate HMI profile (HR[0-4] / CO[0-4], values 0-1000), not the protocol.
# ---------------------------------------------------------------------------
CASES = {
    # --- source-separable baseline ---
    "C1": (1,  struct.pack(">HH", 0, 10),                       0,  10, "",             "normal"),
    "C2": (3,  struct.pack(">HH", 0, 10),                       0,  10, "",             "normal"),
    "C3": (5,  struct.pack(">HH", 0, 65280),                    0,  1,  "1",            "normal"),
    "C4": (6,  struct.pack(">HH", 1, 999),                      1,  1,  "999",          "normal"),
    "C5": (15, struct.pack(">HHBB", 2, 3, 1, 5),                2,  3,  "1;0;1",        "normal"),
    "C6": (16, struct.pack(">HHBHHH", 2, 3, 6, 100, 200, 300),  2,  3,  "100;200;300",  "normal"),
    # --- Step 7 content-distinguishable insider anomalies (run with --authorized 0) ---
    "A1": (6,  struct.pack(">HH", 600, 50),                     600, 1, "50",           "oor_address"),
    "A2": (6,  struct.pack(">HH", 2, 65000),                    2,   1, "65000",        "oor_value"),
    "A3": (16, struct.pack(">HHBHHH", 0, 3, 6, 50, 65000, 90),  0,   3, "50;65000;90",  "oor_value"),
    "A5": (6,  struct.pack(">HH", 20, 10),                      20,  1, "10",           "ro_write"),
    # A4 (write burst) is handled specially in main() because it sends many packets.
}


def parse_arguments():
    p = argparse.ArgumentParser(
        description="CYB691 Team 4 - OT Modbus test-traffic generator (baseline C1-C6 + Step 7 anomalies A1-A5)")
    p.add_argument("-t", "--target", default="10.0.3.10", help="PLC IP (default 10.0.3.10)")
    p.add_argument("-p", "--port", type=int, default=502, help="Modbus TCP port (default 502)")
    p.add_argument("--run-id", required=True, help="Unique identifier for this run (e.g. R01, S7)")
    p.add_argument("--topology", required=True, help="Policy phase label (baseline | layered)")
    p.add_argument("--case", required=True,
                   choices=["C1", "C2", "C3", "C4", "C5", "C6", "A1", "A2", "A3", "A4", "A5"],
                   help="Execute a single Modbus case and exit")
    p.add_argument("--authorized", type=int, choices=[0, 1], required=True,
                   help="DECLARED label (1=authorised, 0=unauthorised); NOT derived from source IP")
    p.add_argument("--source-ip", required=True, help="Source IP recorded in the scenario CSV")
    p.add_argument("--scenario_csv", required=True, help="Scenario CSV path (ground truth)")
    p.add_argument("--anomaly-class", default="",
                   help="Overrides the per-case default (e.g. 'unauth_source' for WS baseline runs)")
    p.add_argument("--burst-count", type=int, default=30, help="A4: number of writes in the burst")
    p.add_argument("--burst-interval-ms", type=int, default=20, help="A4: ms between burst writes")
    return p.parse_args()


def main():
    args = parse_arguments()

    # A4: rapid write burst on CO[0] (timing anomaly). Many packets, one per iteration.
    if args.case == "A4":
        acls = args.anomaly_class or "burst"
        for i in range(args.burst_count):
            on = (i % 2 == 0)
            log_action(args.scenario_csv, args.run_id, args.topology, "A4", args.source_ip,
                       args.target, 5, args.authorized, acls, 0, 1, int(on), args.burst_interval_ms)
            send_native_modbus(args.target, args.port, 1, 5,
                               struct.pack(">HH", 0, 0xFF00 if on else 0x0000))
            time.sleep(args.burst_interval_ms / 1000.0)
        return

    # All other cases: one logged action, one request.
    fc, payload, address, quantity, value, default_cls = CASES[args.case]
    acls = args.anomaly_class or default_cls
    log_action(args.scenario_csv, args.run_id, args.topology, args.case, args.source_ip,
               args.target, fc, args.authorized, acls, address, quantity, value)
    send_native_modbus(args.target, args.port, 1, fc, payload)


if __name__ == "__main__":
    main()