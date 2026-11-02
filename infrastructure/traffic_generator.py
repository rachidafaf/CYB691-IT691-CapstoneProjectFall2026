#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: OT Testbed Traffic Generator & Attack Simulator (traffic_generator.py)
Author: Erick Espinosa (Infrastructure, Emulation & Data Generation Lead)
===============================================================================
Description:
  Automates the generation of industrial Modbus TCP network traffic against 
  virtualized PLC emulators. Appends experiment transactions directly to 
  scenario_file.csv with exact required telemetry columns.
===============================================================================
"""

import os
import sys
import time
import socket
import argparse
import csv
from datetime import datetime, timezone

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[-] Error: 'pymodbus' library is not installed.")
    print("[-] Please run: pip install pymodbus")
    sys.exit(1)

# Case ID Mapping (README Section 5)
# C1 = FC1 (Read Coils)
# C2 = FC3 (Read Holding Registers)
# C3 = FC5 (Write Single Coil)
# C4 = FC6 (Write Single Register)
# C5 = FC15 (Write Multiple Coils)
# C6 = FC16 (Write Multiple Registers)
CASES = {
    "C1": (1, "read_coils"),
    "C2": (3, "read_holding_registers"),
    "C3": (5, "write_coil"),
    "C4": (6, "write_register"),
    "C5": (15, "write_coils"),
    "C6": (16, "write_registers")
}

def get_local_ip():
    """Helper to retrieve local machine IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.0.3.10", 502))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def log_to_csv(run_id, topology, case_id, source_ip, dest_ip, function_code, authorized):
    """Appends action record to scenario_file.csv immediately upon sending."""
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    row = [timestamp_utc, run_id, topology, case_id, source_ip, dest_ip, function_code, authorized]
    
    file_exists = os.path.isfile("scenario_file.csv")
    with open("scenario_file.csv", mode="a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp_utc", "run_id", "topology", "case_id", "source_ip", "dest_ip", "function_code", "authorized"])
        writer.writerow(row)

def execute_transaction(client, target_ip, run_id, topology, case_id, authorized):
    if case_id not in CASES:
        print(f"[-] Invalid case_id: {case_id}. Choose from C1-C6.")
        return False
        
    fc, method_name = CASES[case_id]
    source_ip = get_local_ip()
    success = False
    
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"[*] [{timestamp}] Executing {case_id} (FC {fc}) from {source_ip} to {target_ip}...")

    try:
        if fc == 1:
            res = client.read_coils(address=0, count=1)
        elif fc == 3:
            res = client.read_holding_registers(address=0, count=10)
        elif fc == 5:
            res = client.write_coil(address=0, value=True)
        elif fc == 6:
            res = client.write_register(address=1, value=999)
        elif fc == 15:
            res = client.write_coils(address=0, values=[True, False])
        elif fc == 16:
            res = client.write_registers(address=2, values=[100, 200])
        else:
            res = None

        if res and not res.isError():
            print(f"    [+] {case_id} succeeded.")
            success = True
        else:
            print(f"    [!] {case_id} error response: {res}")
            # Still logs the attempt as per security testbed requirements
            success = True 
    except Exception as e:
        print(f"    [!] Exception during {case_id}: {e}")

    # Log immediately after sending action
    log_to_csv(run_id, topology, case_id, source_ip, target_ip, fc, authorized)
    return success

def parse_arguments():
    parser = argparse.ArgumentParser(description="OT Testbed Traffic Generator with CSV Logging")
    parser.add_argument("-t", "--target", default="10.0.3.10", help="Target PLC IP (default: 10.0.3.10)")
    parser.add_argument("-p", "--port", type=int, default=502, help="Modbus port (default: 502)")
    parser.add_argument("--run-id", default="R01", help="Run identifier (e.g., R01)")
    parser.add_argument("--topology", choices=["baseline", "layered"], required=True, help="Network policy topology")
    parser.add_argument("--case-id", choices=list(CASES.keys()), required=True, help="Test case ID (C1-C6)")
    parser.add_argument("--authorized", type=int, choices=[0, 1], required=True, help="Authorization flag (1=Authorized HMI, 0=Unauthorized)")
    parser.add_argument("--repetitions", type=int, default=1, help="Number of repetitions for this case")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between repetitions")
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    client = ModbusTcpClient(args.target, port=args.port)
    if not client.connect():
        print(f"[-] Connection failed to {args.target}:{args.port}")
        sys.exit(1)

    try:
        for i in range(args.repetitions):
            execute_transaction(client, args.target, args.run_id, args.topology, args.case_id, args.authorized)
            if i < args.repetitions - 1:
                time.sleep(args.delay)
    finally:
        client.close()

if __name__ == "__main__":
    main()
