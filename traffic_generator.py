#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: OT Testbed Traffic Generator & Attack Simulator (traffic_generator.py)
Author: Erick Espinosa (Infrastructure, Emulation & Data Generation Lead)
===============================================================================
Description:
  Automates the generation of industrial Modbus TCP network traffic against 
  virtualized PLC emulators (OpenPLC / Conpot). Executes routine HMI polling 
  (Read Holding Registers) and unauthorized command injections (Write Single 
  Coil / Register) to generate test artifacts and trigger Suricata/pfSense logs.

  Enhancements added for the evaluation pipeline:
    * CSV scenario logging (log_action helper)
    * Additional CLI metadata arguments required by Step 7/8
    * Dispatch of individual Modbus cases (C1‑C6) via ``--case``
    * Support for Read Coils (FC 1) and Write Multiple Coils (FC 15)
    * Logging performed *before* each request so blocked attempts are recorded
    * Short connection timeout to fail fast on dropped connections
===============================================================================
"""

import os
import sys
import time
import argparse
import csv
from datetime import datetime, timezone

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[-] Error: 'pymodbus' library is not installed.")
    print("[-] Please run: pip install pymodbus")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helper: CSV logging (creates header if file does not exist)
# ---------------------------------------------------------------------------

def log_action(csv_path, run_id, topology, case_id,
               source_ip, dest_ip, function_code, authorized):
    """Append one scenario row. Call immediately BEFORE the request is sent.
    Matches the exact Step 7 header.
    """
    new_file = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["timestamp_utc", "run_id", "topology", "case_id",
                       "source_ip", "dest_ip", "function_code", "authorized"])
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        w.writerow([ts, run_id, topology, case_id, source_ip, dest_ip,
                    int(function_code), int(bool(authorized))])
        f.flush()
        os.fsync(f.fileno())

# ---------------------------------------------------------------------------
# Individual Modbus case implementations – each logs **before** sending.
# ---------------------------------------------------------------------------

def case_read_coils(client, args):
    address, count = 0, 10
    # Log before sending request with exact Step 7 columns
    log_action(args.scenario_csv, args.run_id, args.topology, "C1",
               args.source_ip, args.target, 1, args.authorized)
    try:
        result = client.read_coils(address, count=count)
        # No further logging – outcome not recorded per spec
    except Exception:
        pass



def case_read_holding_registers(client, args):
    address, count = 0, 10
    # Log before sending request with Step 7 columns
    log_action(args.scenario_csv, args.run_id, args.topology, "C2",
               args.source_ip, args.target, 3, args.authorized)
    try:
        client.read_holding_registers(address=address, count=count)
    except Exception:
        pass



def case_write_single_coil(client, args):
    address, value = 0, True
    # Log before sending request
    log_action(args.scenario_csv, args.run_id, args.topology, "C3",
               args.source_ip, args.target, 5, args.authorized)
    try:
        client.write_coil(address=address, value=value)
    except Exception:
        pass



def case_write_single_register(client, args):
    address, value = 1, 999
    # Log before sending request
    log_action(args.scenario_csv, args.run_id, args.topology, "C4",
               args.source_ip, args.target, 6, args.authorized)
    try:
        client.write_register(address=address, value=value)
    except Exception:
        pass



def case_write_multiple_coils(client, args):
    address, values = 2, [True, False, True]
    # Log before sending request
    log_action(args.scenario_csv, args.run_id, args.topology, "C5",
               args.source_ip, args.target, 15, args.authorized)
    try:
        client.write_coils(address=address, values=values)
    except Exception:
        pass



def case_write_multiple_registers(client, args):
    address, values = 2, [100, 200, 300]
    # Log before sending request
    log_action(args.scenario_csv, args.run_id, args.topology, "C6",
               args.source_ip, args.target, 16, args.authorized)
    try:
        client.write_registers(address=address, values=values)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Argument parsing – includes new metadata flags.
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="OT Testbed Automated Traffic Generator & Attack Simulator (pymodbus)"
    )
    # Existing options
    parser.add_argument("-t", "--target", default="127.0.0.1",
                        help="Target IP address of the PLC emulator (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus TCP port (default: 502)")
    parser.add_argument("-c", "--count", type=int, default=5,
                        help="Number of baseline polling iterations (default: 5)")
    parser.add_argument("-d", "--delay", type=float, default=1.0,
                        help="Delay in seconds between polls (default: 1.0)")
    parser.add_argument("--attack-only", action="store_true",
                        help="Execute only unauthorized write command injections")
    parser.add_argument("--baseline-only", action="store_true",
                        help="Execute only baseline HMI read polling")
    # New metadata options required by the evaluation harness
    parser.add_argument("--run-id", required=True, help="Unique identifier for this run")
    parser.add_argument("--topology", required=True, help="Topology name (e.g., vm-hmi, vm-ws)")
    parser.add_argument("--case", choices=["C1", "C2", "C3", "C4", "C5", "C6"],
                        help="Execute a single Modbus case and exit")
    parser.add_argument("--authorized", type=int, choices=[0, 1], required=True,
                        help="Authorization flag set by host (1=authorized, 0=unauthorized)")
    parser.add_argument("--source-ip", required=True, help="Source IP address of the request")
    parser.add_argument("--scenario-csv", required=True,
                        help="Path to CSV file where each request is logged")
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Main execution flow
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    print("======================================================================")
    print(" CYB691 Capstone Team 4 — OT Traffic & Attack Simulation Engine       ")
    print(f" Target: {args.target}:{args.port}                                    ")
    print("======================================================================\n")

    print(f"[*] Connecting to Modbus TCP target at {args.target}:{args.port}...")
    # Short timeout to fail fast when the connection is blocked by policy
    client = ModbusTcpClient(args.target, port=args.port, timeout=3)

    if not client.connect():
        print(f"[-] Connection failed to {args.target}:{args.port}.")
        # Log the failed connection attempt for the selected case (if any)
        if args.case:
            # Use function_code 0 to indicate a non‑Modbus connection failure
            log_action(args.scenario_csv, args.run_id, args.topology, args.case,
                       args.source_ip, args.target, 0, args.authorized)
        sys.exit(1)

    print("[+] Connection established successfully.\n")

    try:
        # If a specific case is requested, run only that case and exit.
        if args.case:
            case_map = {
                "C1": case_read_coils,
                "C2": case_read_holding_registers,
                "C3": case_write_single_coil,
                "C4": case_write_single_register,
                "C5": case_write_multiple_coils,
                "C6": case_write_multiple_registers,
            }
            func = case_map.get(args.case)
            if func:
                func(client, args)
            else:
                print(f"[!] Unknown case: {args.case}")
            return

        # Default behaviour – baseline polling followed by attack simulation
        if not args.attack_only:
            send_baseline_polls(client, count=args.count, delay=args.delay)
        if not args.baseline_only:
            inject_unauthorized_commands(client)
    finally:
        client.close()
        print("[*] Modbus TCP connection closed. Execution finished.")

# ---------------------------------------------------------------------------
# Original baseline and attack helpers (unchanged, they still print to console)
# ---------------------------------------------------------------------------

def send_baseline_polls(client, count=5, delay=1.0):
    """Executes legitimate HMI routine read polling (Function Code 0x03)."""
    print(f"[*] Starting Baseline HMI Polling (FC 0x03) - {count} iterations...")
    success_count = 0
    for i in range(1, count + 1):
        try:
            result = client.read_holding_registers(address=0, count=10)
            timestamp = datetime.now(timezone.utc).isoformat()
            if result and not result.isError():
                print(f"  [+] [{timestamp}] Poll {i}/{count} Success: Registers -> {result.registers}")
                success_count += 1
            else:
                print(f"  [!] [{timestamp}] Poll {i}/{count} Error response: {result}")
        except Exception as e:
            print(f"  [!] Exception during poll {i}: {e}")
        time.sleep(delay)
    print(f"[+] Baseline Polling completed: {success_count}/{count} successful reads.\n")


def inject_unauthorized_commands(client):
    """Executes unauthorized state‑altering write command injections (FC 0x05, 0x06, 0x10)."""
    print("[!] INITIATING ATTACK SIMULATION: Unauthorized Modbus Command Injections...")
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        # 1. Write Single Coil (FC 0x05)
        print(f"  [>] [{timestamp}] Injecting FC 0x05 (Write Single Coil) at Address 0 (Value: True)...")
        res_coil = client.write_coil(address=0, value=True)
        if res_coil and not res_coil.isError():
            print("      [+] FC 0x05 executed successfully on target emulator.")
        else:
            print(f"      [!] FC 0x05 response: {res_coil}")
        time.sleep(0.5)
        # 2. Write Single Register (FC 0x06)
        print(f"  [>] [{timestamp}] Injecting FC 0x06 (Write Single Register) at Address 1 (Value: 999)...")
        res_reg = client.write_register(address=1, value=999)
        if res_reg and not res_reg.isError():
            print("      [+] FC 0x06 executed successfully on target emulator.")
        else:
            print(f"      [!] FC 0x06 response: {res_reg}")
        time.sleep(0.5)
        # 3. Write Multiple Registers (FC 0x10)
        print(f"  [>] [{timestamp}] Injecting FC 0x10 (Write Multiple Registers) starting at Address 2...")
        res_multi = client.write_registers(address=2, values=[100, 200, 300])
        if res_multi and not res_multi.isError():
            print("      [+] FC 0x10 executed successfully on target emulator.")
        else:
            print(f"      [!] FC 0x10 response: {res_multi}")
    except Exception as e:
        print(f"  [!] Exception during attack command injection: {e}")
    print("[!] Attack simulation sequence completed.\n")

if __name__ == "__main__":
    main()
