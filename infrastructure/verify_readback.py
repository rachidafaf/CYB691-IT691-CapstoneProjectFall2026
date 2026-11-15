#!/usr/bin/env python3
"""
verify_readback.py  --  Step 9: confirm authorized writes changed PLC state.

READ-ONLY and DEPENDENCY-FREE. Uses raw Modbus/TCP sockets (stdlib only, like
traffic_generator.py), so it runs on stock python3 on vm-hmi with no pymodbus
install. It issues only FC1 (ReadCoils) and FC3 (ReadHoldingRegisters) reads and
never writes to the PLC. The writes under test remain traffic_generator.py's
existing authorized HMI path; this tool only proves their effect.

Target map is decoded from traffic_generator.py's case_payloads:

    C3  FC5  WriteSingleCoil        coil  0        -> ON            read FC1 @0  x1
    C4  FC6  WriteSingleRegister    reg   1        -> 999           read FC3 @1  x1
    C5  FC15 WriteMultipleCoils     coils 2,3,4    -> 1,0,1 (0x05)  read FC1 @2  x3
    C6  FC16 WriteMultipleRegisters regs  2,3,4    -> 100,200,300   read FC3 @2  x3

Workflow (run on vm-hmi, 10.0.1.10, so the layered firewall permits HMI->PLC:502;
restart run_server.py on the PLC first so the baseline is a fresh datastore):

    python3 verify_readback.py snapshot --plc 10.0.3.10 --out pre.json
    # ... run the 4 authorized writes (C3,C4,C5,C6) via traffic_generator.py ...
    python3 verify_readback.py snapshot --plc 10.0.3.10 --out post.json
    python3 verify_readback.py verify --pre pre.json --post post.json \
            --out readback_verification.json

Package readback_verification.json (and pre/post.json) into the handoff so the
command -> enforcement -> effect loop travels with the capture.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys

# case -> read-back target + expected value (decoded from traffic_generator.py)
CASE_TARGETS = {
    "C3": {"write_fc": 5,  "kind": "coils",     "address": 0, "count": 1, "expected": [True]},
    "C4": {"write_fc": 6,  "kind": "registers", "address": 1, "count": 1, "expected": [999]},
    "C5": {"write_fc": 15, "kind": "coils",     "address": 2, "count": 3, "expected": [True, False, True]},
    "C6": {"write_fc": 16, "kind": "registers", "address": 2, "count": 3, "expected": [100, 200, 300]},
}
WRITE_CASES = ["C3", "C4", "C5", "C6"]


class ModbusError(Exception):
    pass


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ModbusError("connection closed mid-response")
        buf += chunk
    return buf


def _txn(host, port, unit, pdu, timeout):
    """One Modbus/TCP transaction; returns the PDU data after the function code."""
    frame = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit) + pdu  # MBAP + unit + PDU
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(frame)
        _tid, _pid, length, _unit = struct.unpack(">HHHB", _recvn(s, 7))
        body = _recvn(s, length - 1)
    fc = body[0]
    if fc & 0x80:
        raise ModbusError(f"Modbus exception, function 0x{fc & 0x7f:02x}, code {body[1]}")
    return body[1:]


def read_coils(host, port, unit, address, count, timeout):
    data = _txn(host, port, unit, struct.pack(">BHH", 1, address, count), timeout)
    byte_count = data[0]
    coil_bytes = data[1:1 + byte_count]
    return [bool((coil_bytes[i // 8] >> (i % 8)) & 1) for i in range(count)]


def read_regs(host, port, unit, address, count, timeout):
    data = _txn(host, port, unit, struct.pack(">BHH", 3, address, count), timeout)
    byte_count = data[0]
    return list(struct.unpack(">" + "H" * count, data[1:1 + byte_count]))


def cmd_snapshot(args):
    snap = {}
    for case in WRITE_CASES:
        t = CASE_TARGETS[case]
        try:
            if t["kind"] == "coils":
                vals = read_coils(args.plc, args.port, args.unit, t["address"], t["count"], args.timeout)
            else:
                vals = read_regs(args.plc, args.port, args.unit, t["address"], t["count"], args.timeout)
            snap[case] = {"values": vals, "error": None}
        except (ModbusError, OSError) as e:
            snap[case] = {"values": None, "error": str(e)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"plc": args.plc, "port": args.port, "unit": args.unit, "snapshot": snap}, f, indent=2)
    ok = sum(1 for v in snap.values() if v["error"] is None)
    print(f"[verify_readback] read {ok}/{len(snap)} targets from {args.plc}:{args.port} -> {args.out}")
    for case, v in snap.items():
        print(f"   {case}: {v['values'] if v['error'] is None else 'ERROR: ' + v['error']}")
    if ok == 0:
        sys.exit("[verify_readback] no targets readable - is the PLC up and is this host on the "
                 "authorized path (HMI->PLC:502)?")


def cmd_verify(args):
    pre = json.load(open(args.pre, encoding="utf-8"))["snapshot"]
    post = json.load(open(args.post, encoding="utf-8"))["snapshot"]

    rows, n_pass, n_fail = [], 0, 0
    for case in WRITE_CASES:
        t = CASE_TARGETS[case]
        pre_v = pre.get(case, {}).get("values")
        post_v = post.get(case, {}).get("values")
        post_err = post.get(case, {}).get("error")
        expected = t["expected"]
        if post_err or post_v is None:
            verdict = "ERROR"
            n_fail += 1
        elif post_v == expected:
            verdict = "PASS" if post_v != pre_v else "PASS (unchanged from baseline)"
            n_pass += 1
        else:
            verdict = "FAIL"
            n_fail += 1
        rows.append({
            "case": case, "write_fc": t["write_fc"], "kind": t["kind"],
            "address": t["address"], "count": t["count"],
            "pre": pre_v, "post": post_v, "commanded": expected,
            "changed": pre_v != post_v, "verdict": verdict,
            "error": post_err,
        })

    summary = {"targets": len(rows), "pass": n_pass, "fail": n_fail,
               "all_confirmed": n_fail == 0}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "results": rows}, f, indent=2)

    bar = "=" * 70
    print(bar)
    print(" STEP 9 READ-BACK VERIFICATION  (command -> enforcement -> effect)")
    print(bar)
    print(f" {'case':<5}{'FC':<4}{'target':<16}{'baseline':<18}{'after write':<18}{'verdict'}")
    for r in rows:
        tgt = f"{r['kind'][:4]} @{r['address']}x{r['count']}"
        print(f" {r['case']:<5}{r['write_fc']:<4}{tgt:<16}"
              f"{str(r['pre']):<18}{str(r['post']):<18}{r['verdict']}")
    print(bar)
    print(f" {summary}")
    print(f"[verify_readback] wrote {args.out}")
    if not summary["all_confirmed"]:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Step 9 PLC read-back verification (read-only, stdlib).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot", help="read current PLC state for the 4 write cases")
    s.add_argument("--plc", default="10.0.3.10")
    s.add_argument("--port", type=int, default=502)
    s.add_argument("--unit", type=int, default=1)
    s.add_argument("--timeout", type=float, default=3.0)
    s.add_argument("--out", required=True)

    v = sub.add_parser("verify", help="compare pre/post snapshots against commanded values")
    v.add_argument("--pre", required=True)
    v.add_argument("--post", required=True)
    v.add_argument("--out", required=True)

    args = ap.parse_args()
    (cmd_snapshot if args.cmd == "snapshot" else cmd_verify)(args)


if __name__ == "__main__":
    main()