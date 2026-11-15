# Step 9 — Read-Back Verification: Closing the Command → Enforcement → Effect Loop

**Capstone:** Layered cybersecurity monitoring and defense for OT networks (Modbus TCP), Team 4
**Prepared for:** Report 2; resolves Report 1 feedback item #2 ("no write succeeded" on Conpot)
**Captures:** `ot_telemetry_handoff_2026-11-14` and `ot_telemetry_handoff_2026-11-15` (Step 7) — verified on the live pymodbus PLC; read-back **4/4 PASS in both**
**Tool:** `verify_readback.py` (read-only, stdlib raw-socket Modbus client); evidence in `readback_verification.json`

## Purpose

Step 8 proved the firewall *contains* unauthorized writes (100%). Step 9 proves the complementary half: that **authorized** writes actually **change PLC state**, closing the full chain of custody — command issued, enforcement permitted it, effect occurred — so containment is measured against a system where writes genuinely do something.

## Method

A read-only verification wraps the authorized write run:

1. **Baseline snapshot** — read the target coils/registers before any writes (`pre.json`).
2. **Authorized writes** — the existing `traffic_generator.py` sends C3–C6 from the HMI (`10.0.1.10`), which the layered firewall permits (HMI→PLC:502 ACCEPT).
3. **Post snapshot** — read the same targets again (`post.json`).
4. **Verify** — assert `post == commanded` and `post != pre` per case (`readback_verification.json`).

`verify_readback.py` issues only FC1 (ReadCoils) and FC3 (ReadHoldingRegisters) — it never writes. It uses raw sockets (stdlib only, like the generator), so it needs no pymodbus install on the HMI. The PLC datastore is restarted before the baseline so the pre-state is known-zero.

Read-back runs from the **authorized** host by design; a read-back attempted from the WS host under the layered policy would be dropped, which is itself consistent with the Step 8 containment result.

## Target map (decoded from the generator's `case_payloads`)

| Case | Write | Address | Commanded | Read-back | Expected |
|---|---|---|---|---|---|
| C3 | FC5 WriteSingleCoil | coil 0 | 0xFF00 = ON | FC1 @0 ×1 | `[True]` |
| C4 | FC6 WriteSingleRegister | reg 1 | 999 | FC3 @1 ×1 | `[999]` |
| C5 | FC15 WriteMultipleCoils | coils 2–4 | 0x05 = 1,0,1 | FC1 @2 ×3 | `[True, False, True]` |
| C6 | FC16 WriteMultipleRegisters | regs 2–4 | 100,200,300 | FC3 @2 ×3 | `[100, 200, 300]` |

Coil and register address spaces are separate and the cases use distinct addresses, so a single post-snapshot captures all four without collision.

## Result — all four confirmed

| Case | FC | Baseline | After write | Verdict |
|---|---|---|---|---|
| C3 | 5 | `[False]` | `[True]` | **PASS** |
| C4 | 6 | `[0]` | `[999]` | **PASS** |
| C5 | 15 | `[False, False, False]` | `[True, False, True]` | **PASS** |
| C6 | 16 | `[0, 0, 0]` | `[100, 200, 300]` | **PASS** |

`{'targets': 4, 'pass': 4, 'fail': 0, 'all_confirmed': True}`

The **2026-11-15 Step 7 capture reproduced the same result** (4/4 PASS: C3 `[True]`, C4 `[999]`, C5 `[True, False, True]`, C6 `[100, 200, 300]`), confirming the authorized-write effect is stable across captures and that the Step 7 insider anomalies (A1–A5, issued from the same HMI) did not perturb the legitimate control path.

Every authorized write produced the commanded state change (`post == commanded`) from a distinct baseline (`post != pre`). On the pymodbus PLC, writes **succeed and alter state** — directly resolving Report 1 item #2, where Conpot returned Illegal Data Address and the capture showed only attempts, not effects.

## Defect found and fixed during verification (methods note)

Read-back initially failed, which exposed a real framing bug in the generator — the value of running Step 9:

1. **C5 payload:** `struct.pack(">HHHB", 2,3,1,5)` encoded the FC15 byte-count as a 2-byte field, so the server read a misaligned request and set only the first coil (`[True, False, False]`). Correct is `">HHBB"` (address H, quantity H, byte-count **B**, data B).
2. **Collateral:** a global `sed 's/>HHHB/>HHBB/'` also rewrote the MBAP-header pack line, corrupting every packet's length/unit (all-FAIL). Fixed by restoring only the MBAP line.

This is a genuine research finding: without read-back, the pipeline would have recorded Modbus *traffic* for these cases while no *state change* occurred, and the error would have gone unnoticed. The PLC datastore itself is correctly configured (`di/co/hr/ir` = `ModbusSequentialDataBlock(0,[0]*999)`, `single=True`), so there is no `zero_mode` offset — reads and writes address the same cells.

## Evidence and reproducibility

- `readback_verification.json`, `pre.json`, `post.json` are bundled in the handoff archive as evidence attachments (carried in the tarball; not ingested by the parser, which processes `eve.json`, `iptables_drops.log`, `scenario_file.csv`, `versions.txt`).
- `versions.txt` now records the deployed pymodbus version, closing Report 1's "record deployed tool versions" item.
- Re-runnable on any future capture with the same four commands (snapshot → writes → snapshot → verify).

## Limitations

- Verification covers the four write cases (C3–C6); read cases (C1, C2) have no state to verify.
- The baseline requires a fresh datastore (PLC restart) for the `post != pre` delta to be meaningful; a persisted datastore would still satisfy `post == commanded` but not demonstrate change.
- Read-back confirms the authorized path's effect; it does not re-measure containment (that is Step 8).