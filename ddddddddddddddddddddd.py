RG="rg-cyb691-lab-dk"

# Reset PLC datastore first so pre.json starts clean
az vm run-command invoke -g "$RG" -n vm-plc --command-id RunShellScript --scripts \
  "pkill -f run_server.py || true; sleep 1; nohup /home/azureuser/mb/bin/python /home/azureuser/run_server.py > /home/azureuser/modbus_sim.log 2>&1 & sleep 2"

# Execute the 4-step read-back verification on vm-hmi
az vm run-command invoke -g "$RG" -n vm-hmi --command-id RunShellScript --scripts '
cd /home/azureuser
python3 verify_readback.py snapshot --plc 10.0.3.10 --out pre.json
for c in C3 C4 C5 C6; do
  python3 traffic_generator.py -t 10.0.3.10 -p 502 --case $c --run-id S9 --topology layered --source-ip 10.0.1.10 --authorized 1 --anomaly-class normal --scenario_csv /home/azureuser/scenario.csv
  sleep 1
done
python3 verify_readback.py snapshot --plc 10.0.3.10 --out post.json
python3 verify_readback.py verify --pre pre.json --post post.json --out readback_verification.json
'

-----------------------------------------------------------------------------
"To validate that our network segmentation and ICS security controls don't break legitimate operational workflows—and that our telemetry accurately captures state changes—we executed an end-to-end command → enforcement → effect read-back verification (Run ID: S9) across the layered topology.
1. Deterministic Baseline Initialization
We first reinitialized the Modbus TCP server (run_server.py) on vm-plc (10.0.3.10:502) via the Azure control plane (az vm run-command), avoiding direct SSH exposure during orchestration. We then polled the target memory addresses from vm-hmi (10.0.1.10) to capture pre.json, verifying a deterministic zeroed state across all target coils (False) and holding registers (0).
2. Granular Write-Path & Policy Enforcement Testing
Next, we generated authorized, normal-class Modbus TCP write traffic (--authorized 1 --anomaly-class normal) across four distinct write function codes (C3–C6) to test deep packet inspection (DPI) and firewall rule precision:
• Single-bit/word writes: Function Code 5 (coil @0x1) and Function Code 6 (register @1x1).
• Multi-bit/word writes: Function Code 15 (coil @2x3, length 3) and Function Code 16 (register @2x3, length 3).
3. Datastore State Verification (post.json)
Rather than relying solely on packet captures or firewall allow-logs—which only prove transit—we executed a post-test Modbus read-back (post.json) and programmatically diffed the datastore states (readback_verification.json):
• FC 5 (C3): Confirmed state transition False → True at coil @0x1.
• FC 6 (C4): Confirmed integer write 0 → 999 at register @1x1.
• FC 15 (C5): Confirmed bitmask write [False, False, False] → [True, False, True] at coil @2x3.
• FC 16 (C6): Confirmed block register write [0, 0, 0] → [100, 200, 300] at register @2x3.
Security Takeaway
All four assertions passed (all_confirmed: True), proving two critical security properties: first, our layered enforcement rules allow granular, authorized HMI write operations without false-positive drops; second, our ground-truth labeling in scenario.csv aligns 1:1 with actual PLC memory mutations."


