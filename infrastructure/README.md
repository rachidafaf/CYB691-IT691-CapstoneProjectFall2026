# OT Testbed Infrastructure, Emulation, and Data Generation

**CYB691 / IT691 Cybersecurity Capstone — Team 4**  
**Module lead:** Erick Espinosa (Infrastructure, Emulation & Data Generation)  
**Contributors:** Rachid Afaf (Security Architect), Anil Kumar (Documentation & Integration)

This directory holds the testbed scripts and the telemetry handoff. Section 1 states what the **captured evidence** shows about the environment that produced the handoff. Section 2 lists each component with its status and the evidence for it. Anything not backed by an artifact in this repository is marked **To confirm** and must be filled in by the module lead (README §8, items 3–4).

---

## 1. What the 2026-09-26 handoff shows (evidence-derived)

Every statement below comes from `ot_telemetry_handoff_2026-09-26.tar.gz` (SHA-256 `0e8bf4f5…447de6`). It can be re-checked with `tar -tvzf` and the analysis in `data/parser_integrity_report.json`.

| # | Observation | Evidence |
| :--- | :--- | :--- |
| E1 | The capture host is an **Azure VM**, not a local host. | Archive members owned by `azureuser`; traffic to Azure platform addresses `168.63.129.16` (WireServer, 2,302 HTTP events) and `169.254.169.254` (instance metadata); DNS for `vm-firewall-gateway.…internal.cloudapp.net` and `azure.archive.ubuntu.com`. |
| E2 | The Modbus target is a **Docker container on the VM's default bridge**: `10.0.1.4 → 172.17.0.2:5020` on interface `docker0`. | All 87 Modbus records and alerts have this tuple. Suricata saw interfaces `eth0`, `lo` and `docker0`. |
| E3 | **No firewall was in the Modbus path** for this capture. Traffic went host → Docker bridge, so the run is a monitored *flat* path. | E2; `iptables_drops.log` contains only `-- No entries --`. |
| E4 | The Modbus target is the **Conpot honeypot** container (`honeynet/conpot:latest`, name `conpot`, host `0.0.0.0:502 → 5020/tcp`). Port 5020 is Conpot's default Modbus port. | `img/Docker_Emulators_Status.png` (`docker ps` on `vm-firewall-gateway`); `img/Port_Binding_Verification.png` (docker-proxy listening on 502); capture tuple in E2. |
| E5 | **All 10 Modbus requests received an exception response** (Illegal Data Address, exception code 2). None of the 6 writes changed any register. A later generator run (2026-09-26 18:46 UTC) also got code 2 for every poll and write, which is consistent with Conpot's default template not mapping these addresses. | `exception_code` in `data/normalized_telemetry.json`; `img/pymodbus_execution_screenshot.png`. |
| E6 | The `traffic_generator.py` **inside the handoff did not produce this capture**. The capture has FC 0x01 reads, writes of 1234 and 57005 (0xDEAD) to address 0, and a run with only FC5 + FC6. The archived script sends FC 0x03 polls, writes 999 to address 1 and `[100,200,300]` to address 2, and never sends FC 0x01. | Compare `extracted_handoff/traffic_generator.py` with the 10 transactions in `data/scenario_actions.json`. |
| E7 | Suricata local rules SIDs 1000001–1000004 were loaded (generic Modbus traffic, function code monitored, write single register, write multiple registers). No write-specific rule fired for FC 0x05. | 67 alerts in `eve.json`. |
| E8 | The capture also contains **non-testbed host traffic**: Docker Hub, Ubuntu mirrors, `whatismyip.akamai.com`, and inbound SSH from public IPs (for example `2.57.122.150`). | DNS/HTTP/TLS/SSH events in `eve.json`. See the privacy note in §5. |

### Reconciliation with earlier descriptions
* **Azure phase.** The project explored Azure first (VNet `vnet-ot-testbed-dk`, subnets `snet-enterprise`, `snet-hmi`, `snet-plc`, budget alerts at $5/$10/$20).
  - E1 shows the handoff itself was captured on an Azure VM named `vm-firewall-gateway`.
  - The earlier statement that "the operational testbed was migrated to a local host" therefore does **not** describe the environment that produced this evidence.
  - **To confirm (Erick):** whether a local deployment exists. If it does, which captures came from it.
* **OpenPLC was a placeholder.** The container named `openplc_runtime` is `nginx:alpine` (host `503 → 502`, `8080 → 80`; `img/Docker_Emulators_Status.png`). It does not speak Modbus. No artifact shows a working OpenPLC runtime. Every Modbus exchange in the evidence went to **Conpot** (E4).
  - **To confirm (Erick):** whether a real OpenPLC runtime was ever deployed. If not, the reports must say "Conpot honeypot" wherever they currently say "OpenPLC".
* **pfSense.** No artifact in the repository shows pfSense in the traffic path (no pfSense log, configuration export or screenshot of rules). Its status is **planned / not evidenced** until one is added.

---

## 2. Components: status, version and evidence

Status key: **Evidenced** = an artifact in this repo proves it · **Claimed** = stated by the team, no artifact yet · **Planned** = not built.

| Zone / level | Component | Version | Address / interface | Status | Evidence / how to record |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Enterprise / L3 | Workstation running `traffic_generator.py` (pymodbus) | **To confirm** (`python -V`, `pip show pymodbus`) | `10.0.1.4` on the Azure VM (`eth0`); same host as the sensor | Evidenced (source of all Modbus requests) | E1, E2. The generator version that ran is **To confirm** (E6). |
| Field / L1 | Conpot ICS honeypot (the Modbus target) | `honeynet/conpot:latest`, an unpinned tag. **Record the digest:** `docker inspect --format '{{.RepoDigests}}' honeynet/conpot`. Template **to confirm** (`default`?). | container `172.17.0.2:5020` on `docker0`; host `0.0.0.0:502` | Evidenced | E2, E4, E5. The default register map returns Illegal Data Address for the generator's addresses, so writes never take effect. A template with mapped holding registers and coils is needed for R1 outcome evidence. |
| Field / L1 | "openplc_runtime" container | `nginx:alpine` | host `503 → 502`, `8080 → 80` | **Placeholder** (not a PLC, no Modbus) | `img/Docker_Emulators_Status.png` |
| Field / L1 | OpenPLC v3 runtime | — | — | Not evidenced / planned | No artifact |
| Monitoring / L2 | Suricata | **To confirm** (`suricata -V`, `suricata --build-info`) | on the VM: `eth0`, `lo`, `docker0` | Evidenced | `eve.json` with `modbus` and `alert` events; local SIDs 1000001–1000004 (E7) |
| Boundary / L2–3 | pfSense CE (stated v2.7.2) | **To confirm** (Dashboard → Version) | WAN/HMI/PLC interfaces **to confirm** | Planned / not evidenced | Add a configuration backup (secrets removed) and a rules screenshot |
| Boundary / L2–3 | Host firewall (`iptables`) drop log | — | VM | Evidenced as **empty** | `iptables_drops.log` = `-- No entries --` |

### Implemented vs planned connections
* **Implemented (evidenced):**
  - `10.0.1.4` → Conpot container `172.17.0.2:5020` over `docker0` (host port 502 published);
  - Suricata monitoring of that bridge;
  - handoff packaging of `eve.json`, `iptables_drops.log` and a generator script.
* **Planned:**
  - a layered topology with enterprise, HMI and PLC zones separated by pfSense ACLs (R1 in the main README);
  - the same scripted cases run in both the flat and the layered topology (README §5).

```text
EVIDENCED (2026-09-23 capture)                 PLANNED (layered topology, Report 2)
┌──────────── Azure VM "vm-firewall-gateway" ───┐   Enterprise 10.0.1.0/24 ─┐
│ traffic_generator.py  (10.0.1.4, eth0)        │                            │ pfSense ACLs
│        │ Modbus/TCP                           │   HMI 10.0.2.0/24 ─────────┤ (R1 evidence:
│        ▼ docker0                              │                            │  drop log)
│ Conpot 172.17.0.2:5020     ◄── Suricata sees  │   PLC 10.0.3.0/24 ─────────┘
│ (honeynet/conpot:latest)       eth0/lo/docker0│   Suricata on the HMI/PLC segment
└───────────────────────────────────────────────┘
```

---

## 3. Traffic generator (`traffic_generator.py`)

The script in this directory polls with FC 0x03 and then sends unauthorized FC 0x05, 0x06 and 0x10 writes. It is **not** the version that produced the 2026-09-26 capture (E6).

**For every future run:**
1. Commit the exact script version used (record the git commit in the run notes).
2. Log each action as it executes (timestamp, actor, command, authorized yes/no), so that `data/scenario_actions.json` is written at execution time instead of reconstructed.

---

## 4. Telemetry handoff contents

`ot_telemetry_handoff_2026-09-26.tar.gz` contains:
* `var/log/suricata/eve.json`: 20,074 records captured 2026-09-23 02:51–03:18 UTC, including 67 alerts and 20 `modbus` records.
  - The 20 records are **10 unique transactions, each logged twice** on consecutive, byte-identical lines.
  - The 10 transactions are 4 reads (2 × FC 0x01, 2 × FC 0x03) and 6 writes (1 × FC 0x05, 3 × FC 0x06, 2 × FC 0x10).
  - `src/log_parser.py` counts each transaction once and records the de-duplication in `data/parser_integrity_report.json`.
* `iptables_drops.log`: `-- No entries --` (no firewall drops recorded).
* `traffic_generator.py`: a generator script (see E6).

---

## 5. Privacy, ethics and licensing of captured material

* **Privacy.** `eve.json` contains more than testbed traffic (E8):
  - public IP addresses of inbound SSH clients, which may include personal addresses;
  - the VM's internal Azure DNS name;
  - update and registry hostnames.

  Before any public release, either redact or drop non-Modbus events, or confirm that publishing them is acceptable. Record the decision in `THIRD_PARTY_LICENSES.md` §3.
* **Safety.** All Modbus traffic targeted a lab container. No production or third-party control system was contacted.
* **Licensing.** Tool and data terms are in [THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md).
