# OT Cyber-Physical Incident Triage & Timeline Report
**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)
**Generated Date:** 2026-09-26 14:06:02 UTC
**Lead Security Architect:** Rachid Afaf

---
## Executive Incident Summary
During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, 
the normalization pipeline analyzed **20 Modbus TCP telemetry frames** 
between `2026-09-23T02:51:42.772834+00:00` and `2026-09-23T03:18:40.538822+00:00`.
The analysis isolated **12 unauthorized state-altering write command attempts** 
and **20 protocol exception alerts** originating from workstation `10.0.1.4` 
targeting Industrial PLC `172.17.0.2` (Port 502).

### Key Metrics Breakdown
- **Total Telemetry Ingested:** 20 records
- **Read Commands (Polling):** 8 (0.67 Read/Write Ratio)
- **State-Altering Write Commands:** 12
- **Illegal Data Address Exceptions:** 20
- **High-Threat Incident Alerts (Score >= 75):** 12

---
## Chronological Incident Event Timeline

| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| MODBUS-EVT-0001 | 2026-09-23 02:51:42.772834+00:00 | 10.0.1.4 | 172.17.0.2 | 0x01 (Read Coils) | READ | LOW | **25** | `addr:0 qty:8` [IllegalDataAddr] |
| MODBUS-EVT-0002 | 2026-09-23 02:51:42.772834+00:00 | 10.0.1.4 | 172.17.0.2 | 0x01 (Read Coils) | READ | LOW | **25** | `addr:0 qty:8` [IllegalDataAddr] |
| MODBUS-EVT-0003 | 2026-09-23 02:51:42.974256+00:00 | 10.0.1.4 | 172.17.0.2 | 0x03 (Read Holding Registers) | READ | LOW | **25** | `addr:0 qty:2` [IllegalDataAddr] |
| MODBUS-EVT-0004 | 2026-09-23 02:51:42.974256+00:00 | 10.0.1.4 | 172.17.0.2 | 0x03 (Read Holding Registers) | READ | LOW | **25** | `addr:0 qty:2` [IllegalDataAddr] |
| MODBUS-EVT-0005 | 2026-09-23 02:51:43.175714+00:00 | 10.0.1.4 | 172.17.0.2 | 0x06 (Write Single Register) | WRITE | HIGH | **75** | `addr:0 val:1234` [IllegalDataAddr] |
| MODBUS-EVT-0006 | 2026-09-23 02:51:43.175714+00:00 | 10.0.1.4 | 172.17.0.2 | 0x06 (Write Single Register) | WRITE | HIGH | **75** | `addr:0 val:1234` [IllegalDataAddr] |
| MODBUS-EVT-0007 | 2026-09-23 02:51:43.377147+00:00 | 10.0.1.4 | 172.17.0.2 | 0x10 (Write Multiple Registers) | WRITE | CRITICAL | **100** | `addr:0 val:` [IllegalDataAddr] |
| MODBUS-EVT-0008 | 2026-09-23 02:51:43.377147+00:00 | 10.0.1.4 | 172.17.0.2 | 0x10 (Write Multiple Registers) | WRITE | CRITICAL | **100** | `addr:0 val:` [IllegalDataAddr] |
| MODBUS-EVT-0009 | 2026-09-23 02:52:55.414908+00:00 | 10.0.1.4 | 172.17.0.2 | 0x01 (Read Coils) | READ | LOW | **25** | `addr:0 qty:8` [IllegalDataAddr] |
| MODBUS-EVT-0010 | 2026-09-23 02:52:55.414908+00:00 | 10.0.1.4 | 172.17.0.2 | 0x01 (Read Coils) | READ | LOW | **25** | `addr:0 qty:8` [IllegalDataAddr] |
| MODBUS-EVT-0011 | 2026-09-23 02:52:55.616642+00:00 | 10.0.1.4 | 172.17.0.2 | 0x03 (Read Holding Registers) | READ | LOW | **25** | `addr:0 qty:2` [IllegalDataAddr] |
| MODBUS-EVT-0012 | 2026-09-23 02:52:55.616642+00:00 | 10.0.1.4 | 172.17.0.2 | 0x03 (Read Holding Registers) | READ | LOW | **25** | `addr:0 qty:2` [IllegalDataAddr] |
| MODBUS-EVT-0013 | 2026-09-23 02:52:55.818597+00:00 | 10.0.1.4 | 172.17.0.2 | 0x06 (Write Single Register) | WRITE | HIGH | **75** | `addr:0 val:1234` [IllegalDataAddr] |
| MODBUS-EVT-0014 | 2026-09-23 02:52:55.818597+00:00 | 10.0.1.4 | 172.17.0.2 | 0x06 (Write Single Register) | WRITE | HIGH | **75** | `addr:0 val:1234` [IllegalDataAddr] |
| MODBUS-EVT-0015 | 2026-09-23 02:52:56.019737+00:00 | 10.0.1.4 | 172.17.0.2 | 0x10 (Write Multiple Registers) | WRITE | CRITICAL | **100** | `addr:0 val:` [IllegalDataAddr] |
| MODBUS-EVT-0016 | 2026-09-23 02:52:56.019737+00:00 | 10.0.1.4 | 172.17.0.2 | 0x10 (Write Multiple Registers) | WRITE | CRITICAL | **100** | `addr:0 val:` [IllegalDataAddr] |
| MODBUS-EVT-0017 | 2026-09-23 03:18:40.337284+00:00 | 10.0.1.4 | 172.17.0.2 | 0x05 (Write Single Coil) | WRITE | HIGH | **75** | `addr:0 val:65280` [IllegalDataAddr] |
| MODBUS-EVT-0018 | 2026-09-23 03:18:40.337284+00:00 | 10.0.1.4 | 172.17.0.2 | 0x05 (Write Single Coil) | WRITE | HIGH | **75** | `addr:0 val:65280` [IllegalDataAddr] |
| MODBUS-EVT-0019 | 2026-09-23 03:18:40.538822+00:00 | 10.0.1.4 | 172.17.0.2 | 0x06 (Write Single Register) | WRITE | HIGH | **75** | `addr:0 val:57005` [IllegalDataAddr] |
| MODBUS-EVT-0020 | 2026-09-23 03:18:40.538822+00:00 | 10.0.1.4 | 172.17.0.2 | 0x06 (Write Single Register) | WRITE | HIGH | **75** | `addr:0 val:57005` [IllegalDataAddr] |

---
## Defensive Triage Recommendations & Security Controls
1. **Enforce Purdue Model Microsegmentation (pfSense):** Restrict Modbus Port 502 ingress traffic targeting PLC `172.17.0.2` strictly to authorized HMI subnets. Drop non-whitelisted workstation traffic (`10.0.1.4`).
2. **Deploy Stateful Deep Packet Inspection (Suricata/Zeek):** Enforce signature rules that block Modbus Function Codes `0x05` (Write Single Coil), `0x06` (Write Single Register), and `0x10` (Write Multiple Registers) originating outside authorized engineering workstations.
3. **Automate SIEM/Triage Alerting:** Ingest standardized JSON event frames into downstream ML anomaly models (Bhavesh Dalal) to detect anomalous inter-arrival command bursts.