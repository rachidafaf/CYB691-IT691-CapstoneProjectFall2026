# OT Cyber-Physical Incident Triage & Timeline Report
**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)
**Generated Date:** 2026-11-03 14:59:58 UTC
**Lead Security Architect:** Rachid Afaf

---
## Executive Incident Summary
During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, 
the normalization pipeline analyzed **5 Modbus TCP telemetry frames** and **3 firewall drop records** 
between `2026-11-02T00:30:10.150000+00:00` and `2026-11-02T05:30:25.400000+00:00` (UTC).
The analysis isolated **2 state-altering write command attempts** from `192.168.1.200` targeting `192.168.1.100` (port 502), 
**0 protocol exception responses**, and **3 firewall drops** of traffic from `192.168.1.200`.

### Key Metrics Breakdown
- **Total Telemetry Ingested:** 8 records
- **Read Commands (Polling):** 3 (1.5 Read/Write Ratio)
- **State-Altering Write Commands:** 2
- **Modbus Protocol Exceptions:** 0
- **Firewall Drops:** 3
- **High-Threat Incident Alerts (Score >= 75):** 3

---
## Chronological Incident Event Timeline

| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| MODBUS-EVT-0001 | 2026-11-02 00:30:10.150000+00:00 | `192.168.1.200` | `192.168.1.100` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0002 | 2026-11-02 00:30:15.200000+00:00 | `192.168.1.200` | `192.168.1.100` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0003 | 2026-11-02 00:30:25.400000+00:00 | `192.168.1.200` | `192.168.1.100` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0004 | 2026-11-02 00:30:00.200000-05:00 | `192.168.1.50` | `192.168.1.100` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0005 | 2026-11-02 00:30:05.100000-05:00 | `192.168.1.50` | `192.168.1.100` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0006 | 2026-11-02 00:30:10.150100-05:00 | `192.168.1.200` | `192.168.1.100` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0007 | 2026-11-02 00:30:20.100000-05:00 | `192.168.1.50` | `192.168.1.100` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0008 | 2026-11-02 00:30:25.400000-05:00 | `192.168.1.200` | `192.168.1.100` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |

---

## Defensive Recommendations & Containment Actions
1. **Inbound ACL Enforcement:** Restrict port 502 to authorized engineering workstations only; review write traffic from `192.168.1.200`.
2. **Suricata DPI Rule Tuning:** Enforce Modbus rule SID 1000004 to drop state-altering function codes (`FC05`, `FC06`, `FC15`, `FC16`) originating outside the Control Zone.
3. **Machine Learning Anomaly Quarantine:** Ingest high-threat events into `ml_detector.py` to trigger automated microsegmentation isolation.