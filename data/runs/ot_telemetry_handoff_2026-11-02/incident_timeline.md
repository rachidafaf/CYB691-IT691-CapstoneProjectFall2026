# OT Cyber-Physical Incident Triage & Timeline Report
**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)
**Generated Date:** 2026-11-03 15:00:13 UTC
**Lead Security Architect:** Rachid Afaf

---
## Executive Incident Summary
During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, 
the normalization pipeline analyzed **0 Modbus TCP telemetry frames** and **1 firewall drop records** 
between `2026-11-03T09:00:01+00:00` and `2026-11-03T09:00:01+00:00` (UTC).
The analysis isolated **0 state-altering write command attempts** from none targeting none (port 502), 
**0 protocol exception responses**, and **1 firewall drops** of traffic from `10.0.1.20`.

### Key Metrics Breakdown
- **Total Telemetry Ingested:** 1 records
- **Read Commands (Polling):** 0 (0.0 Read/Write Ratio)
- **State-Altering Write Commands:** 0
- **Modbus Protocol Exceptions:** 0
- **Firewall Drops:** 1
- **High-Threat Incident Alerts (Score >= 75):** 1

---
## Chronological Incident Event Timeline

| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| MODBUS-EVT-0001 | 2026-11-03 09:00:01+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |

---

## Defensive Recommendations & Containment Actions
1. **Inbound ACL Enforcement:** Restrict port 502 to authorized engineering workstations only; review write traffic from none.
2. **Suricata DPI Rule Tuning:** Enforce Modbus rule SID 1000004 to drop state-altering function codes (`FC05`, `FC06`, `FC15`, `FC16`) originating outside the Control Zone.
3. **Machine Learning Anomaly Quarantine:** Ingest high-threat events into `ml_detector.py` to trigger automated microsegmentation isolation.