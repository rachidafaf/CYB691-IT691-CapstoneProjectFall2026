# OT Cyber-Physical Incident Triage & Timeline Report
**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)
**Generated Date:** 2026-11-20 18:34:05 UTC
**Lead Security Architect:** Rachid Afaf

---
## Executive Incident Summary
During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, 
the normalization pipeline analyzed **270 Modbus TCP telemetry frames** and **91 firewall drop records** 
between `2026-11-14T20:24:36.762356+00:00` and `2026-11-14T20:34:25.588864+00:00` (UTC).
The analysis isolated **180 state-altering write command attempts** from `10.0.1.10`, `10.0.1.20` targeting `10.0.3.10` (port 502), 
**0 protocol exception responses**, and **91 firewall drops** of traffic from `10.0.1.20`.

### Key Metrics Breakdown
- **Total Telemetry Ingested:** 361 records
- **Read Commands (Polling):** 90 (0.5 Read/Write Ratio)
- **State-Altering Write Commands:** 180
- **Modbus Protocol Exceptions:** 0
- **Firewall Drops:** 91
- **High-Threat Incident Alerts (Score >= 75):** 181

---
## Chronological Incident Event Timeline

| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| MODBUS-EVT-0001 | 2026-11-14 20:24:36.762356+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0002 | 2026-11-14 20:24:37.810519+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0003 | 2026-11-14 20:24:38.867217+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0004 | 2026-11-14 20:24:39.920506+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0005 | 2026-11-14 20:24:40.975813+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0006 | 2026-11-14 20:24:42.036301+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0007 | 2026-11-14 20:24:43.084041+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0008 | 2026-11-14 20:24:44.136563+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0009 | 2026-11-14 20:24:45.184608+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0010 | 2026-11-14 20:24:46.238683+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0011 | 2026-11-14 20:24:47.285452+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0012 | 2026-11-14 20:24:48.337957+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0013 | 2026-11-14 20:24:49.385600+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0014 | 2026-11-14 20:24:50.438954+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0015 | 2026-11-14 20:24:51.490052+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0016 | 2026-11-14 20:24:52.540242+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0017 | 2026-11-14 20:24:53.594814+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0018 | 2026-11-14 20:24:54.643727+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0019 | 2026-11-14 20:24:55.691816+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0020 | 2026-11-14 20:24:56.744818+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0021 | 2026-11-14 20:24:57.795753+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0022 | 2026-11-14 20:24:58.846476+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0023 | 2026-11-14 20:24:59.893149+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0024 | 2026-11-14 20:25:00.942867+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0025 | 2026-11-14 20:25:01.994432+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0026 | 2026-11-14 20:25:03.043468+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0027 | 2026-11-14 20:25:04.091571+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0028 | 2026-11-14 20:25:05.140863+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0029 | 2026-11-14 20:25:06.196928+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0030 | 2026-11-14 20:25:07.245423+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0031 | 2026-11-14 20:25:08.294431+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0032 | 2026-11-14 20:25:09.342658+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0033 | 2026-11-14 20:25:10.389822+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0034 | 2026-11-14 20:25:11.439929+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0035 | 2026-11-14 20:25:12.489056+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0036 | 2026-11-14 20:25:13.540303+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0037 | 2026-11-14 20:25:14.589457+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0038 | 2026-11-14 20:25:15.636805+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0039 | 2026-11-14 20:25:16.684547+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0040 | 2026-11-14 20:25:17.733231+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0041 | 2026-11-14 20:25:18.782150+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0042 | 2026-11-14 20:25:19.838912+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0043 | 2026-11-14 20:25:20.887415+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0044 | 2026-11-14 20:25:21.934642+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0045 | 2026-11-14 20:25:22.985093+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0046 | 2026-11-14 20:25:24.032446+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0047 | 2026-11-14 20:25:25.082665+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0048 | 2026-11-14 20:25:26.131094+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0049 | 2026-11-14 20:25:27.184354+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0050 | 2026-11-14 20:25:28.232153+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0051 | 2026-11-14 20:25:29.278844+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0052 | 2026-11-14 20:25:30.325502+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0053 | 2026-11-14 20:25:31.373227+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0054 | 2026-11-14 20:25:32.420169+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0055 | 2026-11-14 20:25:33.469738+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0056 | 2026-11-14 20:25:34.519097+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0057 | 2026-11-14 20:25:35.566755+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0058 | 2026-11-14 20:25:36.616231+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0059 | 2026-11-14 20:25:37.664744+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0060 | 2026-11-14 20:25:38.712855+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0061 | 2026-11-14 20:25:39.760767+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0062 | 2026-11-14 20:25:40.817729+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0063 | 2026-11-14 20:25:41.864759+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0064 | 2026-11-14 20:25:42.910841+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0065 | 2026-11-14 20:25:43.957891+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0066 | 2026-11-14 20:25:45.006211+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0067 | 2026-11-14 20:25:46.055242+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0068 | 2026-11-14 20:25:47.102033+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0069 | 2026-11-14 20:25:48.150177+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0070 | 2026-11-14 20:25:49.198502+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0071 | 2026-11-14 20:25:50.246667+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0072 | 2026-11-14 20:25:51.297349+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0073 | 2026-11-14 20:25:52.344716+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0074 | 2026-11-14 20:25:53.400937+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0075 | 2026-11-14 20:25:54.477436+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0076 | 2026-11-14 20:25:55.538854+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0077 | 2026-11-14 20:25:56.597136+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0078 | 2026-11-14 20:25:57.646955+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0079 | 2026-11-14 20:25:58.694807+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0080 | 2026-11-14 20:25:59.741619+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0081 | 2026-11-14 20:26:00.788333+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0082 | 2026-11-14 20:26:01.835103+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0083 | 2026-11-14 20:26:02.886515+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0084 | 2026-11-14 20:26:03.933224+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0085 | 2026-11-14 20:26:04.979812+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0086 | 2026-11-14 20:26:06.027523+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0087 | 2026-11-14 20:26:07.076844+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0088 | 2026-11-14 20:26:08.124680+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0089 | 2026-11-14 20:26:09.173423+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0090 | 2026-11-14 20:26:10.220748+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0091 | 2026-11-14 20:26:38.801727+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0092 | 2026-11-14 20:26:39.849697+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0093 | 2026-11-14 20:26:40.898907+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0094 | 2026-11-14 20:26:41.956715+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0095 | 2026-11-14 20:26:43.007210+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0096 | 2026-11-14 20:26:44.054653+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0097 | 2026-11-14 20:26:45.102322+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0098 | 2026-11-14 20:26:46.149742+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0099 | 2026-11-14 20:26:47.197853+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0100 | 2026-11-14 20:26:48.253327+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0101 | 2026-11-14 20:26:49.300968+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0102 | 2026-11-14 20:26:50.347752+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0103 | 2026-11-14 20:26:51.397544+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0104 | 2026-11-14 20:26:52.449186+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0105 | 2026-11-14 20:26:53.505224+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0106 | 2026-11-14 20:26:54.559675+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0107 | 2026-11-14 20:26:55.612320+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0108 | 2026-11-14 20:26:56.663378+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0109 | 2026-11-14 20:26:57.712788+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0110 | 2026-11-14 20:26:58.764545+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0111 | 2026-11-14 20:26:59.812128+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0112 | 2026-11-14 20:27:00.859397+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0113 | 2026-11-14 20:27:01.906908+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0114 | 2026-11-14 20:27:02.954201+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0115 | 2026-11-14 20:27:04.002494+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0116 | 2026-11-14 20:27:05.049686+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0117 | 2026-11-14 20:27:06.100027+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0118 | 2026-11-14 20:27:07.148093+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0119 | 2026-11-14 20:27:08.196463+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0120 | 2026-11-14 20:27:09.243770+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0121 | 2026-11-14 20:27:10.291113+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0122 | 2026-11-14 20:27:11.338954+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0123 | 2026-11-14 20:27:12.386236+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0124 | 2026-11-14 20:27:13.433466+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0125 | 2026-11-14 20:27:14.481510+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0126 | 2026-11-14 20:27:15.528394+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0127 | 2026-11-14 20:27:16.576652+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0128 | 2026-11-14 20:27:17.623986+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0129 | 2026-11-14 20:27:18.672671+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0130 | 2026-11-14 20:27:19.721079+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0131 | 2026-11-14 20:27:20.769683+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0132 | 2026-11-14 20:27:21.817456+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0133 | 2026-11-14 20:27:22.867990+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0134 | 2026-11-14 20:27:23.918338+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0135 | 2026-11-14 20:27:24.967253+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0136 | 2026-11-14 20:27:26.017460+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0137 | 2026-11-14 20:27:27.065570+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0138 | 2026-11-14 20:27:28.113760+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0139 | 2026-11-14 20:27:29.163486+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0140 | 2026-11-14 20:27:30.211922+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0141 | 2026-11-14 20:27:31.262193+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0142 | 2026-11-14 20:27:32.311862+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0143 | 2026-11-14 20:27:33.359470+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0144 | 2026-11-14 20:27:34.410069+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0145 | 2026-11-14 20:27:35.458131+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0146 | 2026-11-14 20:27:36.505858+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0147 | 2026-11-14 20:27:37.554060+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0148 | 2026-11-14 20:27:38.605675+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0149 | 2026-11-14 20:27:39.654068+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0150 | 2026-11-14 20:27:40.702618+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0151 | 2026-11-14 20:27:41.753760+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0152 | 2026-11-14 20:27:42.802546+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0153 | 2026-11-14 20:27:43.851022+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0154 | 2026-11-14 20:27:44.904184+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0155 | 2026-11-14 20:27:45.963534+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0156 | 2026-11-14 20:27:47.013356+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0157 | 2026-11-14 20:27:48.069721+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0158 | 2026-11-14 20:27:49.118331+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0159 | 2026-11-14 20:27:50.166686+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0160 | 2026-11-14 20:27:51.216011+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0161 | 2026-11-14 20:27:52.263276+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0162 | 2026-11-14 20:27:53.311058+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0163 | 2026-11-14 20:27:54.359368+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0164 | 2026-11-14 20:27:55.407231+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0165 | 2026-11-14 20:27:56.463437+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0166 | 2026-11-14 20:27:57.518532+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0167 | 2026-11-14 20:27:58.568071+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0168 | 2026-11-14 20:27:59.621732+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0169 | 2026-11-14 20:28:00.674918+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0170 | 2026-11-14 20:28:01.722255+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0171 | 2026-11-14 20:28:02.772243+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0172 | 2026-11-14 20:28:03.820708+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0173 | 2026-11-14 20:28:04.869061+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0174 | 2026-11-14 20:28:05.920409+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0175 | 2026-11-14 20:28:06.973210+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0176 | 2026-11-14 20:28:08.021573+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0177 | 2026-11-14 20:28:09.072944+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0178 | 2026-11-14 20:28:10.119920+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0179 | 2026-11-14 20:28:11.170362+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0180 | 2026-11-14 20:28:12.217878+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0181 | 2026-11-14 20:29:23.576988+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0182 | 2026-11-14 20:29:24.625521+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0183 | 2026-11-14 20:29:25.675148+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0184 | 2026-11-14 20:29:26.723193+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0185 | 2026-11-14 20:29:27.773898+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0186 | 2026-11-14 20:29:28.821124+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0187 | 2026-11-14 20:29:29.868244+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0188 | 2026-11-14 20:29:30.923615+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0189 | 2026-11-14 20:29:31.976708+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0190 | 2026-11-14 20:29:33.023414+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0191 | 2026-11-14 20:29:34.073536+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0192 | 2026-11-14 20:29:35.124912+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0193 | 2026-11-14 20:29:36.174839+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0194 | 2026-11-14 20:29:37.225634+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0195 | 2026-11-14 20:29:38.275435+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0196 | 2026-11-14 20:29:39.322783+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0197 | 2026-11-14 20:29:40.373586+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0198 | 2026-11-14 20:29:41.421173+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0199 | 2026-11-14 20:29:42.471109+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0200 | 2026-11-14 20:29:43.520822+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0201 | 2026-11-14 20:29:44.570852+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0202 | 2026-11-14 20:29:45.618481+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0203 | 2026-11-14 20:29:46.665743+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0204 | 2026-11-14 20:29:47.716163+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0205 | 2026-11-14 20:29:48.764990+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0206 | 2026-11-14 20:29:49.812436+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0207 | 2026-11-14 20:29:50.859878+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0208 | 2026-11-14 20:29:51.915744+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0209 | 2026-11-14 20:29:52.969699+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0210 | 2026-11-14 20:29:54.017423+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0211 | 2026-11-14 20:29:55.066817+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0212 | 2026-11-14 20:29:56.114664+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0213 | 2026-11-14 20:29:57.161960+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0214 | 2026-11-14 20:29:58.209422+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0215 | 2026-11-14 20:29:59.258191+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0216 | 2026-11-14 20:30:00.304501+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0217 | 2026-11-14 20:30:01.351518+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0218 | 2026-11-14 20:30:02.399005+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0219 | 2026-11-14 20:30:03.445741+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0220 | 2026-11-14 20:30:04.498522+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0221 | 2026-11-14 20:30:05.548117+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0222 | 2026-11-14 20:30:06.595745+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0223 | 2026-11-14 20:30:07.646738+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0224 | 2026-11-14 20:30:08.694554+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0225 | 2026-11-14 20:30:09.744262+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0226 | 2026-11-14 20:30:10.791532+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0227 | 2026-11-14 20:30:11.844222+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0228 | 2026-11-14 20:30:12.892590+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0229 | 2026-11-14 20:30:13.939907+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0230 | 2026-11-14 20:30:14.991802+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0231 | 2026-11-14 20:30:16.038784+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0232 | 2026-11-14 20:30:17.085755+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0233 | 2026-11-14 20:30:18.132950+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0234 | 2026-11-14 20:30:19.180747+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0235 | 2026-11-14 20:30:20.228649+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0236 | 2026-11-14 20:30:21.275018+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0237 | 2026-11-14 20:30:22.322973+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0238 | 2026-11-14 20:30:23.369062+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0239 | 2026-11-14 20:30:24.416552+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0240 | 2026-11-14 20:30:25.470677+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0241 | 2026-11-14 20:30:26.521119+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0242 | 2026-11-14 20:30:27.575494+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0243 | 2026-11-14 20:30:28.626267+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0244 | 2026-11-14 20:30:29.675947+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0245 | 2026-11-14 20:30:30.723354+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0246 | 2026-11-14 20:30:31.770340+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0247 | 2026-11-14 20:30:32.817495+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0248 | 2026-11-14 20:30:33.864863+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0249 | 2026-11-14 20:30:34.912163+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0250 | 2026-11-14 20:30:35.963016+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0251 | 2026-11-14 20:30:37.013054+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0252 | 2026-11-14 20:30:38.071419+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0253 | 2026-11-14 20:30:39.118391+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0254 | 2026-11-14 20:30:40.174699+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0255 | 2026-11-14 20:30:41.221348+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0256 | 2026-11-14 20:30:42.269407+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0257 | 2026-11-14 20:30:43.317263+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0258 | 2026-11-14 20:30:44.365097+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0259 | 2026-11-14 20:30:45.412761+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0260 | 2026-11-14 20:30:46.460207+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0261 | 2026-11-14 20:30:47.508000+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0262 | 2026-11-14 20:30:48.557235+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0263 | 2026-11-14 20:30:49.604629+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0264 | 2026-11-14 20:30:50.658719+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0265 | 2026-11-14 20:30:51.706050+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0266 | 2026-11-14 20:30:52.753664+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0267 | 2026-11-14 20:30:53.804148+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0268 | 2026-11-14 20:30:54.853243+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0269 | 2026-11-14 20:30:55.901615+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0270 | 2026-11-14 20:30:56.954529+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0271 | 2026-11-14 20:31:23.530230+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0272 | 2026-11-14 20:31:25.576468+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0273 | 2026-11-14 20:31:27.622368+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0274 | 2026-11-14 20:31:29.667084+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0275 | 2026-11-14 20:31:31.711730+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0276 | 2026-11-14 20:31:33.757447+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0277 | 2026-11-14 20:31:35.803285+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0278 | 2026-11-14 20:31:37.849362+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0279 | 2026-11-14 20:31:39.894872+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0280 | 2026-11-14 20:31:41.940705+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0281 | 2026-11-14 20:31:43.986369+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0282 | 2026-11-14 20:31:46.031162+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0283 | 2026-11-14 20:31:48.076709+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0284 | 2026-11-14 20:31:50.122370+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0285 | 2026-11-14 20:31:52.167142+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0286 | 2026-11-14 20:31:54.212847+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0287 | 2026-11-14 20:31:56.259409+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0288 | 2026-11-14 20:31:58.303900+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0289 | 2026-11-14 20:32:00.351372+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0290 | 2026-11-14 20:32:02.396282+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0291 | 2026-11-14 20:32:04.441915+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0292 | 2026-11-14 20:32:06.488064+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0293 | 2026-11-14 20:32:07.488602+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0294 | 2026-11-14 20:32:08.533519+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0295 | 2026-11-14 20:32:10.578676+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0296 | 2026-11-14 20:32:12.624266+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0297 | 2026-11-14 20:32:14.670322+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0298 | 2026-11-14 20:32:16.715641+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0299 | 2026-11-14 20:32:18.762409+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0300 | 2026-11-14 20:32:20.806514+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0301 | 2026-11-14 20:32:22.851996+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0302 | 2026-11-14 20:32:24.898207+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0303 | 2026-11-14 20:32:26.944237+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0304 | 2026-11-14 20:32:28.989740+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0305 | 2026-11-14 20:32:31.034684+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0306 | 2026-11-14 20:32:33.080876+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0307 | 2026-11-14 20:32:35.125835+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0308 | 2026-11-14 20:32:37.171144+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0309 | 2026-11-14 20:32:39.216396+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0310 | 2026-11-14 20:32:41.261863+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0311 | 2026-11-14 20:32:43.307531+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0312 | 2026-11-14 20:32:45.352840+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0313 | 2026-11-14 20:32:47.398649+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0314 | 2026-11-14 20:32:49.444453+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0315 | 2026-11-14 20:32:51.489591+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0316 | 2026-11-14 20:32:53.534775+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0317 | 2026-11-14 20:32:55.580425+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0318 | 2026-11-14 20:32:57.627826+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0319 | 2026-11-14 20:32:59.672477+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0320 | 2026-11-14 20:33:01.719376+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0321 | 2026-11-14 20:33:03.763038+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0322 | 2026-11-14 20:33:05.808697+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0323 | 2026-11-14 20:33:07.854395+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0324 | 2026-11-14 20:33:09.899592+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0325 | 2026-11-14 20:33:11.945498+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0326 | 2026-11-14 20:33:13.990911+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0327 | 2026-11-14 20:33:16.037254+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0328 | 2026-11-14 20:33:18.083500+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0329 | 2026-11-14 20:33:20.130080+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0330 | 2026-11-14 20:33:22.174764+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0331 | 2026-11-14 20:33:24.220686+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0332 | 2026-11-14 20:33:26.269230+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0333 | 2026-11-14 20:33:28.314630+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0334 | 2026-11-14 20:33:30.359510+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0335 | 2026-11-14 20:33:32.405221+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0336 | 2026-11-14 20:33:34.450892+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0337 | 2026-11-14 20:33:36.496371+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0338 | 2026-11-14 20:33:38.542404+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0339 | 2026-11-14 20:33:40.588456+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0340 | 2026-11-14 20:33:42.634369+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0341 | 2026-11-14 20:33:44.679361+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0342 | 2026-11-14 20:33:46.724771+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0343 | 2026-11-14 20:33:48.770023+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0344 | 2026-11-14 20:33:50.815800+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0345 | 2026-11-14 20:33:52.862422+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0346 | 2026-11-14 20:33:54.907588+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0347 | 2026-11-14 20:33:56.953371+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0348 | 2026-11-14 20:33:58.998911+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0349 | 2026-11-14 20:34:01.044286+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0350 | 2026-11-14 20:34:03.090406+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0351 | 2026-11-14 20:34:05.135279+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0352 | 2026-11-14 20:34:07.180669+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0353 | 2026-11-14 20:34:09.225625+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0354 | 2026-11-14 20:34:11.270756+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0355 | 2026-11-14 20:34:13.315791+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0356 | 2026-11-14 20:34:15.361304+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0357 | 2026-11-14 20:34:17.407489+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0358 | 2026-11-14 20:34:19.452979+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0359 | 2026-11-14 20:34:21.498808+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0360 | 2026-11-14 20:34:23.544093+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0361 | 2026-11-14 20:34:25.588864+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |

---

## Defensive Recommendations & Containment Actions
1. **Inbound ACL Enforcement:** Restrict port 502 to authorized engineering workstations only; review write traffic from `10.0.1.10`, `10.0.1.20`.
2. **Suricata DPI Rule Tuning:** Enforce Modbus rule SID 1000004 to drop state-altering function codes (`FC05`, `FC06`, `FC15`, `FC16`) originating outside the Control Zone.
3. **Machine Learning Anomaly Quarantine:** Ingest high-threat events into `ml_detector.py` to trigger automated microsegmentation isolation.