# OT Cyber-Physical Incident Triage & Timeline Report
**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)
**Generated Date:** 2026-11-20 18:34:23 UTC
**Lead Security Architect:** Rachid Afaf

---
## Executive Incident Summary
During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, 
the normalization pipeline analyzed **493 Modbus TCP telemetry frames** and **92 firewall drop records** 
between `2026-11-15T00:00:27.860902+00:00` and `2026-11-15T00:16:56.997236+00:00` (UTC).
The analysis isolated **407 state-altering write command attempts** from `10.0.1.10`, `10.0.1.20` targeting `10.0.3.10` (port 502), 
**0 protocol exception responses**, and **92 firewall drops** of traffic from `10.0.1.20`.

### Key Metrics Breakdown
- **Total Telemetry Ingested:** 585 records
- **Read Commands (Polling):** 86 (0.21 Read/Write Ratio)
- **State-Altering Write Commands:** 407
- **Modbus Protocol Exceptions:** 0
- **Firewall Drops:** 92
- **High-Threat Incident Alerts (Score >= 75):** 196

---
## Chronological Incident Event Timeline

| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| MODBUS-EVT-0001 | 2026-11-15 00:00:27.860902+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0002 | 2026-11-15 00:00:28.909275+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0003 | 2026-11-15 00:00:29.956747+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0004 | 2026-11-15 00:00:31.008685+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0005 | 2026-11-15 00:00:32.057085+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0006 | 2026-11-15 00:00:33.105081+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0007 | 2026-11-15 00:00:34.152435+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0008 | 2026-11-15 00:00:35.200524+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0009 | 2026-11-15 00:00:36.248402+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0010 | 2026-11-15 00:00:37.296093+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0011 | 2026-11-15 00:00:38.344516+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0012 | 2026-11-15 00:00:39.392153+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0013 | 2026-11-15 00:00:40.440591+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0014 | 2026-11-15 00:00:41.488618+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0015 | 2026-11-15 00:00:42.536072+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0016 | 2026-11-15 00:00:43.586621+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0017 | 2026-11-15 00:00:44.634201+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0018 | 2026-11-15 00:00:45.689119+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0019 | 2026-11-15 00:00:46.743456+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0020 | 2026-11-15 00:00:47.792466+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0021 | 2026-11-15 00:00:48.841551+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0022 | 2026-11-15 00:00:49.889841+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0023 | 2026-11-15 00:00:50.941550+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0024 | 2026-11-15 00:00:51.988614+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0025 | 2026-11-15 00:00:53.036811+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0026 | 2026-11-15 00:00:54.084864+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0027 | 2026-11-15 00:00:55.133204+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0028 | 2026-11-15 00:00:56.186206+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0029 | 2026-11-15 00:00:57.242388+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0030 | 2026-11-15 00:00:58.290195+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0031 | 2026-11-15 00:00:59.337066+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0032 | 2026-11-15 00:01:00.384321+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0033 | 2026-11-15 00:01:01.433191+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0034 | 2026-11-15 00:01:02.481257+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0035 | 2026-11-15 00:01:03.528713+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0036 | 2026-11-15 00:01:04.582333+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0037 | 2026-11-15 00:01:05.630303+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0038 | 2026-11-15 00:01:06.681290+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0039 | 2026-11-15 00:01:07.736538+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0040 | 2026-11-15 00:01:08.786989+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0041 | 2026-11-15 00:01:09.835507+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0042 | 2026-11-15 00:01:10.884038+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0043 | 2026-11-15 00:01:10.912438+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0044 | 2026-11-15 00:01:10.938278+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0045 | 2026-11-15 00:01:10.963658+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0046 | 2026-11-15 00:01:10.989869+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0047 | 2026-11-15 00:01:11.018280+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0048 | 2026-11-15 00:01:11.044104+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0049 | 2026-11-15 00:01:11.069254+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0050 | 2026-11-15 00:01:11.094931+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0051 | 2026-11-15 00:01:11.123272+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0052 | 2026-11-15 00:01:11.148921+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0053 | 2026-11-15 00:01:11.176440+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0054 | 2026-11-15 00:01:11.205016+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0055 | 2026-11-15 00:01:11.230835+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0056 | 2026-11-15 00:01:11.256648+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0057 | 2026-11-15 00:01:11.286108+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0058 | 2026-11-15 00:01:11.312206+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0059 | 2026-11-15 00:01:11.343245+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0060 | 2026-11-15 00:01:11.368992+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0061 | 2026-11-15 00:01:11.394371+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0062 | 2026-11-15 00:01:11.420129+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0063 | 2026-11-15 00:01:11.446646+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0064 | 2026-11-15 00:01:11.472814+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0065 | 2026-11-15 00:01:11.500036+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0066 | 2026-11-15 00:01:11.525680+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0067 | 2026-11-15 00:01:11.550885+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0068 | 2026-11-15 00:01:11.576759+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0069 | 2026-11-15 00:01:11.602848+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0070 | 2026-11-15 00:01:11.628282+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0071 | 2026-11-15 00:01:11.653822+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0072 | 2026-11-15 00:01:12.722702+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0073 | 2026-11-15 00:01:13.770192+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0074 | 2026-11-15 00:01:14.820155+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0075 | 2026-11-15 00:01:15.872744+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0076 | 2026-11-15 00:01:16.921207+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0077 | 2026-11-15 00:01:17.968046+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0078 | 2026-11-15 00:01:19.017316+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0079 | 2026-11-15 00:01:20.064487+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0080 | 2026-11-15 00:01:21.111445+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0081 | 2026-11-15 00:01:22.158728+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0082 | 2026-11-15 00:01:23.208262+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0083 | 2026-11-15 00:01:24.256618+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0084 | 2026-11-15 00:01:25.308372+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0085 | 2026-11-15 00:01:26.357311+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0086 | 2026-11-15 00:01:27.407579+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0087 | 2026-11-15 00:01:28.458850+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0088 | 2026-11-15 00:01:29.507075+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0089 | 2026-11-15 00:01:30.554271+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0090 | 2026-11-15 00:01:31.603249+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0091 | 2026-11-15 00:01:32.652596+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0092 | 2026-11-15 00:01:33.703366+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0093 | 2026-11-15 00:01:34.751796+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0094 | 2026-11-15 00:01:35.809640+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0095 | 2026-11-15 00:01:36.859740+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0096 | 2026-11-15 00:01:37.913640+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0097 | 2026-11-15 00:01:38.961442+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0098 | 2026-11-15 00:01:40.008807+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0099 | 2026-11-15 00:01:41.057357+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0100 | 2026-11-15 00:01:42.105542+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0101 | 2026-11-15 00:01:43.153643+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0102 | 2026-11-15 00:01:44.200728+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0103 | 2026-11-15 00:01:45.253545+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0104 | 2026-11-15 00:01:46.302861+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0105 | 2026-11-15 00:01:47.351070+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0106 | 2026-11-15 00:01:48.399411+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0107 | 2026-11-15 00:01:49.447909+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0108 | 2026-11-15 00:01:50.495807+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0109 | 2026-11-15 00:01:51.544606+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0110 | 2026-11-15 00:01:52.592777+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0111 | 2026-11-15 00:01:53.641249+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0112 | 2026-11-15 00:01:54.692135+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0113 | 2026-11-15 00:01:55.742494+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0114 | 2026-11-15 00:01:56.794710+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0115 | 2026-11-15 00:01:57.844040+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0116 | 2026-11-15 00:01:58.892067+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0117 | 2026-11-15 00:01:59.940238+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0118 | 2026-11-15 00:02:00.988561+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0119 | 2026-11-15 00:02:02.036108+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0120 | 2026-11-15 00:02:03.089621+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0121 | 2026-11-15 00:02:04.139479+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0122 | 2026-11-15 00:02:05.187190+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0123 | 2026-11-15 00:02:05.213692+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0124 | 2026-11-15 00:02:05.243389+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0125 | 2026-11-15 00:02:05.269384+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0126 | 2026-11-15 00:02:05.296589+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0127 | 2026-11-15 00:02:05.321926+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0128 | 2026-11-15 00:02:05.348607+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0129 | 2026-11-15 00:02:05.375327+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0130 | 2026-11-15 00:02:05.401089+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0131 | 2026-11-15 00:02:05.427224+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0132 | 2026-11-15 00:02:05.454594+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0133 | 2026-11-15 00:02:05.480333+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0134 | 2026-11-15 00:02:05.509005+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0135 | 2026-11-15 00:02:05.534906+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0136 | 2026-11-15 00:02:05.560597+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0137 | 2026-11-15 00:02:05.587719+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0138 | 2026-11-15 00:02:05.613206+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0139 | 2026-11-15 00:02:05.639188+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0140 | 2026-11-15 00:02:05.668973+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0141 | 2026-11-15 00:02:05.695254+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0142 | 2026-11-15 00:02:05.721568+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0143 | 2026-11-15 00:02:05.747900+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0144 | 2026-11-15 00:02:05.773389+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0145 | 2026-11-15 00:02:05.799187+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0146 | 2026-11-15 00:02:05.824723+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0147 | 2026-11-15 00:02:05.851489+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0148 | 2026-11-15 00:02:05.881162+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0149 | 2026-11-15 00:02:05.907617+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0150 | 2026-11-15 00:02:05.933109+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0151 | 2026-11-15 00:02:05.958680+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0152 | 2026-11-15 00:02:25.694518+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0153 | 2026-11-15 00:02:26.744483+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0154 | 2026-11-15 00:02:27.800047+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0155 | 2026-11-15 00:02:28.849298+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0156 | 2026-11-15 00:02:29.898388+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0157 | 2026-11-15 00:02:30.945639+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0158 | 2026-11-15 00:02:31.995538+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0159 | 2026-11-15 00:02:33.048838+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0160 | 2026-11-15 00:02:34.100182+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0161 | 2026-11-15 00:02:35.148488+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0162 | 2026-11-15 00:02:36.197319+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0163 | 2026-11-15 00:02:37.246125+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0164 | 2026-11-15 00:02:38.299323+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0165 | 2026-11-15 00:02:39.346699+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0166 | 2026-11-15 00:02:40.397825+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0167 | 2026-11-15 00:02:41.446199+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0168 | 2026-11-15 00:02:42.495023+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0169 | 2026-11-15 00:02:43.546623+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0170 | 2026-11-15 00:02:44.594487+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0171 | 2026-11-15 00:02:45.645353+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0172 | 2026-11-15 00:02:46.697217+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0173 | 2026-11-15 00:02:47.749461+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0174 | 2026-11-15 00:02:48.799124+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0175 | 2026-11-15 00:02:49.846867+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0176 | 2026-11-15 00:02:50.898903+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0177 | 2026-11-15 00:02:51.951782+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0178 | 2026-11-15 00:02:52.999564+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0179 | 2026-11-15 00:02:54.048383+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0180 | 2026-11-15 00:02:55.096998+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0181 | 2026-11-15 00:02:56.146085+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0182 | 2026-11-15 00:02:57.198923+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0183 | 2026-11-15 00:02:58.246730+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0184 | 2026-11-15 00:02:59.296146+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0185 | 2026-11-15 00:03:00.344318+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0186 | 2026-11-15 00:03:01.395482+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0187 | 2026-11-15 00:03:02.443701+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0188 | 2026-11-15 00:03:03.497850+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0189 | 2026-11-15 00:03:04.551070+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0190 | 2026-11-15 00:03:05.600378+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0191 | 2026-11-15 00:03:06.651117+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0192 | 2026-11-15 00:03:07.701643+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0193 | 2026-11-15 00:03:08.750955+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0194 | 2026-11-15 00:03:09.800254+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0195 | 2026-11-15 00:03:10.849607+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0196 | 2026-11-15 00:03:11.905621+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0197 | 2026-11-15 00:03:12.954981+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0198 | 2026-11-15 00:03:14.007587+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0199 | 2026-11-15 00:03:15.057003+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0200 | 2026-11-15 00:03:16.105513+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0201 | 2026-11-15 00:03:17.153825+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0202 | 2026-11-15 00:03:18.201832+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0203 | 2026-11-15 00:03:19.250387+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0204 | 2026-11-15 00:03:20.298595+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0205 | 2026-11-15 00:03:21.346898+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0206 | 2026-11-15 00:03:22.395610+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0207 | 2026-11-15 00:03:23.445023+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0208 | 2026-11-15 00:03:24.494769+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0209 | 2026-11-15 00:03:25.545943+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0210 | 2026-11-15 00:03:26.599502+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0211 | 2026-11-15 00:03:27.648540+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0212 | 2026-11-15 00:03:28.700270+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0213 | 2026-11-15 00:03:29.752616+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0214 | 2026-11-15 00:03:30.804089+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0215 | 2026-11-15 00:03:31.855299+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0216 | 2026-11-15 00:03:32.904223+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0217 | 2026-11-15 00:03:33.954238+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0218 | 2026-11-15 00:03:35.002948+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0219 | 2026-11-15 00:03:36.051317+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0220 | 2026-11-15 00:03:37.099529+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0221 | 2026-11-15 00:03:38.148327+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0222 | 2026-11-15 00:03:39.196883+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0223 | 2026-11-15 00:03:40.245817+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0224 | 2026-11-15 00:03:41.294571+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0225 | 2026-11-15 00:03:42.344370+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0226 | 2026-11-15 00:03:43.401628+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0227 | 2026-11-15 00:03:44.451142+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0228 | 2026-11-15 00:03:45.501603+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0229 | 2026-11-15 00:03:46.550813+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0230 | 2026-11-15 00:03:47.600570+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0231 | 2026-11-15 00:03:48.649938+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0232 | 2026-11-15 00:03:49.702014+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0233 | 2026-11-15 00:03:50.751178+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0234 | 2026-11-15 00:03:51.807099+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0235 | 2026-11-15 00:03:52.855467+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0236 | 2026-11-15 00:03:53.912401+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0237 | 2026-11-15 00:03:54.965673+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0238 | 2026-11-15 00:03:56.014771+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0239 | 2026-11-15 00:03:57.063486+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0240 | 2026-11-15 00:03:58.112390+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0241 | 2026-11-15 00:03:59.162055+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0242 | 2026-11-15 00:05:47.043093+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0243 | 2026-11-15 00:05:48.092760+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0244 | 2026-11-15 00:05:49.142839+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0245 | 2026-11-15 00:05:50.192210+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0246 | 2026-11-15 00:05:51.241032+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0247 | 2026-11-15 00:05:52.289946+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0248 | 2026-11-15 00:05:53.337829+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0249 | 2026-11-15 00:05:54.385041+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0250 | 2026-11-15 00:05:55.433816+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0251 | 2026-11-15 00:05:56.486773+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0252 | 2026-11-15 00:05:57.543021+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0253 | 2026-11-15 00:05:58.592429+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0254 | 2026-11-15 00:05:59.641740+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0255 | 2026-11-15 00:06:00.689651+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0256 | 2026-11-15 00:06:01.740258+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0257 | 2026-11-15 00:06:02.788547+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0258 | 2026-11-15 00:06:03.837117+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0259 | 2026-11-15 00:06:04.890095+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0260 | 2026-11-15 00:06:05.940959+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0261 | 2026-11-15 00:06:06.988974+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0262 | 2026-11-15 00:06:08.041019+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0263 | 2026-11-15 00:06:09.089031+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0264 | 2026-11-15 00:06:10.136962+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0265 | 2026-11-15 00:06:11.184066+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0266 | 2026-11-15 00:06:12.232777+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0267 | 2026-11-15 00:06:13.280868+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0268 | 2026-11-15 00:06:14.330322+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0269 | 2026-11-15 00:06:15.380547+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0270 | 2026-11-15 00:06:16.432942+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0271 | 2026-11-15 00:06:17.480625+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0272 | 2026-11-15 00:06:18.529768+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0273 | 2026-11-15 00:06:19.582896+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0274 | 2026-11-15 00:06:20.630600+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0275 | 2026-11-15 00:06:21.678771+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0276 | 2026-11-15 00:06:22.726100+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0277 | 2026-11-15 00:06:23.773313+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0278 | 2026-11-15 00:06:24.820459+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0279 | 2026-11-15 00:06:25.868010+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0280 | 2026-11-15 00:06:26.926995+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0281 | 2026-11-15 00:06:27.978653+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0282 | 2026-11-15 00:06:29.030622+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0283 | 2026-11-15 00:06:30.078661+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0284 | 2026-11-15 00:06:31.128977+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0285 | 2026-11-15 00:06:32.184537+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0286 | 2026-11-15 00:06:33.231895+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0287 | 2026-11-15 00:06:34.281753+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0288 | 2026-11-15 00:06:35.329112+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0289 | 2026-11-15 00:06:36.376668+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0290 | 2026-11-15 00:06:37.428193+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0291 | 2026-11-15 00:06:38.476832+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0292 | 2026-11-15 00:06:39.526457+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0293 | 2026-11-15 00:06:39.553616+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0294 | 2026-11-15 00:06:39.580348+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0295 | 2026-11-15 00:06:39.606268+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0296 | 2026-11-15 00:06:39.634122+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0297 | 2026-11-15 00:06:39.659313+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0298 | 2026-11-15 00:06:39.689170+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0299 | 2026-11-15 00:06:39.716877+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0300 | 2026-11-15 00:06:39.743572+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0301 | 2026-11-15 00:06:39.769399+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0302 | 2026-11-15 00:06:39.796357+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0303 | 2026-11-15 00:06:39.822268+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0304 | 2026-11-15 00:06:39.849126+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0305 | 2026-11-15 00:06:39.874861+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0306 | 2026-11-15 00:06:39.901646+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0307 | 2026-11-15 00:06:39.928299+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0308 | 2026-11-15 00:06:39.954567+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0309 | 2026-11-15 00:06:39.980994+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0310 | 2026-11-15 00:06:40.007726+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0311 | 2026-11-15 00:06:40.034319+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0312 | 2026-11-15 00:06:40.060412+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0313 | 2026-11-15 00:06:40.086581+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0314 | 2026-11-15 00:06:40.113146+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0315 | 2026-11-15 00:06:40.138999+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0316 | 2026-11-15 00:06:40.166043+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0317 | 2026-11-15 00:06:40.191653+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0318 | 2026-11-15 00:06:40.217844+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0319 | 2026-11-15 00:06:40.244995+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0320 | 2026-11-15 00:06:40.274267+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0321 | 2026-11-15 00:06:40.300510+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0322 | 2026-11-15 00:06:41.369381+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0323 | 2026-11-15 00:06:42.417283+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0324 | 2026-11-15 00:06:43.470136+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0325 | 2026-11-15 00:06:44.518464+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0326 | 2026-11-15 00:06:45.566863+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0327 | 2026-11-15 00:06:46.615817+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0328 | 2026-11-15 00:06:47.665656+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0329 | 2026-11-15 00:06:48.715787+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0330 | 2026-11-15 00:06:49.763993+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0331 | 2026-11-15 00:06:50.822551+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0332 | 2026-11-15 00:06:51.872879+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0333 | 2026-11-15 00:06:52.921274+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0334 | 2026-11-15 00:06:53.972796+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0335 | 2026-11-15 00:06:55.023122+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0336 | 2026-11-15 00:06:56.072298+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0337 | 2026-11-15 00:06:57.122943+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0338 | 2026-11-15 00:06:58.171917+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0339 | 2026-11-15 00:06:59.220834+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0340 | 2026-11-15 00:07:00.273332+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0341 | 2026-11-15 00:07:01.321481+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0342 | 2026-11-15 00:07:02.369457+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0343 | 2026-11-15 00:07:03.422092+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0344 | 2026-11-15 00:07:04.470182+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0345 | 2026-11-15 00:07:05.520574+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0346 | 2026-11-15 00:07:06.570949+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0347 | 2026-11-15 00:07:07.619780+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0348 | 2026-11-15 00:07:08.668525+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0349 | 2026-11-15 00:07:09.716380+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0350 | 2026-11-15 00:07:10.764216+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0351 | 2026-11-15 00:07:11.817636+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0352 | 2026-11-15 00:07:12.865766+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0353 | 2026-11-15 00:07:13.914300+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0354 | 2026-11-15 00:07:14.962470+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0355 | 2026-11-15 00:07:16.010473+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0356 | 2026-11-15 00:07:17.058557+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0357 | 2026-11-15 00:07:18.110661+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0358 | 2026-11-15 00:07:19.159606+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0359 | 2026-11-15 00:07:20.207369+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0360 | 2026-11-15 00:07:21.256047+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0361 | 2026-11-15 00:07:22.303786+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0362 | 2026-11-15 00:07:23.351733+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0363 | 2026-11-15 00:07:24.399045+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0364 | 2026-11-15 00:07:25.449159+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0365 | 2026-11-15 00:07:26.496918+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0366 | 2026-11-15 00:07:27.555671+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0367 | 2026-11-15 00:07:28.605213+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0368 | 2026-11-15 00:07:29.652838+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0369 | 2026-11-15 00:07:30.701936+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0370 | 2026-11-15 00:07:31.751821+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0371 | 2026-11-15 00:07:32.800664+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0372 | 2026-11-15 00:07:33.849143+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0373 | 2026-11-15 00:07:33.874773+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0374 | 2026-11-15 00:07:33.903123+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0375 | 2026-11-15 00:07:33.931004+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0376 | 2026-11-15 00:07:33.957217+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0377 | 2026-11-15 00:07:33.983087+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0378 | 2026-11-15 00:07:34.009117+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0379 | 2026-11-15 00:07:34.035217+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0380 | 2026-11-15 00:07:34.060286+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0381 | 2026-11-15 00:07:34.086037+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0382 | 2026-11-15 00:07:34.112157+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0383 | 2026-11-15 00:07:34.137644+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0384 | 2026-11-15 00:07:34.164043+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0385 | 2026-11-15 00:07:34.190670+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0386 | 2026-11-15 00:07:34.217151+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0387 | 2026-11-15 00:07:34.243687+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0388 | 2026-11-15 00:07:34.270495+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0389 | 2026-11-15 00:07:34.295796+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0390 | 2026-11-15 00:07:34.322966+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0391 | 2026-11-15 00:07:34.350550+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0392 | 2026-11-15 00:07:34.376287+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0393 | 2026-11-15 00:07:34.401991+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0394 | 2026-11-15 00:07:34.427449+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0395 | 2026-11-15 00:07:34.453675+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0396 | 2026-11-15 00:07:34.479894+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0397 | 2026-11-15 00:07:34.506666+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0398 | 2026-11-15 00:07:34.533263+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0399 | 2026-11-15 00:07:34.559758+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0400 | 2026-11-15 00:07:34.585570+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0401 | 2026-11-15 00:07:34.612629+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0402 | 2026-11-15 00:07:35.683338+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0403 | 2026-11-15 00:07:36.731802+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0404 | 2026-11-15 00:07:37.780084+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0405 | 2026-11-15 00:07:38.831514+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0406 | 2026-11-15 00:07:39.880717+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0407 | 2026-11-15 00:07:40.937415+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0408 | 2026-11-15 00:07:41.985048+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0409 | 2026-11-15 00:07:43.033684+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0410 | 2026-11-15 00:07:44.082185+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0411 | 2026-11-15 00:07:45.132669+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0412 | 2026-11-15 00:07:46.181510+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0413 | 2026-11-15 00:07:47.229426+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0414 | 2026-11-15 00:07:48.281296+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0415 | 2026-11-15 00:07:49.329841+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0416 | 2026-11-15 00:07:50.377161+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0417 | 2026-11-15 00:07:51.427014+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0418 | 2026-11-15 00:07:52.477642+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0419 | 2026-11-15 00:07:53.526802+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0420 | 2026-11-15 00:07:54.574884+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0421 | 2026-11-15 00:07:55.623192+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0422 | 2026-11-15 00:07:56.671869+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0423 | 2026-11-15 00:07:57.720166+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0424 | 2026-11-15 00:07:58.778773+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0425 | 2026-11-15 00:07:59.826533+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0426 | 2026-11-15 00:08:00.880032+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0427 | 2026-11-15 00:08:01.931000+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0428 | 2026-11-15 00:08:02.983238+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0429 | 2026-11-15 00:08:04.032771+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0430 | 2026-11-15 00:08:05.079982+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0431 | 2026-11-15 00:08:06.128156+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0432 | 2026-11-15 00:08:07.176662+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0433 | 2026-11-15 00:08:08.225643+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0434 | 2026-11-15 00:08:09.273685+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0435 | 2026-11-15 00:08:10.322134+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0436 | 2026-11-15 00:08:11.370691+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0437 | 2026-11-15 00:08:12.419117+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0438 | 2026-11-15 00:08:13.466751+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0439 | 2026-11-15 00:08:14.514986+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0440 | 2026-11-15 00:08:15.563913+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0441 | 2026-11-15 00:08:16.612692+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0442 | 2026-11-15 00:08:17.661828+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0443 | 2026-11-15 00:08:18.710173+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=0 qty=10` [None] |
| MODBUS-EVT-0444 | 2026-11-15 00:08:19.758121+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0445 | 2026-11-15 00:08:20.812073+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0446 | 2026-11-15 00:08:21.866997+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0447 | 2026-11-15 00:08:22.915843+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0448 | 2026-11-15 00:08:23.964969+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=600 qty=1 vals=[50]` [None] |
| MODBUS-EVT-0449 | 2026-11-15 00:08:25.013354+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=2 qty=1 vals=[65000]` [None] |
| MODBUS-EVT-0450 | 2026-11-15 00:08:26.065105+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=0 qty=3 vals=[50, 65000, 90]` [None] |
| MODBUS-EVT-0451 | 2026-11-15 00:08:27.114441+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=20 qty=1 vals=[10]` [None] |
| MODBUS-EVT-0452 | 2026-11-15 00:08:28.162648+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0453 | 2026-11-15 00:08:28.189903+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0454 | 2026-11-15 00:08:28.216641+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0455 | 2026-11-15 00:08:28.242977+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0456 | 2026-11-15 00:08:28.269586+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0457 | 2026-11-15 00:08:28.295741+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0458 | 2026-11-15 00:08:28.321930+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0459 | 2026-11-15 00:08:28.347812+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0460 | 2026-11-15 00:08:28.374697+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0461 | 2026-11-15 00:08:28.401816+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0462 | 2026-11-15 00:08:28.428633+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0463 | 2026-11-15 00:08:28.454193+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0464 | 2026-11-15 00:08:28.482334+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0465 | 2026-11-15 00:08:28.510841+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0466 | 2026-11-15 00:08:28.537104+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0467 | 2026-11-15 00:08:28.563271+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0468 | 2026-11-15 00:08:28.589732+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0469 | 2026-11-15 00:08:28.616080+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0470 | 2026-11-15 00:08:28.644640+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0471 | 2026-11-15 00:08:28.671120+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0472 | 2026-11-15 00:08:28.700628+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0473 | 2026-11-15 00:08:28.727210+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0474 | 2026-11-15 00:08:28.753519+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0475 | 2026-11-15 00:08:28.780508+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0476 | 2026-11-15 00:08:28.807081+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0477 | 2026-11-15 00:08:28.833788+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0478 | 2026-11-15 00:08:28.860843+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0479 | 2026-11-15 00:08:28.886483+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0480 | 2026-11-15 00:08:28.913441+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0481 | 2026-11-15 00:08:28.939287+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[0]` [None] |
| MODBUS-EVT-0482 | 2026-11-15 00:08:46+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0483 | 2026-11-15 00:08:48+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0484 | 2026-11-15 00:08:50+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0485 | 2026-11-15 00:08:52+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0486 | 2026-11-15 00:08:54+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0487 | 2026-11-15 00:08:56+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0488 | 2026-11-15 00:08:58+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0489 | 2026-11-15 00:09:00+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0490 | 2026-11-15 00:09:02+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0491 | 2026-11-15 00:09:04+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0492 | 2026-11-15 00:09:07+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0493 | 2026-11-15 00:09:09+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0494 | 2026-11-15 00:09:11+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0495 | 2026-11-15 00:09:13+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0496 | 2026-11-15 00:09:15+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0497 | 2026-11-15 00:09:17+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0498 | 2026-11-15 00:09:19+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0499 | 2026-11-15 00:09:21+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0500 | 2026-11-15 00:09:23+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0501 | 2026-11-15 00:09:25+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0502 | 2026-11-15 00:09:27+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0503 | 2026-11-15 00:09:29+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0504 | 2026-11-15 00:09:31+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0505 | 2026-11-15 00:09:33+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0506 | 2026-11-15 00:09:35+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0507 | 2026-11-15 00:09:37+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0508 | 2026-11-15 00:09:39+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0509 | 2026-11-15 00:09:41+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0510 | 2026-11-15 00:09:43+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0511 | 2026-11-15 00:09:45+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0512 | 2026-11-15 00:09:47+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0513 | 2026-11-15 00:09:49+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0514 | 2026-11-15 00:09:52+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0515 | 2026-11-15 00:09:54+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0516 | 2026-11-15 00:09:56+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0517 | 2026-11-15 00:09:58+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0518 | 2026-11-15 00:10:00+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0519 | 2026-11-15 00:10:02+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0520 | 2026-11-15 00:10:04+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0521 | 2026-11-15 00:10:06+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0522 | 2026-11-15 00:10:08+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0523 | 2026-11-15 00:10:10+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0524 | 2026-11-15 00:10:12+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0525 | 2026-11-15 00:10:14+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0526 | 2026-11-15 00:10:16+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0527 | 2026-11-15 00:10:18+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0528 | 2026-11-15 00:10:20+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0529 | 2026-11-15 00:10:22+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0530 | 2026-11-15 00:10:24+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0531 | 2026-11-15 00:10:26+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0532 | 2026-11-15 00:10:28+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0533 | 2026-11-15 00:10:30+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0534 | 2026-11-15 00:10:32+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0535 | 2026-11-15 00:10:34+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0536 | 2026-11-15 00:10:37+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0537 | 2026-11-15 00:10:39+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0538 | 2026-11-15 00:10:41+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0539 | 2026-11-15 00:10:43+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0540 | 2026-11-15 00:10:45+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0541 | 2026-11-15 00:10:47+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0542 | 2026-11-15 00:10:49+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0543 | 2026-11-15 00:10:51+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0544 | 2026-11-15 00:10:53+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0545 | 2026-11-15 00:10:55+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0546 | 2026-11-15 00:10:57+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0547 | 2026-11-15 00:10:59+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0548 | 2026-11-15 00:11:01+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0549 | 2026-11-15 00:11:03+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0550 | 2026-11-15 00:11:05+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0551 | 2026-11-15 00:11:07+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0552 | 2026-11-15 00:11:08+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0553 | 2026-11-15 00:11:09+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0554 | 2026-11-15 00:11:10+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0555 | 2026-11-15 00:11:11+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0556 | 2026-11-15 00:11:13+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0557 | 2026-11-15 00:11:15+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0558 | 2026-11-15 00:11:17+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0559 | 2026-11-15 00:11:20+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0560 | 2026-11-15 00:11:22+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0561 | 2026-11-15 00:11:24+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0562 | 2026-11-15 00:11:26+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0563 | 2026-11-15 00:11:28+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0564 | 2026-11-15 00:11:30+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0565 | 2026-11-15 00:11:32+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0566 | 2026-11-15 00:11:34+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0567 | 2026-11-15 00:11:36+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0568 | 2026-11-15 00:11:38+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0569 | 2026-11-15 00:11:40+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0570 | 2026-11-15 00:11:42+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0571 | 2026-11-15 00:11:44+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0572 | 2026-11-15 00:11:46+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0573 | 2026-11-15 00:11:48+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0574 | 2026-11-15 00:16:52.724984+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=1` [None] |
| MODBUS-EVT-0575 | 2026-11-15 00:16:52.726904+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=1 qty=1` [None] |
| MODBUS-EVT-0576 | 2026-11-15 00:16:52.728348+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=2 qty=3` [None] |
| MODBUS-EVT-0577 | 2026-11-15 00:16:52.729731+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=2 qty=3` [None] |
| MODBUS-EVT-0578 | 2026-11-15 00:16:52.779199+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `write:addr=0 qty=1 vals=[1]` [None] |
| MODBUS-EVT-0579 | 2026-11-15 00:16:53.827335+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `write:addr=1 qty=1 vals=[999]` [None] |
| MODBUS-EVT-0580 | 2026-11-15 00:16:54.880901+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 1, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0581 | 2026-11-15 00:16:55.934014+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200, 300]` [None] |
| MODBUS-EVT-0582 | 2026-11-15 00:16:56.988433+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=0 qty=1` [None] |
| MODBUS-EVT-0583 | 2026-11-15 00:16:56.994354+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=1 qty=1` [None] |
| MODBUS-EVT-0584 | 2026-11-15 00:16:56.995765+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `read:addr=2 qty=3` [None] |
| MODBUS-EVT-0585 | 2026-11-15 00:16:56.997236+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `read:addr=2 qty=3` [None] |

---

## Defensive Recommendations & Containment Actions
1. **Inbound ACL Enforcement:** Restrict port 502 to authorized engineering workstations only; review write traffic from `10.0.1.10`, `10.0.1.20`.
2. **Suricata DPI Rule Tuning:** Enforce Modbus rule SID 1000004 to drop state-altering function codes (`FC05`, `FC06`, `FC15`, `FC16`) originating outside the Control Zone.
3. **Machine Learning Anomaly Quarantine:** Ingest high-threat events into `ml_detector.py` to trigger automated microsegmentation isolation.