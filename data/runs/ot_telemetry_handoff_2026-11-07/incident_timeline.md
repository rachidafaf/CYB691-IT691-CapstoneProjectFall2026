# OT Cyber-Physical Incident Triage & Timeline Report
**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)
**Generated Date:** 2026-11-15 22:02:37 UTC
**Lead Security Architect:** Rachid Afaf

---
## Executive Incident Summary
During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, 
the normalization pipeline analyzed **270 Modbus TCP telemetry frames** and **93 firewall drop records** 
between `2026-11-07T15:38:35.131416+00:00` and `2026-11-07T15:57:37.554918+00:00` (UTC).
The analysis isolated **180 state-altering write command attempts** from `10.0.1.10`, `10.0.1.20` targeting `10.0.3.10` (port 502), 
**0 protocol exception responses**, and **93 firewall drops** of traffic from `10.0.1.20`.

### Key Metrics Breakdown
- **Total Telemetry Ingested:** 363 records
- **Read Commands (Polling):** 90 (0.5 Read/Write Ratio)
- **State-Altering Write Commands:** 180
- **Modbus Protocol Exceptions:** 0
- **Firewall Drops:** 93
- **High-Threat Incident Alerts (Score >= 75):** 183

---
## Chronological Incident Event Timeline

| Event ID | Timestamp (ISO 8601) | Source IP | Dest IP | Function Code | Category | Risk Level | Threat Score | Payload & Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| MODBUS-EVT-0001 | 2026-11-07 15:38:35.131416+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0002 | 2026-11-07 15:38:37.279663+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0003 | 2026-11-07 15:38:39.224003+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0004 | 2026-11-07 15:38:44.223953+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0005 | 2026-11-07 15:38:46.130113+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0006 | 2026-11-07 15:38:47.418072+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0007 | 2026-11-07 15:38:50.168159+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0008 | 2026-11-07 15:38:51.129828+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0009 | 2026-11-07 15:38:56.011129+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0010 | 2026-11-07 15:38:57.012405+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0011 | 2026-11-07 15:38:57.012456+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0012 | 2026-11-07 15:38:59.713869+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0013 | 2026-11-07 15:39:01.015865+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0014 | 2026-11-07 15:39:04.911361+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0015 | 2026-11-07 15:39:06.960171+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0016 | 2026-11-07 15:39:06.960272+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0017 | 2026-11-07 15:39:11.866377+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0018 | 2026-11-07 15:39:11.999715+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0019 | 2026-11-07 15:39:14.849851+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0020 | 2026-11-07 15:39:16.796345+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0021 | 2026-11-07 15:39:20.698252+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0022 | 2026-11-07 15:39:20.698317+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0023 | 2026-11-07 15:39:20.698350+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0024 | 2026-11-07 15:39:24.301457+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0025 | 2026-11-07 15:39:28.596922+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0026 | 2026-11-07 15:39:29.603678+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0027 | 2026-11-07 15:39:31.645269+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0028 | 2026-11-07 15:39:34.535397+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0029 | 2026-11-07 15:39:35.517921+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0030 | 2026-11-07 15:39:36.591470+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0031 | 2026-11-07 15:39:37.493055+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0032 | 2026-11-07 15:39:39.540208+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0033 | 2026-11-07 15:39:41.429787+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0034 | 2026-11-07 15:39:43.434649+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0035 | 2026-11-07 15:39:45.384995+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0036 | 2026-11-07 15:39:48.881452+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0037 | 2026-11-07 15:39:51.330004+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0038 | 2026-11-07 15:39:54.355385+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0039 | 2026-11-07 15:39:55.329574+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0040 | 2026-11-07 15:39:57.282037+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0041 | 2026-11-07 15:39:59.272661+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0042 | 2026-11-07 15:40:01.183086+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0043 | 2026-11-07 15:40:04.231754+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0044 | 2026-11-07 15:40:05.132876+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0045 | 2026-11-07 15:40:08.136234+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0046 | 2026-11-07 15:40:10.084186+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0047 | 2026-11-07 15:40:13.477808+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0048 | 2026-11-07 15:40:14.079091+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0049 | 2026-11-07 15:40:14.079191+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0050 | 2026-11-07 15:40:20.929666+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0051 | 2026-11-07 15:40:21.955626+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0052 | 2026-11-07 15:40:22.956833+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0053 | 2026-11-07 15:40:23.923630+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0054 | 2026-11-07 15:40:25.769694+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0055 | 2026-11-07 15:40:26.871400+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0056 | 2026-11-07 15:40:30.866249+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0057 | 2026-11-07 15:40:31.867561+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0058 | 2026-11-07 15:40:32.813228+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0059 | 2026-11-07 15:40:34.762222+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0060 | 2026-11-07 15:40:38.055370+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0061 | 2026-11-07 15:40:40.707038+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0062 | 2026-11-07 15:40:40.707131+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0063 | 2026-11-07 15:40:43.656538+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0064 | 2026-11-07 15:40:46.650659+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0065 | 2026-11-07 15:40:50.343261+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0066 | 2026-11-07 15:40:50.622646+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0067 | 2026-11-07 15:40:55.540000+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0068 | 2026-11-07 15:40:56.483800+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0069 | 2026-11-07 15:40:58.489929+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0070 | 2026-11-07 15:40:59.502147+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0071 | 2026-11-07 15:41:01.484028+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0072 | 2026-11-07 15:41:02.629167+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0073 | 2026-11-07 15:41:04.431773+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0074 | 2026-11-07 15:41:05.413083+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0075 | 2026-11-07 15:41:10.372888+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0076 | 2026-11-07 15:41:12.284601+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0077 | 2026-11-07 15:41:14.926197+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0078 | 2026-11-07 15:41:15.327019+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0079 | 2026-11-07 15:41:16.228108+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0080 | 2026-11-07 15:41:20.221668+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0081 | 2026-11-07 15:41:22.168839+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0082 | 2026-11-07 15:41:22.168906+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0083 | 2026-11-07 15:41:25.153946+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0084 | 2026-11-07 15:41:27.212974+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0085 | 2026-11-07 15:41:29.115623+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0086 | 2026-11-07 15:41:32.066478+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0087 | 2026-11-07 15:41:35.070168+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0088 | 2026-11-07 15:41:38.979570+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0089 | 2026-11-07 15:41:39.980894+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0090 | 2026-11-07 15:41:41.993314+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0091 | 2026-11-07 15:44:17.369555+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0092 | 2026-11-07 15:44:23.925350+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0093 | 2026-11-07 15:44:25.873085+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0094 | 2026-11-07 15:44:28.857582+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0095 | 2026-11-07 15:44:28.857677+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0096 | 2026-11-07 15:44:29.670283+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0097 | 2026-11-07 15:44:33.721222+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0098 | 2026-11-07 15:44:35.772740+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0099 | 2026-11-07 15:44:35.772839+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0100 | 2026-11-07 15:44:36.723065+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0101 | 2026-11-07 15:44:41.974313+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0102 | 2026-11-07 15:44:42.675835+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0103 | 2026-11-07 15:44:44.625937+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0104 | 2026-11-07 15:44:46.573738+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0105 | 2026-11-07 15:44:47.575014+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0106 | 2026-11-07 15:44:50.528110+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0107 | 2026-11-07 15:44:51.529366+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0108 | 2026-11-07 15:44:54.269801+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0109 | 2026-11-07 15:44:58.469885+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0110 | 2026-11-07 15:44:59.471174+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0111 | 2026-11-07 15:45:01.419236+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0112 | 2026-11-07 15:45:01.419320+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0113 | 2026-11-07 15:45:03.367589+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0114 | 2026-11-07 15:45:06.564928+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0115 | 2026-11-07 15:45:08.367951+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0116 | 2026-11-07 15:45:11.266900+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0117 | 2026-11-07 15:45:12.268246+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0118 | 2026-11-07 15:45:14.216841+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0119 | 2026-11-07 15:45:18.217173+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0120 | 2026-11-07 15:45:18.862891+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0121 | 2026-11-07 15:45:20.165351+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0122 | 2026-11-07 15:45:24.166641+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0123 | 2026-11-07 15:45:26.114405+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0124 | 2026-11-07 15:45:29.097444+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0125 | 2026-11-07 15:45:30.014485+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0126 | 2026-11-07 15:45:31.161139+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0127 | 2026-11-07 15:45:32.063054+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0128 | 2026-11-07 15:45:35.960064+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0129 | 2026-11-07 15:45:38.914493+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0130 | 2026-11-07 15:45:40.924081+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0131 | 2026-11-07 15:45:43.470041+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0132 | 2026-11-07 15:45:43.871341+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0133 | 2026-11-07 15:45:46.835387+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0134 | 2026-11-07 15:45:47.874712+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0135 | 2026-11-07 15:45:49.622109+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0136 | 2026-11-07 15:45:49.828778+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0137 | 2026-11-07 15:45:54.734506+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0138 | 2026-11-07 15:45:55.778089+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0139 | 2026-11-07 15:45:55.781421+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0140 | 2026-11-07 15:45:58.660113+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0141 | 2026-11-07 15:46:03.636816+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0142 | 2026-11-07 15:46:05.572415+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0143 | 2026-11-07 15:46:08.080386+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0144 | 2026-11-07 15:46:08.581848+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0145 | 2026-11-07 15:46:11.493543+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0146 | 2026-11-07 15:46:11.493616+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0147 | 2026-11-07 15:46:12.478769+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0148 | 2026-11-07 15:46:18.425877+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0149 | 2026-11-07 15:46:20.373158+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0150 | 2026-11-07 15:46:21.375085+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0151 | 2026-11-07 15:46:22.417356+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0152 | 2026-11-07 15:46:23.422366+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0153 | 2026-11-07 15:46:29.272382+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0154 | 2026-11-07 15:46:30.273709+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0155 | 2026-11-07 15:46:31.320648+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0156 | 2026-11-07 15:46:32.668859+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0157 | 2026-11-07 15:46:34.232247+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0158 | 2026-11-07 15:46:35.221731+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0159 | 2026-11-07 15:46:39.218395+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0160 | 2026-11-07 15:46:41.166051+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0161 | 2026-11-07 15:46:44.115608+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0162 | 2026-11-07 15:46:44.961469+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0163 | 2026-11-07 15:46:47.110649+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0164 | 2026-11-07 15:46:48.011842+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0165 | 2026-11-07 15:46:50.064476+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0166 | 2026-11-07 15:46:54.973324+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0167 | 2026-11-07 15:46:55.920832+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0168 | 2026-11-07 15:46:57.266323+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0169 | 2026-11-07 15:47:01.867779+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0170 | 2026-11-07 15:47:01.867866+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0171 | 2026-11-07 15:47:02.869114+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0172 | 2026-11-07 15:47:06.867677+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0173 | 2026-11-07 15:47:07.816416+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0174 | 2026-11-07 15:47:09.563772+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0175 | 2026-11-07 15:47:14.715641+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0176 | 2026-11-07 15:47:14.715730+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0177 | 2026-11-07 15:47:16.741897+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0178 | 2026-11-07 15:47:19.645501+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0179 | 2026-11-07 15:47:21.647966+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0180 | 2026-11-07 15:47:23.658007+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0181 | 2026-11-07 15:49:38.617562+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0182 | 2026-11-07 15:49:41.870332+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0183 | 2026-11-07 15:49:43.817933+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0184 | 2026-11-07 15:49:49.769189+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0185 | 2026-11-07 15:49:50.914500+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0186 | 2026-11-07 15:49:51.715909+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0187 | 2026-11-07 15:49:53.663110+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0188 | 2026-11-07 15:49:56.712190+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0189 | 2026-11-07 15:49:56.712276+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0190 | 2026-11-07 15:50:01.557823+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0191 | 2026-11-07 15:50:02.559117+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0192 | 2026-11-07 15:50:03.203926+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0193 | 2026-11-07 15:50:05.553893+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0194 | 2026-11-07 15:50:08.501973+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0195 | 2026-11-07 15:50:11.501657+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0196 | 2026-11-07 15:50:12.502940+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0197 | 2026-11-07 15:50:14.450592+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0198 | 2026-11-07 15:50:15.496570+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0199 | 2026-11-07 15:50:17.400231+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0200 | 2026-11-07 15:50:21.315229+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0201 | 2026-11-07 15:50:22.346740+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0202 | 2026-11-07 15:50:25.298061+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0203 | 2026-11-07 15:50:27.231872+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0204 | 2026-11-07 15:50:27.791327+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0205 | 2026-11-07 15:50:30.239122+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0206 | 2026-11-07 15:50:31.240409+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0207 | 2026-11-07 15:50:34.235727+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0208 | 2026-11-07 15:50:36.183652+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0209 | 2026-11-07 15:50:39.153501+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0210 | 2026-11-07 15:50:40.081642+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0211 | 2026-11-07 15:50:42.084478+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0212 | 2026-11-07 15:50:44.037247+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0213 | 2026-11-07 15:50:45.065690+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0214 | 2026-11-07 15:50:47.035833+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0215 | 2026-11-07 15:50:51.978967+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0216 | 2026-11-07 15:50:52.376904+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0217 | 2026-11-07 15:50:56.875638+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0218 | 2026-11-07 15:50:57.901087+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0219 | 2026-11-07 15:51:01.878065+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0220 | 2026-11-07 15:51:02.828809+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0221 | 2026-11-07 15:51:03.811964+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0222 | 2026-11-07 15:51:04.674588+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0223 | 2026-11-07 15:51:05.776472+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0224 | 2026-11-07 15:51:11.723683+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0225 | 2026-11-07 15:51:13.698271+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0226 | 2026-11-07 15:51:13.698356+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0227 | 2026-11-07 15:51:15.643032+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0228 | 2026-11-07 15:51:16.967068+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0229 | 2026-11-07 15:51:17.668590+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0230 | 2026-11-07 15:51:20.616056+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0231 | 2026-11-07 15:51:22.563141+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0232 | 2026-11-07 15:51:23.609479+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0233 | 2026-11-07 15:51:29.255168+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0234 | 2026-11-07 15:51:29.455837+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0235 | 2026-11-07 15:51:32.405811+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0236 | 2026-11-07 15:51:35.401442+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0237 | 2026-11-07 15:51:36.405711+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0238 | 2026-11-07 15:51:38.353033+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0239 | 2026-11-07 15:51:41.301824+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0240 | 2026-11-07 15:51:41.546108+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0241 | 2026-11-07 15:51:44.296334+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0242 | 2026-11-07 15:51:47.294574+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0243 | 2026-11-07 15:51:48.292105+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0244 | 2026-11-07 15:51:49.193295+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0245 | 2026-11-07 15:51:52.188100+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0246 | 2026-11-07 15:51:53.836062+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0247 | 2026-11-07 15:51:56.184647+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0248 | 2026-11-07 15:51:58.131961+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0249 | 2026-11-07 15:51:59.133254+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0250 | 2026-11-07 15:52:03.028890+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0251 | 2026-11-07 15:52:05.076506+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0252 | 2026-11-07 15:52:06.122108+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0253 | 2026-11-07 15:52:10.925985+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0254 | 2026-11-07 15:52:10.926076+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0255 | 2026-11-07 15:52:11.927328+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0256 | 2026-11-07 15:52:17.871743+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0257 | 2026-11-07 15:52:18.417394+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0258 | 2026-11-07 15:52:19.819576+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0259 | 2026-11-07 15:52:22.816649+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0260 | 2026-11-07 15:52:23.817990+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0261 | 2026-11-07 15:52:25.764815+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0262 | 2026-11-07 15:52:27.720303+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0263 | 2026-11-07 15:52:30.704610+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0264 | 2026-11-07 15:52:30.706991+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0265 | 2026-11-07 15:52:33.633234+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0266 | 2026-11-07 15:52:35.635721+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0267 | 2026-11-07 15:52:37.638142+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0268 | 2026-11-07 15:52:41.547409+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0269 | 2026-11-07 15:52:41.547478+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0270 | 2026-11-07 15:52:47.505721+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0271 | 2026-11-07 15:53:06.473244+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0272 | 2026-11-07 15:53:09.520124+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0273 | 2026-11-07 15:53:10.525268+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0274 | 2026-11-07 15:53:12.570043+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0275 | 2026-11-07 15:53:15.609924+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0276 | 2026-11-07 15:53:18.660066+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0277 | 2026-11-07 15:53:21.701018+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0278 | 2026-11-07 15:53:24.746802+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0279 | 2026-11-07 15:53:27.791546+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0280 | 2026-11-07 15:53:30.839124+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0281 | 2026-11-07 15:53:33.884114+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0282 | 2026-11-07 15:53:36.929472+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0283 | 2026-11-07 15:53:39.975626+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0284 | 2026-11-07 15:53:43.021936+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0285 | 2026-11-07 15:53:46.066982+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0286 | 2026-11-07 15:53:49.113087+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0287 | 2026-11-07 15:53:52.158377+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0288 | 2026-11-07 15:53:55.207544+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0289 | 2026-11-07 15:53:58.253411+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0290 | 2026-11-07 15:54:01.298695+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0291 | 2026-11-07 15:54:04.348624+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0292 | 2026-11-07 15:54:07.397441+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0293 | 2026-11-07 15:54:10.438742+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0294 | 2026-11-07 15:54:13.483257+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0295 | 2026-11-07 15:54:16.530124+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0296 | 2026-11-07 15:54:19.574826+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0297 | 2026-11-07 15:54:22.620613+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0298 | 2026-11-07 15:54:25.665315+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0299 | 2026-11-07 15:54:28.710326+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0300 | 2026-11-07 15:54:31.756129+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0301 | 2026-11-07 15:54:34.801909+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0302 | 2026-11-07 15:54:37.846883+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0303 | 2026-11-07 15:54:40.893500+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0304 | 2026-11-07 15:54:43.948824+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0305 | 2026-11-07 15:54:46.996179+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0306 | 2026-11-07 15:54:50.043128+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0307 | 2026-11-07 15:54:53.088450+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0308 | 2026-11-07 15:54:56.134082+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0309 | 2026-11-07 15:54:59.181582+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0310 | 2026-11-07 15:55:02.227149+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0311 | 2026-11-07 15:55:05.273991+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0312 | 2026-11-07 15:55:08.318721+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0313 | 2026-11-07 15:55:11.364417+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0314 | 2026-11-07 15:55:14.409772+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0315 | 2026-11-07 15:55:17.456960+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0316 | 2026-11-07 15:55:18.455406+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0317 | 2026-11-07 15:55:20.499767+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0318 | 2026-11-07 15:55:23.544998+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0319 | 2026-11-07 15:55:26.590267+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0320 | 2026-11-07 15:55:29.635243+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0321 | 2026-11-07 15:55:32.681679+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0322 | 2026-11-07 15:55:35.729835+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0323 | 2026-11-07 15:55:38.775123+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0324 | 2026-11-07 15:55:41.819490+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0325 | 2026-11-07 15:55:44.864622+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0326 | 2026-11-07 15:55:47.910164+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0327 | 2026-11-07 15:55:50.955975+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0328 | 2026-11-07 15:55:54.001250+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0329 | 2026-11-07 15:55:57.047726+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0330 | 2026-11-07 15:56:00.093886+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0331 | 2026-11-07 15:56:03.142799+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0332 | 2026-11-07 15:56:06.187383+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0333 | 2026-11-07 15:56:09.231124+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0334 | 2026-11-07 15:56:10.231416+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0335 | 2026-11-07 15:56:12.275888+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0336 | 2026-11-07 15:56:15.321850+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0337 | 2026-11-07 15:56:18.367379+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0338 | 2026-11-07 15:56:21.413598+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0339 | 2026-11-07 15:56:24.458584+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0340 | 2026-11-07 15:56:27.508324+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0341 | 2026-11-07 15:56:30.551124+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0342 | 2026-11-07 15:56:33.600966+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0343 | 2026-11-07 15:56:36.640690+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0344 | 2026-11-07 15:56:39.686127+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0345 | 2026-11-07 15:56:42.730824+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0346 | 2026-11-07 15:56:45.778223+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0347 | 2026-11-07 15:56:48.823607+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0348 | 2026-11-07 15:56:51.869348+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0349 | 2026-11-07 15:56:54.915026+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0350 | 2026-11-07 15:56:57.960517+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0351 | 2026-11-07 15:57:01.006234+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0352 | 2026-11-07 15:57:04.051567+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0353 | 2026-11-07 15:57:07.097245+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0354 | 2026-11-07 15:57:10.142727+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0355 | 2026-11-07 15:57:13.187973+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0356 | 2026-11-07 15:57:16.232663+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0357 | 2026-11-07 15:57:19.278334+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0358 | 2026-11-07 15:57:22.326437+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0359 | 2026-11-07 15:57:25.371478+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0360 | 2026-11-07 15:57:28.417474+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0361 | 2026-11-07 15:57:31.462698+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0362 | 2026-11-07 15:57:34.508155+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0363 | 2026-11-07 15:57:37.554918+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |

---

## Defensive Recommendations & Containment Actions
1. **Inbound ACL Enforcement:** Restrict port 502 to authorized engineering workstations only; review write traffic from `10.0.1.10`, `10.0.1.20`.
2. **Suricata DPI Rule Tuning:** Enforce Modbus rule SID 1000004 to drop state-altering function codes (`FC05`, `FC06`, `FC15`, `FC16`) originating outside the Control Zone.
3. **Machine Learning Anomaly Quarantine:** Ingest high-threat events into `ml_detector.py` to trigger automated microsegmentation isolation.