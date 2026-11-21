# OT Cyber-Physical Incident Triage & Timeline Report
**Project:** CYB 691 Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)
**Generated Date:** 2026-11-21 03:03:28 UTC
**Lead Security Architect:** Rachid Afaf

---
## Executive Incident Summary
During operational telemetry monitoring of the virtualized Purdue Model Level 1-3 OT testbed, 
the normalization pipeline analyzed **270 Modbus TCP telemetry frames** and **91 firewall drop records** 
between `2026-11-04T20:09:14.006666+00:00` and `2026-11-04T20:25:00.513928+00:00` (UTC).
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
| MODBUS-EVT-0001 | 2026-11-04 20:09:14.006666+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0002 | 2026-11-04 20:09:19.805208+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0003 | 2026-11-04 20:09:19.805285+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0004 | 2026-11-04 20:09:22.724880+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0005 | 2026-11-04 20:09:25.747941+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0006 | 2026-11-04 20:09:26.292661+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0007 | 2026-11-04 20:09:31.691432+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0008 | 2026-11-04 20:09:31.691527+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0009 | 2026-11-04 20:09:32.636753+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0010 | 2026-11-04 20:09:34.583780+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0011 | 2026-11-04 20:09:38.535291+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0012 | 2026-11-04 20:09:38.580046+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0013 | 2026-11-04 20:09:42.480429+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0014 | 2026-11-04 20:09:44.480347+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0015 | 2026-11-04 20:09:45.526943+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0016 | 2026-11-04 20:09:49.421741+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0017 | 2026-11-04 20:09:50.423227+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0018 | 2026-11-04 20:09:50.868758+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0019 | 2026-11-04 20:09:51.369763+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0020 | 2026-11-04 20:09:53.416879+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0021 | 2026-11-04 20:09:57.316343+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0022 | 2026-11-04 20:09:59.266245+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0023 | 2026-11-04 20:10:01.320104+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0024 | 2026-11-04 20:10:03.166300+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0025 | 2026-11-04 20:10:04.267956+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0026 | 2026-11-04 20:10:06.214665+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0027 | 2026-11-04 20:10:12.155682+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0028 | 2026-11-04 20:10:12.155746+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0029 | 2026-11-04 20:10:15.106144+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0030 | 2026-11-04 20:10:15.451668+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0031 | 2026-11-04 20:10:18.115107+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0032 | 2026-11-04 20:10:19.016281+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0033 | 2026-11-04 20:10:22.961622+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0034 | 2026-11-04 20:10:24.965716+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0035 | 2026-11-04 20:10:26.912057+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0036 | 2026-11-04 20:10:27.760427+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0037 | 2026-11-04 20:10:29.907743+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0038 | 2026-11-04 20:10:32.857548+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0039 | 2026-11-04 20:10:34.898012+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0040 | 2026-11-04 20:10:34.898207+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0041 | 2026-11-04 20:10:39.800314+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0042 | 2026-11-04 20:10:40.049883+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0043 | 2026-11-04 20:10:44.744388+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0044 | 2026-11-04 20:10:44.744577+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0045 | 2026-11-04 20:10:46.691893+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0046 | 2026-11-04 20:10:48.663403+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0047 | 2026-11-04 20:10:51.687648+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0048 | 2026-11-04 20:10:52.332295+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0049 | 2026-11-04 20:10:54.579672+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0050 | 2026-11-04 20:10:57.527917+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0051 | 2026-11-04 20:10:58.575705+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0052 | 2026-11-04 20:11:00.519792+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0053 | 2026-11-04 20:11:04.474546+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0054 | 2026-11-04 20:11:04.617414+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0055 | 2026-11-04 20:11:08.467978+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0056 | 2026-11-04 20:11:09.415465+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0057 | 2026-11-04 20:11:10.416931+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0058 | 2026-11-04 20:11:11.379439+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0059 | 2026-11-04 20:11:13.416183+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0060 | 2026-11-04 20:11:16.910087+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0061 | 2026-11-04 20:11:17.310914+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0062 | 2026-11-04 20:11:20.259044+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0063 | 2026-11-04 20:11:21.305000+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0064 | 2026-11-04 20:11:26.200307+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0065 | 2026-11-04 20:11:26.200394+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0066 | 2026-11-04 20:11:29.198044+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0067 | 2026-11-04 20:11:33.156799+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0068 | 2026-11-04 20:11:33.156900+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0069 | 2026-11-04 20:11:34.107224+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0070 | 2026-11-04 20:11:39.101915+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0071 | 2026-11-04 20:11:40.049464+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0072 | 2026-11-04 20:11:41.496265+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0073 | 2026-11-04 20:11:42.998521+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0074 | 2026-11-04 20:11:45.993946+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0075 | 2026-11-04 20:11:46.959117+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0076 | 2026-11-04 20:11:51.942898+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0077 | 2026-11-04 20:11:53.789481+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0078 | 2026-11-04 20:11:53.889990+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0079 | 2026-11-04 20:11:56.838311+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0080 | 2026-11-04 20:11:57.839753+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0081 | 2026-11-04 20:12:01.738131+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0082 | 2026-11-04 20:12:01.738240+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0083 | 2026-11-04 20:12:03.786348+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0084 | 2026-11-04 20:12:06.077919+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0085 | 2026-11-04 20:12:06.678949+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0086 | 2026-11-04 20:12:08.730890+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0087 | 2026-11-04 20:12:11.626060+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0088 | 2026-11-04 20:12:14.629899+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0089 | 2026-11-04 20:12:15.631339+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0090 | 2026-11-04 20:12:20.544432+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0091 | 2026-11-04 20:12:52.438469+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0092 | 2026-11-04 20:12:58.050425+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0093 | 2026-11-04 20:12:58.050637+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0094 | 2026-11-04 20:13:01.064150+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0095 | 2026-11-04 20:13:02.065547+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0096 | 2026-11-04 20:13:04.759265+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0097 | 2026-11-04 20:13:09.966825+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0098 | 2026-11-04 20:13:10.868092+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0099 | 2026-11-04 20:13:11.865829+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0100 | 2026-11-04 20:13:12.867187+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0101 | 2026-11-04 20:13:17.067754+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0102 | 2026-11-04 20:13:17.779400+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0103 | 2026-11-04 20:13:17.779503+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0104 | 2026-11-04 20:13:22.770518+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0105 | 2026-11-04 20:13:23.718215+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0106 | 2026-11-04 20:13:24.719539+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0107 | 2026-11-04 20:13:29.369941+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0108 | 2026-11-04 20:13:29.671207+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0109 | 2026-11-04 20:13:33.667701+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0110 | 2026-11-04 20:13:33.667783+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0111 | 2026-11-04 20:13:34.568991+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0112 | 2026-11-04 20:13:37.560388+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0113 | 2026-11-04 20:13:40.523903+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0114 | 2026-11-04 20:13:41.677664+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0115 | 2026-11-04 20:13:44.528175+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0116 | 2026-11-04 20:13:45.529669+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0117 | 2026-11-04 20:13:46.475670+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0118 | 2026-11-04 20:13:50.373457+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0119 | 2026-11-04 20:13:50.373535+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0120 | 2026-11-04 20:13:53.978024+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0121 | 2026-11-04 20:13:55.380620+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0122 | 2026-11-04 20:13:58.280605+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0123 | 2026-11-04 20:14:01.331337+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0124 | 2026-11-04 20:14:02.280414+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0125 | 2026-11-04 20:14:05.229975+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0126 | 2026-11-04 20:14:06.285751+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0127 | 2026-11-04 20:14:08.189035+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0128 | 2026-11-04 20:14:10.141911+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0129 | 2026-11-04 20:14:11.189984+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0130 | 2026-11-04 20:14:14.139896+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0131 | 2026-11-04 20:14:18.033487+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0132 | 2026-11-04 20:14:18.589985+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0133 | 2026-11-04 20:14:20.093059+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0134 | 2026-11-04 20:14:24.046217+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0135 | 2026-11-04 20:14:25.955516+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0136 | 2026-11-04 20:14:25.955708+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0137 | 2026-11-04 20:14:30.903634+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0138 | 2026-11-04 20:14:31.905855+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0139 | 2026-11-04 20:14:35.895274+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0140 | 2026-11-04 20:14:36.796698+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0141 | 2026-11-04 20:14:38.855665+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0142 | 2026-11-04 20:14:39.802609+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0143 | 2026-11-04 20:14:43.210564+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0144 | 2026-11-04 20:14:43.712227+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0145 | 2026-11-04 20:14:44.713684+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0146 | 2026-11-04 20:14:49.660915+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0147 | 2026-11-04 20:14:51.621014+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0148 | 2026-11-04 20:14:52.622440+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0149 | 2026-11-04 20:14:54.577459+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0150 | 2026-11-04 20:14:55.524289+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0151 | 2026-11-04 20:14:59.541758+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0152 | 2026-11-04 20:15:01.533151+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0153 | 2026-11-04 20:15:03.481142+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0154 | 2026-11-04 20:15:03.481231+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0155 | 2026-11-04 20:15:07.827549+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0156 | 2026-11-04 20:15:08.429104+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0157 | 2026-11-04 20:15:11.378476+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0158 | 2026-11-04 20:15:12.425404+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0159 | 2026-11-04 20:15:15.382418+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0160 | 2026-11-04 20:15:18.287951+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0161 | 2026-11-04 20:15:18.288035+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0162 | 2026-11-04 20:15:20.144759+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0163 | 2026-11-04 20:15:22.292921+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0164 | 2026-11-04 20:15:26.244157+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0165 | 2026-11-04 20:15:26.244259+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0166 | 2026-11-04 20:15:28.192169+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0167 | 2026-11-04 20:15:29.138734+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0168 | 2026-11-04 20:15:32.436711+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0169 | 2026-11-04 20:15:34.139996+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0170 | 2026-11-04 20:15:37.045400+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0171 | 2026-11-04 20:15:38.046653+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0172 | 2026-11-04 20:15:41.048052+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0173 | 2026-11-04 20:15:44.748710+00:00 | `10.0.1.20` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0174 | 2026-11-04 20:15:44.949843+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0175 | 2026-11-04 20:15:46.998081+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0176 | 2026-11-04 20:15:48.921188+00:00 | `10.0.1.20` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0177 | 2026-11-04 20:15:50.923626+00:00 | `10.0.1.20` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0178 | 2026-11-04 20:15:51.924968+00:00 | `10.0.1.20` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0179 | 2026-11-04 20:15:53.874047+00:00 | `10.0.1.20` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0180 | 2026-11-04 20:15:57.779116+00:00 | `10.0.1.20` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0181 | 2026-11-04 20:16:59.102654+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0182 | 2026-11-04 20:17:03.992379+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0183 | 2026-11-04 20:17:06.949138+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0184 | 2026-11-04 20:17:08.896892+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0185 | 2026-11-04 20:17:08.896975+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0186 | 2026-11-04 20:17:11.389612+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0187 | 2026-11-04 20:17:13.837608+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0188 | 2026-11-04 20:17:15.885832+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0189 | 2026-11-04 20:17:18.833794+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0190 | 2026-11-04 20:17:19.778682+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0191 | 2026-11-04 20:17:20.780057+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0192 | 2026-11-04 20:17:23.675124+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0193 | 2026-11-04 20:17:25.677862+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0194 | 2026-11-04 20:17:28.653217+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0195 | 2026-11-04 20:17:30.616285+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0196 | 2026-11-04 20:17:33.665021+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0197 | 2026-11-04 20:17:35.959293+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0198 | 2026-11-04 20:17:36.560370+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0199 | 2026-11-04 20:17:36.560457+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0200 | 2026-11-04 20:17:40.554438+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0201 | 2026-11-04 20:17:41.555881+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0202 | 2026-11-04 20:17:43.503708+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0203 | 2026-11-04 20:17:48.245039+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0204 | 2026-11-04 20:17:48.432730+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0205 | 2026-11-04 20:17:49.444144+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0206 | 2026-11-04 20:17:52.336641+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0207 | 2026-11-04 20:17:53.343894+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0208 | 2026-11-04 20:17:55.393527+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0209 | 2026-11-04 20:17:59.288724+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0210 | 2026-11-04 20:18:00.534461+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0211 | 2026-11-04 20:18:01.235682+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0212 | 2026-11-04 20:18:04.238448+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0213 | 2026-11-04 20:18:06.234260+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0214 | 2026-11-04 20:18:07.184131+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0215 | 2026-11-04 20:18:12.186457+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0216 | 2026-11-04 20:18:12.831071+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0217 | 2026-11-04 20:18:14.133219+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0218 | 2026-11-04 20:18:18.040292+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0219 | 2026-11-04 20:18:19.995004+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0220 | 2026-11-04 20:18:20.996317+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0221 | 2026-11-04 20:18:22.983994+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0222 | 2026-11-04 20:18:25.137674+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0223 | 2026-11-04 20:18:28.895339+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0224 | 2026-11-04 20:18:31.888884+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0225 | 2026-11-04 20:18:32.890208+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0226 | 2026-11-04 20:18:34.809488+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0227 | 2026-11-04 20:18:37.436741+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0228 | 2026-11-04 20:18:37.837624+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0229 | 2026-11-04 20:18:40.822933+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0230 | 2026-11-04 20:18:43.781520+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0231 | 2026-11-04 20:18:44.682732+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0232 | 2026-11-04 20:18:47.673175+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0233 | 2026-11-04 20:18:47.673275+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0234 | 2026-11-04 20:18:49.723166+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0235 | 2026-11-04 20:18:53.650052+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0236 | 2026-11-04 20:18:54.623511+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0237 | 2026-11-04 20:18:57.573892+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0238 | 2026-11-04 20:18:58.561683+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0239 | 2026-11-04 20:18:58.561771+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0240 | 2026-11-04 20:19:02.023971+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0241 | 2026-11-04 20:19:05.474012+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0242 | 2026-11-04 20:19:05.474109+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0243 | 2026-11-04 20:19:06.420772+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0244 | 2026-11-04 20:19:11.415694+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0245 | 2026-11-04 20:19:13.362974+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0246 | 2026-11-04 20:19:14.307939+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0247 | 2026-11-04 20:19:15.309556+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0248 | 2026-11-04 20:19:19.306748+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0249 | 2026-11-04 20:19:22.210423+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0250 | 2026-11-04 20:19:24.201801+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0251 | 2026-11-04 20:19:25.248536+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0252 | 2026-11-04 20:19:26.594553+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0253 | 2026-11-04 20:19:30.144058+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0254 | 2026-11-04 20:19:33.136941+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0255 | 2026-11-04 20:19:33.137015+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0256 | 2026-11-04 20:19:34.138335+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0257 | 2026-11-04 20:19:36.085104+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0258 | 2026-11-04 20:19:38.887322+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0259 | 2026-11-04 20:19:42.043674+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0260 | 2026-11-04 20:19:42.043738+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0261 | 2026-11-04 20:19:46.975678+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0262 | 2026-11-04 20:19:48.971311+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0263 | 2026-11-04 20:19:51.187829+00:00 | `10.0.1.10` | `10.0.3.10` | 0x0F (Write Multiple Coils) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[1, 0, 0, 0, 0, 0, 0, 0]` [None] |
| MODBUS-EVT-0264 | 2026-11-04 20:19:51.889045+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0265 | 2026-11-04 20:19:51.889135+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0266 | 2026-11-04 20:19:56.843042+00:00 | `10.0.1.10` | `10.0.3.10` | 0x01 (Read Coils) | **READ** | LOW | **10** | `FC=1` [None] |
| MODBUS-EVT-0267 | 2026-11-04 20:19:59.804840+00:00 | `10.0.1.10` | `10.0.3.10` | 0x03 (Read Holding Registers) | **READ** | LOW | **10** | `FC=3` [None] |
| MODBUS-EVT-0268 | 2026-11-04 20:20:00.806358+00:00 | `10.0.1.10` | `10.0.3.10` | 0x05 (Write Single Coil) | **WRITE** | HIGH | **60** | `FC=5` [None] |
| MODBUS-EVT-0269 | 2026-11-04 20:20:04.714807+00:00 | `10.0.1.10` | `10.0.3.10` | 0x06 (Write Single Register) | **WRITE** | HIGH | **60** | `FC=6` [None] |
| MODBUS-EVT-0270 | 2026-11-04 20:20:07.718604+00:00 | `10.0.1.10` | `10.0.3.10` | 0x10 (Write Multiple Registers) | **WRITE** | CRITICAL | **85** | `write:addr=2 qty=3 vals=[100, 200]` [None] |
| MODBUS-EVT-0271 | 2026-11-04 20:20:29.388376+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0272 | 2026-11-04 20:20:32.436982+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0273 | 2026-11-04 20:20:35.483601+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0274 | 2026-11-04 20:20:38.528369+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0275 | 2026-11-04 20:20:41.575258+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0276 | 2026-11-04 20:20:44.621321+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0277 | 2026-11-04 20:20:47.666668+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0278 | 2026-11-04 20:20:50.712668+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0279 | 2026-11-04 20:20:53.762441+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0280 | 2026-11-04 20:20:56.813012+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0281 | 2026-11-04 20:20:59.851365+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0282 | 2026-11-04 20:21:02.901555+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0283 | 2026-11-04 20:21:05.943371+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0284 | 2026-11-04 20:21:08.989048+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0285 | 2026-11-04 20:21:12.035540+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0286 | 2026-11-04 20:21:15.081520+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0287 | 2026-11-04 20:21:18.132707+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0288 | 2026-11-04 20:21:21.173651+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0289 | 2026-11-04 20:21:24.218241+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0290 | 2026-11-04 20:21:27.264543+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0291 | 2026-11-04 20:21:30.310561+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0292 | 2026-11-04 20:21:33.357357+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0293 | 2026-11-04 20:21:36.403519+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0294 | 2026-11-04 20:21:39.451106+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0295 | 2026-11-04 20:21:42.495353+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0296 | 2026-11-04 20:21:45.545909+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0297 | 2026-11-04 20:21:46.541893+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0298 | 2026-11-04 20:21:48.587516+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0299 | 2026-11-04 20:21:51.634464+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0300 | 2026-11-04 20:21:54.680864+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0301 | 2026-11-04 20:21:57.726549+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0302 | 2026-11-04 20:22:00.771995+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0303 | 2026-11-04 20:22:03.820533+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0304 | 2026-11-04 20:22:06.865674+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0305 | 2026-11-04 20:22:09.911409+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0306 | 2026-11-04 20:22:12.957569+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0307 | 2026-11-04 20:22:16.003970+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0308 | 2026-11-04 20:22:19.050404+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0309 | 2026-11-04 20:22:22.098625+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0310 | 2026-11-04 20:22:25.141912+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0311 | 2026-11-04 20:22:28.188273+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0312 | 2026-11-04 20:22:31.233643+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0313 | 2026-11-04 20:22:34.279710+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0314 | 2026-11-04 20:22:37.325688+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0315 | 2026-11-04 20:22:40.372182+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0316 | 2026-11-04 20:22:43.418392+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0317 | 2026-11-04 20:22:46.466699+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0318 | 2026-11-04 20:22:49.512429+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0319 | 2026-11-04 20:22:52.558286+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0320 | 2026-11-04 20:22:55.604517+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0321 | 2026-11-04 20:22:58.650549+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0322 | 2026-11-04 20:23:01.700216+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0323 | 2026-11-04 20:23:04.745521+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0324 | 2026-11-04 20:23:07.792136+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0325 | 2026-11-04 20:23:10.837791+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0326 | 2026-11-04 20:23:13.884960+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0327 | 2026-11-04 20:23:16.932599+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0328 | 2026-11-04 20:23:19.977667+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0329 | 2026-11-04 20:23:23.024015+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0330 | 2026-11-04 20:23:26.069525+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0331 | 2026-11-04 20:23:29.116559+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0332 | 2026-11-04 20:23:32.160789+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0333 | 2026-11-04 20:23:35.206575+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0334 | 2026-11-04 20:23:38.252153+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0335 | 2026-11-04 20:23:41.298196+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0336 | 2026-11-04 20:23:44.362590+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0337 | 2026-11-04 20:23:47.408591+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0338 | 2026-11-04 20:23:50.454430+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0339 | 2026-11-04 20:23:53.500579+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0340 | 2026-11-04 20:23:56.550003+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0341 | 2026-11-04 20:23:59.594902+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0342 | 2026-11-04 20:24:02.639519+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0343 | 2026-11-04 20:24:05.685845+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0344 | 2026-11-04 20:24:08.731407+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0345 | 2026-11-04 20:24:11.777641+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0346 | 2026-11-04 20:24:14.823773+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0347 | 2026-11-04 20:24:17.869764+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0348 | 2026-11-04 20:24:20.916512+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0349 | 2026-11-04 20:24:23.962019+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0350 | 2026-11-04 20:24:27.008898+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0351 | 2026-11-04 20:24:30.054994+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0352 | 2026-11-04 20:24:33.101249+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0353 | 2026-11-04 20:24:36.147285+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0354 | 2026-11-04 20:24:39.192989+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0355 | 2026-11-04 20:24:42.238676+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0356 | 2026-11-04 20:24:45.283973+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0357 | 2026-11-04 20:24:48.329430+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0358 | 2026-11-04 20:24:51.375741+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0359 | 2026-11-04 20:24:54.422253+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0360 | 2026-11-04 20:24:57.468563+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |
| MODBUS-EVT-0361 | 2026-11-04 20:25:00.513928+00:00 | `10.0.1.20` | `10.0.3.10` | 0x00 (Firewall Boundary Drop) | **FIREWALL_DROP** | CRITICAL | **90** | `INBOUND_ACL_DROP` [AccessDenied] |

---

## Defensive Recommendations & Containment Actions
1. **Inbound ACL Enforcement:** Restrict port 502 to authorized engineering workstations only; review write traffic from `10.0.1.10`, `10.0.1.20`.
2. **Suricata DPI Rule Tuning:** Enforce Modbus rule SID 1000004 to drop state-altering function codes (`FC05`, `FC06`, `FC15`, `FC16`) originating outside the Control Zone.
3. **Machine Learning Anomaly Quarantine:** Ingest high-threat events into `ml_detector.py` to trigger automated microsegmentation isolation.