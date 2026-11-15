# Security Policy

## CYB691 / IT691 Capstone Team 4 — Cyber-Physical & Network Defense Monitoring

### Supported Versions
This project is developed as part of the CYB691/IT691 Cybersecurity Capstone (Fall 2026).

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## 🔒 Reporting a Vulnerability

As this repository contains research code, virtualized OT infrastructure scripts, and telemetry analysis pipelines for industrial control systems (ICS/OT):

1. **Do NOT open public GitHub issues** for security vulnerabilities, credential disclosures, or infrastructure exposure.
2. Direct all vulnerability reports to the project maintainers:
   - **Rachid Afaf** — Security Architect & Lead Security Analyst (`src/log_parser.py`, `src/timeline_generator.py`, `src/ml_detector.py`, `validate_stride_threats.py`)
   - **Erick Espinosa** — Infrastructure & OT Virtualization Lead (`infrastructure/traffic_generator.py`, testbed emulators)
   - **Anil Kumar** — Security Hardening, Review & Documentation Lead
3. Maintainers will acknowledge reports within 48 hours and coordinate remediation within private branches prior to release.

---

## 🛡️ Threat Modeling & STRIDE Architecture (OWASP Threat Dragon v2.3.0)

This repository incorporates a repository-level STRIDE threat model formatted in **OWASP Threat Dragon v2.3.0 JSON** (`Team 4 Threat Model.json`).

### 1. Model Overview & Status at Milestone
* **File:** `Team 4 Threat Model.json` (Threat Dragon v2.3.0 Standard)
* **Total Tracked Threats:** 37 open STRIDE threats across 32 components and 40 diagram cells.
* **Status at Milestone 1:** All 37 threats remain formally tracked as **OPEN / PLANNED** at this planning gate. Empirical threat mitigation and closure will be conducted during Report 2 experimental benchmarking.
* **Automated Audit Script:** `validate_stride_threats.py` reports **INVENTORY** results (artifacts exist and are well formed) separately from **PROPERTY** results (a control was actually exercised: parser functions driven with hostile inputs, normalized data reconciled with raw `eve.json`, ML evaluation method checked). Inventory results are not evidence that a threat is mitigated.

### 2. Trust Boundaries
* **OT Network Boundary (`curve-ot-boundary`):** Segregates Level 1–3 Purdue Model testbed components from developer workstations and external networks. *(2026-09-26 capture: Conpot Modbus target `172.17.0.2:5020` on the capture VM's Docker bridge, Suricata sensor, no firewall in path. Report 2 captures: real pymodbus 3.8.6 PLC `10.0.3.10:502` behind iptables 1.8.10 + Suricata 7.0.3 on vm-fwsensor — `infrastructure/README.md` §6.)*
* **Analysis Evidence Boundary (`curve-analysis-boundary`):** Protects cross-zone telemetry handoff archives (`.tar.gz`), log parsing routines (`src/log_parser.py`), incident triage engines (`src/timeline_generator.py`), machine learning analytics (`src/ml_detector.py`), and post-mortem report deliverables.

### 3. STRIDE Threat Distribution (37 Open Threats)
* **Spoofing (2 Threats):** Impersonation of operators or developers during test script invocation (`flow-operator-commands`, `flow-source-code`). Mitigated via named accounts, MFA, RBAC, and commit signing.
* **Tampering (19 Threats):** Unauthenticated Modbus/TCP write commands (`FC05`, `FC06`, `FC16`), Suricata EVE JSON log tampering, dataset poisoning, and report alteration. Planned mitigations: pfSense ACLs, Suricata write-function-code alerts, SHA-256 sidecar hashes, and immutable signed manifests.
* **Repudiation (2 Threats):** Unverified report provenance. Mitigated via source file SHA-256 hashes, git commit IDs, execution timestamps, and build manifests.
* **Information Disclosure (3 Threats):** EVE JSON log disclosure of OT layout, unencrypted transit, committed secrets. Mitigated via automated Gitleaks scanning, RFC 1918 private addressing, data redaction, and strict filesystem access control.
* **Denial of Service (5 Threats):** Testbed command floods, Suricata packet ring drops, ML feature matrix memory exhaustion. Mitigated via rate limiting, SPAN/TAP drop monitoring, bounded batch quotas, and process memory limits.
* **Elevation of Privilege (6 Threats):** Conpot container breakout, Tar-Slip directory traversal in `log_parser.py`, malicious third-party Python package installation. Mitigated via non-privileged Docker sandboxing, strict path boundary verification (`is_within_directory`), and pinned package dependencies.

---

## 🔍 Automated STRIDE Validation Output (`validate_stride_threats.py`)

Run of 2026-11-01 on the 2026-09-26 handoff (10 unique Modbus transactions). The full table is in `data/stride_validation_report.md`.

```text
INVENTORY | Threat model structure: 37 threats on 32 components, 5 trust boundaries; status as recorded in the model: {'Open': 37}
INVENTORY | Trust boundary 'OT Network Boundary': present in model
INVENTORY | Trust boundary 'Analysis Evidence Boundary': present in model
INVENTORY | Policy & licence files: present (existence only - not a security test)
[PASS] PROPERTY | P1 Parser controls: exercised: Tar-Slip and link members refused, '-- No entries --' -> 0 drops,
                  real drop -> 1, non-Modbus EVE ignored, function_raw 6 preserved
[PASS] PROPERTY | P2 Normalized vs raw: 10 normalized Modbus events == 10 unique raw transactions; function codes match;
                  0 firewall drops == raw drop lines
[WARN] PROPERTY | P3 ML evaluation: method checks passed; scenario record not yet confirmed by the team; without
                  function_code, Random Forest recall falls to 0.0% (detection rests on the function code);
                  only 10 labelled events
AUDIT PARTIAL: 2 property check(s) passed, 1 warning(s). This audit does not close threats.
```

The negative control described in the Report 1 feedback (an empty parser, normalized data holding an empty object, an empty model-results object) now produces **FAIL** on P1, P2 and P3 (`tests/test_pipeline.py::test_validator_negative_control_reproduces_professor_probe`).

> **November 2026 update.** The run above is the 2026-09-26 Conpot capture. The validator (P1/P2/P3) now runs and passes on each of the **four** Report 2 handoffs — the three source-separable captures (2026-11-04/07/14) and the Step 7 content-distinguishable capture (2026-11-15) — during ingest (`up.ps1` → **25/25** checks, 4/4 handoffs receipted). The 2026-11-15 capture adds content-distinguishable insider anomalies (writes from the authorized HMI with out-of-range address/value and burst timing), exercising the Tampering/Elevation paths that source-based controls alone cannot see; the content layer detects them per-class ~100%, though a static content rule matches the ML (`docs/ablation-results.md`). Two readable STRIDE figures were produced for Report 2 (Graphviz PNG + SVG + `.dot` source): **Figure 1 — OT Network Boundary** and **Figure 2 — Analysis/Evidence Boundary**, each mapping STRIDE threats to the validated controls (firewall containment, Suricata DPI, read-back, hashing, append-only audit, least-privilege roles). Threat-model threat/mitigation rows remain to be confirmed against `Team 4 Threat Model.json`.

## 🔏 Captured Data Handling
The handoff archive contains non-testbed traffic captured on the Azure VM, including public IPs of inbound SSH clients. Do not make the repository public until the release decision in `THIRD_PARTY_LICENSES.md` §3 is recorded.

---

## 📜 Third-Party Reuse & Governance
Detailed terms, copyleft boundary separation, and pre-release license compliance verification procedures are documented in [THIRD_PARTY_LICENSES.md](file:///c:/Users/rachi/PycharmProjects/CYB691-IT691-CapstoneProjectFall2026/THIRD_PARTY_LICENSES.md).
