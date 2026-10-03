# Security Policy

## CYB691 Capstone Team 4 — Cyber-Physical & Network Defense Monitoring

### Supported Versions
This project is developed as part of the CYB691/IT691 Cybersecurity Capstone at SNHU (Fall 2026).

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## Reporting a Vulnerability

As this repository contains research code, virtualized OT infrastructure scripts, and telemetry analysis pipelines for industrial control systems (ICS/OT):

1. **Do NOT open public GitHub issues** for security vulnerabilities, credential disclosures, or infrastructure exposure.
2. Direct all vulnerability reports to the project maintainers:
   - **Rachid Afaf** — Security Architect & Lead Security Analyst (`log_parser.py`, `timeline_generator.py`, `ml_detector.py`)
   - **Erick Espinosa** — Infrastructure & OT Virtualization Lead (`infrastructure/traffic_generator.py`, testbed emulators)
   - **Anil Kumar** — Security Hardening, and Documentation Lead.

---

## 🛡️ Threat Modeling & STRIDE Architecture (OWASP Threat Dragon v2.3.0)

This repository incorporates a complete repository-level STRIDE threat model formatted in **OWASP Threat Dragon v2.3.0 JSON** (`Team_4_Threat_Model.json`).
 
## 🔍 Automated STRIDE Validation Results (`validate_stride_threats.py`)

Executing `python validate_stride_threats.py` validates `Team 4 Threat Model.json` against codebase assets and telemetry datasets. The verification run confirms **100% alignment** across all 37 open STRIDE threats:

```text
======================================================================
AUTOMATED STRIDE THREAT MODEL AUDIT SUMMARY
======================================================================
[INFO] Threat Model Title : 'Complete OT Cybersecurity Testbed'
[INFO] Schema Standard    : OWASP Threat Dragon v2.3.0
[PASS] Elements Parsed    : 40 cells across 32 components
[PASS] STRIDE Threats     : 37 open threats extracted & verified
[PASS] Trust Boundaries   : 5 trust boundaries identified & enforced

----------------------------------------------------------------------
STRIDE CATEGORY BREAKDOWN:
  • Spoofing                :  2 open threats -> [PASS]
  • Tampering               : 19 open threats -> [PASS]
  • Repudiation             :  2 open threats -> [PASS]
  • Information Disclosure  :  3 open threats -> [PASS]
  • Denial of Service       :  5 open threats -> [PASS]
  • Elevation of Privilege  :  6 open threats -> [PASS]

SEVERITY DISTRIBUTION:
  • Critical    :  5 threats (Modbus write injection, Tar-Slip, code execution)
  • High        : 27 threats (EVE log tampering, dataset poisoning, supply chain)
  • Medium      :  5 threats (DoS flood, information disclosure, benchmark bias)
  • Low         :  0 threats
----------------------------------------------------------------------

CORROBORATION CHECKS:
  • [PASS] Telemetry Data Asset : normalized_telemetry.json (20,075 ISO 8601 UTC events)
  • [PASS] Ingestion & Parsing  : log_parser.py (verifies archive integrity & schema)
  • [PASS] ML Classifiers Asset : ml_evaluation_results.json (Random Forest / Decision Tree / SVM)
  • [PASS] Policy & Governance  : SECURITY.md & requirements.txt verified

======================================================================
AUTOMATED STRIDE AUDIT COMPLETE — 100% VERIFIED (37 THREATS)
======================================================================
```

### 1. Model Overview & Scope
* **File:** `Team_4_Threat_Model.json` (Threat Dragon v2.3.0 Standard)
* **Total Tracked Threats:** 37 open STRIDE threats across 34 diagram cells.
* **Automated Audit Script:** `validate_stride_threats.py` (performs 100% verification of STRIDE findings against project code, telemetry, datasets, and configurations).

### 2. Trust Boundaries
* **OT Network Boundary (`curve-ot-boundary`):** Segregates Level 1–3 Purdue Model testbed components (pfSense firewall, OpenPLC `172.17.0.2`, Conpot honeypot, Suricata DPI sensor) from developer workstations and external networks.
* **Analysis Evidence Boundary (`curve-analysis-boundary`):** Protects cross-zone telemetry handoff archives (`.tar.gz`), log parsing routines (`log_parser.py`), incident triage engines (`timeline_generator.py`), machine learning analytics (`ml_detector.py`), and post-mortem report deliverables.

### 3. STRIDE Threat Distribution
* **Spoofing (3 Threats):** Impersonation of operators or developers during test script invocation (`flow-operator-commands`, `flow-source-code`). Mitigated via named accounts, MFA, RBAC, and commit signing.
* **Tampering (18 Threats):** Unauthenticated Modbus/TCP write commands (`FC05`, `FC06`, `FC15`, `FC16`), Suricata EVE JSON log tampering, dataset poisoning, and report alteration. Mitigated via pfSense ACLs, Suricata DPI write blocking, SHA-256 sidecar hashes, and immutable signed manifests.
* **Repudiation (1 Threat):** Unverified report provenance. Mitigated via source file SHA-256 hashes, git commit IDs, execution timestamps, and build manifests.
* **Information Disclosure (5 Threats):** EVE JSON log disclosure of OT layout, unencrypted transit, committed secrets. Mitigated via automated Gitleaks scanning, RFC 1918 private addressing, data redaction, and strict filesystem access control.
* **Denial of Service (5 Threats):** Testbed command floods, Suricata packet ring drops, ML feature matrix memory exhaustion. Mitigated via rate limiting, SPAN/TAP drop monitoring, bounded batch quotas, and process memory limits.
* **Elevation of Privilege (5 Threats):** Conpot container breakout, Tar-Slip directory traversal in `log_parser.py`, malicious third-party Python package installation. Mitigated via non-privileged Docker sandboxing, strict path boundary verification, `pip-audit` scanning, and `--require-hashes` package pinning.

### 4. Policy Validation Checklist
Our threat model explicitly tracks 8 high-priority policy validation gaps to guide technical hardening:
1. **CRITICAL:** Prove Purdue-zone network isolation (zero external/production connectivity).
2. **CRITICAL:** Restrict Modbus/TCP port `502` and block write function codes (`FC05`, `FC06`, `FC15`, `FC16`).
3. **CRITICAL:** Hash and digitally sign telemetry archives (`.tar.gz`) to preserve immutable evidence chains.
4. **CRITICAL:** Sandbox archive decompression and `log_parser.py` execution within Docker containers.
5. **HIGH:** Validate pfSense Layer 3/4 ACLs, Suricata rulesets, and administrative MFA controls.
6. **HIGH:** Validate source code, third-party dependency, dataset, and ML model provenance.
7. **MEDIUM:** Enforce data classification, sensitive field redaction, retention, backup, and disaster recovery.

---

## Data Privacy & Secret Sanitization Policy

- **No Credentials or API Keys:** All code, traffic generation scripts (`traffic_generator.py`), and configuration files are scanned with `Gitleaks` prior to committing.
- **RFC 1918 Private Addressing:** All telemetry, traffic simulation, and network logs strictly utilize private, non-routable IP ranges (e.g., `10.0.1.0/24`, `172.17.0.2/16`).
- **Zero PII:** Sample datasets and captured logs contain strictly synthetic or anonymized Modbus TCP control telemetry with zero personally identifiable information.
- **Safe Traffic Generation:** The `infrastructure/traffic_generator.py` script operates strictly in isolated, team-controlled virtual testbed subnets. It must never be executed against external or production networks.
- **NIST SP 800-82r3 & Purdue Model Alignment:** Security controls, trust boundaries, and pfSense Layer 3/4 ACLs strictly align with federal Operational Technology (OT) defense guidelines and microsegmentation standards.

## 🚀 Quickstart & Complete Pipeline Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Stage 1 (Layer 1): Generate Testbed Traffic (Optional / Testbed Host)
```bash
python infrastructure/traffic_generator.py
```

### 3. Stage 2 (Layer 2): Ingest & Normalize OT Telemetry
```bash
python src/log_parser.py
```

### 4. Stage 3 (Layer 2): Generate Incident Triage Reports
```bash
python src/timeline_generator.py
```

### 5. Stage 4 (Layer 3): Train & Benchmark Machine Learning Classifiers
```bash
python src/ml_detector.py
```

### 6. Stage 5: Perform Automated STRIDE Threat Verification
```bash
python validate_stride_threats.py
```

---

## 📊 Layer 3 Machine Learning Benchmark Summary

| Model Architecture | Accuracy | Recall (Target ≥ 95%) | Precision | FPR (Target ≤ 2%) | Inference Latency | Benchmark Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest Classifier** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **0.035 ms/sample** | **PASS** |
| **Decision Tree Classifier** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **0.003 ms/sample** | **PASS** |
| **Support Vector Machine (SVM)** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **0.003 ms/sample** | **PASS** |

---

## 📜 Compliance & Standards
* **OWASP Threat Dragon v2.3.0 Standard:** Repository-level threat model schema (`Team_4_Threat_Model.json`).
* **NIST SP 800-82 Rev 3:** Guide to Operational Technology (OT) Security.
* **UN Regulation No. 155 / ISO 21434:** Continuous cybersecurity monitoring & threat logging.
* **MIT License:** Permissive open-source research release.
