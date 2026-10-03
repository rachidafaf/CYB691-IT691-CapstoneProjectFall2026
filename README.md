# Cyber-Physical & Network Defense Monitoring Testbed

**CYB 691 Cybersecurity Capstone — Team 4**  
**Official Repository:** [CYB691-IT691-CapstoneProjectFall2026](https://github.com/rachidafaf/CYB691-IT691-CapstoneProjectFall2026.git)  
**Target Platform:** Python 3.10+ (Cross-platform Linux/macOS/Windows) & Virtualized Purdue Model OT Architecture

---

## 📌 Executive Overview

Team 4 evaluates layered threat detection, network microsegmentation, telemetry normalization, and machine learning anomaly detection in a virtualized Operational Technology (OT) environment. The architecture is formally threat modeled using **OWASP Threat Dragon v2.3.0** (`Team_4_Threat_Model.json`).

```
┌────────────────────────────────────────┐
│     Erick Espinosa (Layer 1)           │
│  pfSense + OpenPLC + Conpot Testbed    │
│  Traffic Generator & Suricata DPI Logs │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Ingestion & Handoff (OT Network Boundary)
┌────────────────────────────────────────┐
│     Rachid Afaf (Layer 2)              │
│  log_parser.py & timeline_generator.py │
│  ISO 8601 Normalization & Triage       │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Feature Vectors (Analysis Evidence Boundary)
┌────────────────────────────────────────┐
│     RachidAfaf (Layer 3)            │
│  ml_detector.py ML Anomaly Classifier  │
│  Random Forest / Decision Tree / SVM   │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Hardening, STRIDE & Verification
┌────────────────────────────────────────┐
│     Rachid Afaf (Layer 4)               │
│  pfSense Layer 3/4 ACL Hardening,      │
│  Team_4_Threat_Model.json STRIDE Rules │
│  validate_stride_threats.py Auditor    │
└────────────────────────────────────────┘
                   │
                   ▼ Documentation
┌────────────────────────────────────────┐
│     Anil Kumar (Layer 5)               │
│                                        │
│                                        │
│            Auditor                     │
└────────────────────────────────────────┘
```

---

## 👥 Team 4 Member Roles & Responsibilities

| Member Name | Assigned Role | Primary Technical Scope | Boundary Definition |
| :--- | :--- | :--- | :--- |
| **Erick Espinosa** | Infrastructure Lead | Purdue Model testbed, pfSense firewalls, OpenPLC/Conpot emulators, `traffic_generator.py`, Suricata DPI rules. | Builds VMs/containers & generates testbed traffic. Does not write telemetry parsing code. |
| **Rachid Afaf** | Security Architect | Standardized ISO 8601 JSON schema, `log_parser.py`, `timeline_generator.py`, incident triage reports. | Ingests, extracts tarballs, and normalizes telemetry. Does not train ML models. |
| **Rachid Afaf** | Detection Analytics Lead | Feature vector extraction, `ml_detector.py`, supervised ML classifier training (Random Forest/SVM), recall benchmarks. | Trains & evaluates ML models. Does not configure pfSense firewalls. 
| **Rachid Afaf** | Security Hardening & Doc Lead | Layer 3/4 pfSense ACL enforcement, OWASP Threat Dragon STRIDE mapping (`Team_4_Threat_Model.json`), technical report integration. | Designs security rules & edits documentation. Does not write telemetry code. |
| **Anil Kumar** | Security Hardening & Doc Lead | Layer 4/4 technical report integration. |  edits documentation. |

---

## 📁 Detailed Repository Structure

```
CYB691-IT691-CapstoneProjectFall2026/
├── README.md                      # Project overview, pipeline execution & STRIDE docs
├── LICENSE                        # MIT Open-Source License
├── SECURITY.md                    # Security reporting, threat policy & secret sanitization
├── requirements.txt               # Python dependencies (pandas, numpy, scikit-learn, pytest)
├── .gitignore                     # Git tracking exclusions
├── Team_4_Threat_Model.json       # OWASP Threat Dragon v2.3.0 STRIDE Model (37 Open Threats)
├── validate_stride_threats.py     # Automated STRIDE finding & mitigation verification engine
│
├── infrastructure/                # Layer 1: Virtualized OT Testbed & Traffic Generation (Erick Espinosa)
│   ├── extracted_handoff/        # Auto-extracted handoff telemetry archives (git ignored)
│   ├── img/                      # Testbed architecture diagrams & network topology visuals
│   ├── logs/                     # Captured testbed logs (eve.json, iptables_drops.log, PCAPs)
│   ├── README.md                 # Testbed setup & deployment guide
│   ├── requirements.txt          # Infrastructure-specific dependencies
│   └── traffic_generator.py      # Modbus TCP traffic generation script
│
├── src/                           # Layer 2 & Layer 3: Telemetry Normalization & ML Detection
│   ├── log_parser.py             # Normalization engine (Ingests eve.json, iptables, CSV, .tar.gz)
│   ├── timeline_generator.py      # Incident triage & Markdown timeline generator
│   └── ml_detector.py            # Layer 3 ML classifier & anomaly detection engine
│
├── img/                           # 
│   ├── STRIDE\_1.png ... STRIDE\_42.png # Figure screenshots for all 42 threat model items
│
└── data/                          # Datasets, ML Results, Triage Reports & STRIDE Verification
    ├── modbus_telemetry_dataset.csv # Raw OT traffic capture (20 frames, 12 unauthorized writes)
    ├── normalized_telemetry.json  # Standardized ISO 8601 JSON records
    ├── incident_report.json       # Structured incident triage metrics
    ├── incident_timeline.md       # Executive Markdown triage report
    ├── ml_evaluation_results.json # Layer 3 ML model performance & benchmark metrics
    ├── stride_validation_report.json # Automated STRIDE threat validation execution log
    └── stride_validation_report.md   # Executive STRIDE threat verification summary
	
```

---

## 🛡️ Threat Modeling & STRIDE Security Architecture (OWASP Threat Dragon v2.3.0)

Our project integrates a complete, repository-level threat model saved as **`Team_4_Threat_Model.json`** compliant with **OWASP Threat Dragon v2.3.0**. The model tracks **37 open STRIDE threats** across 2 distinct **Trust Boundaries**:
The system threat architecture is modeled in **OWASP Threat Dragon v2.3.0 JSON** (`Team_4_Threat_Model.json`). It encompasses **37 open STRIDE threats** and **2 critical trust boundaries** (`OT Network Boundary` and `Analysis Evidence Boundary`), illustrated across 42 screenshot figures in the `/img/` directory (`img/STRIDE_1.png` through `img/STRIDE_42.png`).


### 1. Key Trust Boundaries
* **OT Network Boundary (`curve-ot-boundary`):** Segregates the isolated Purdue Model Level 1–3 OT testbed (pfSense, OpenPLC, Conpot, Suricata) from enterprise IT and developer workstations.
* **Analysis Evidence Boundary (`curve-analysis-boundary`):** Enforces cryptographic and execution isolation around cross-zone telemetry archive ingestion (`.tar.gz`), log normalization (`log_parser.py`), incident triage (`timeline_generator.py`), machine learning classifier training (`ml_detector.py`), and post-mortem report artifacts.

### 2. STRIDE Category Breakdown (37 Open Threats)
| STRIDE Category | Count | Primary Risk Vectors | Key Defensive Mitigations |
| :--- | :---: | :--- | :--- |
| **Spoofing** | 3 | Operator/developer impersonation, uncontrolled test commands | Named user accounts, MFA, RBAC, approval workflows, append-only audit logs |
| **Tampering** | 18 | Modbus write command injection (`FC05`/`FC06`/`FC15`/`FC16`), EVE log modification, dataset poisoning, report alteration | pfSense ACLs, Suricata write blocking, SHA-256 sidecar hashes, signed manifests |
| **Repudiation** | 1 | Reports unprovable from raw telemetry evidence | Source file SHA-256 hashes, git commit IDs, execution timestamps, signed manifests |
| **Information Disclosure** | 5 | EVE log OT layout exposure, unencrypted archive transit, committed repo secrets | Gitleaks scanning, RFC 1918 private IPs, restricted storage permissions, data redaction |
| **Denial of Service** | 5 | Unintended traffic floods, Suricata packet ring drops, ML feature memory exhaustion | Rate limits, SPAN/TAP drop monitoring, bounded batch limits, memory quotas |
| **Elevation of Privilege** | 5 | Conpot container breakout, Tar-Slip directory traversal in `log_parser.py`, malicious dependencies | Non-privileged Docker sandboxing, strict path verification, `pip-audit`, pinned package hashes |

### 3. Policy Validation Checklist Gaps
The threat model tracks 8 critical policy validation checklist items:
1. **CRITICAL:** Prove Purdue-zone network isolation (zero external/production connectivity).
2. **CRITICAL:** Restrict Modbus/TCP port `502` and state-altering write function codes (`FC05`, `FC06`, `FC15`, `FC16`).
3. **CRITICAL:** Hash and digitally sign telemetry archives (`.tar.gz`) to preserve immutable evidence chains.
4. **CRITICAL:** Sandbox archive decompression and `log_parser.py` execution within Docker containers.
5. **HIGH:** Validate pfSense Layer 3/4 ACLs, Suricata rulesets, and administrative MFA controls.
6. **HIGH:** Validate source code, third-party dependency, dataset, and ML model provenance.
7. **MEDIUM:** Define data classification, sensitive field redaction, retention, backup, and disaster recovery.

---

## 🚀 Quickstart & Complete Pipeline Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Stage 1 (Layer 1): Generate Testbed Traffic (Optional / Testbed Host)
```bash
python infrastructure/traffic_generator.py
```
*Simulates Modbus TCP read/write polling and state-altering traffic within the virtualized Purdue Model testbed.*

### 3. Stage 2 (Layer 2): Ingest & Normalize OT Telemetry
```bash
python src/log_parser.py
```
*Dynamically detects, extracts `.tar.gz` handoff archives, ingests Suricata `eve.json`, `iptables_drops.log`, and Modbus CSVs, outputting `data/normalized_telemetry.json`.*

### 4. Stage 3 (Layer 2): Generate Incident Triage Reports
```bash
python src/timeline_generator.py
```
*Ingests `data/normalized_telemetry.json` and outputs structured `data/incident_report.json` and `data/incident_timeline.md`.*

### 5. Stage 4 (Layer 3): Train & Benchmark Machine Learning Classifiers
```bash
python src/ml_detector.py
```
*Ingests `data/normalized_telemetry.json`, trains Random Forest, Decision Tree, and SVM classifiers, and generates `data/ml_evaluation_results.json`.*

### 6. Stage 5 (Layer 4): Perform Automated STRIDE Threat Verification
```bash
python validate_stride_threats.py
```
*Parses `Team_4_Threat_Model.json` (Threat Dragon v2.3.0), validates all 37 open STRIDE threats against project files, datasets, and scripts, and outputs `data/stride_validation_report.json` and `data/stride_validation_report.md`.*

---

## 📊 Layer 3 Machine Learning Benchmark Summary

| Model Architecture | Accuracy | Recall (Target ≥ 95%) | Precision | FPR (Target ≤ 2%) | Inference Latency | Benchmark Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest Classifier** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **0.035 ms/sample** | **PASS** |
| **Decision Tree Classifier** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **0.003 ms/sample** | **PASS** |
| **Support Vector Machine (SVM)** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **0.003 ms/sample** | **PASS** |

**Top Model Features:** `is_state_altering` (28.0%), `inter_arrival_ms` (24.0%), `threat_score` (21.9%).

---

## 📜 Compliance & Standards
* **OWASP Threat Dragon v2.3.0:** Threat Modeling & STRIDE Validation Schema.
* **NIST SP 800-82 Rev 3:** Guide to Operational Technology (OT) Security.
* **UN Regulation No. 155 / ISO 21434:** Continuous cybersecurity monitoring & threat logging.
* **MIT License:** Permissive open-source research release.
