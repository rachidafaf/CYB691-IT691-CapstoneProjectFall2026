# Cyber-Physical & Network Defense Monitoring Testbed

**CYB 691 Cybersecurity Capstone — Team 4**  
**Official Repository:** [CYB691-IT691-CapstoneProjectFall2026](https://github.com/rachidafaf/CYB691-IT691-CapstoneProjectFall2026.git)  
**Target Platform:** Python 3.10+ (Cross-platform Linux/macOS/Windows) & Virtualized Purdue Model OT Architecture

---

## 📌 Executive Overview

Team 4 evaluates layered threat detection, network microsegmentation, telemetry normalization, and machine learning anomaly detection in a virtualized Operational Technology (OT) environment.

```
┌────────────────────────────────────────┐
│     Erick Espinosa (Layer 1)           │
│  pfSense + OpenPLC + Conpot Testbed    │
│  Traffic Generator & Suricata DPI Logs │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Ingestion & Handoff
┌────────────────────────────────────────┐
│     Rachid Afaf (Layer 2)              │
│  log_parser.py & timeline_generator.py │
│  ISO 8601 Normalization & Triage       │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Feature Vectors
┌────────────────────────────────────────┐
│     Rachid Afaf (Layer 3)              │
│  ml_detector.py ML Anomaly Classifier  │
│  Random Forest / Decision Tree / SVM   │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Hardening & Verification
┌────────────────────────────────────────┐
│     Anil Kumar (Layer 4)               │
│  pfSense Layer 3/4 ACL Hardening,      │
│  NIST SP 800-82r3 Validation & Editing │
└────────────────────────────────────────┘
```

---

## 👥 Team 4 Member Roles & Responsibilities

| Member Name | Assigned Role | Primary Technical Scope | Boundary Definition |
| :--- | :--- | :--- | :--- |
| **Erick Espinosa** | Infrastructure Lead | Purdue Model testbed, pfSense firewalls, OpenPLC/Conpot emulators, `traffic_generator.py`, Suricata DPI rules. | Builds VMs/containers & generates testbed traffic. Does not write telemetry parsing code. |
| **Rachid Afaf** | Security Architect | Standardized ISO 8601 JSON schema, `log_parser.py`, `timeline_generator.py`, incident triage reports. | Ingests, extracts tarballs, and normalizes telemetry. Does not train ML models. |
| **Rachid Afaf** | Detection Analytics Lead | Feature vector extraction, `ml_detector.py`, supervised ML classifier training (Random Forest/SVM), recall benchmarks. | Trains & evaluates ML models. Does not configure pfSense firewalls. |
| **Anil Kumar** | Security Hardening & Doc Lead | Layer 3/4 pfSense ACL enforcement, NIST SP 800-82r3 threat model mapping, technical report integration. | Designs security rules & edits documentation. Does not write telemetry code. |

---

## 📁 Detailed Repository Structure

```
CYB691-IT691-CapstoneProjectFall2026/
├── README.md                      # Project overview & pipeline execution instructions
├── LICENSE                        # MIT Open-Source License
├── SECURITY.md                    # Security reporting & secret sanitization policy
├── requirements.txt               # Python dependencies (pandas, numpy, scikit-learn, pytest)
├── .gitignore                     # Git tracking exclusions
│
├── infrastructure/                # Layer 1: Virtualized OT Testbed & Traffic Generation (Erick Espinosa)
│   ├── extracted_handoff/        # Auto-extracted handoff telemetry archives (git ignored)
│   ├── img/                      # Testbed architecture diagrams & network topology visuals
│   ├── logs/                     # Captured testbed logs (eve.json, iptables_drops.log, PCAPs)
│   ├── README.md                 # Testbed setup & deployment guide
│   ├── requirements.txt          # Infrastructure-specific dependencies
│   └── traffic_generator.py      # Modbus TCP traffic generation script
│
├── src/                           # Layer 2 & Layer 3: Telemetry Normalization & ML Detection (Rachid Afaf)
│   ├── log_parser.py             # Normalization engine (Ingests eve.json, iptables, CSV, .tar.gz archives)
│   ├── timeline_generator.py      # Incident triage & Markdown timeline generator
│   └── ml_detector.py            # Layer 3 ML classifier & anomaly detection engine (Random Forest, Decision Tree, SVM)
│
└── data/                          # Telemetry Datasets, ML Benchmark Results & Triage Reports
    ├── modbus_telemetry_dataset.csv # Raw OT traffic capture
    ├── normalized_telemetry.json  # Standardized ISO 8601 JSON records
    ├── incident_report.json       # Structured incident triage metrics
    ├── incident_timeline.md       # Executive Markdown triage report
    └── ml_evaluation_results.json # Layer 3 ML model performance & benchmark metrics
```

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
* **NIST SP 800-82 Rev 3:** Guide to Operational Technology (OT) Security.
* **UN Regulation No. 155 / ISO 21434:** Continuous cybersecurity monitoring & threat logging.
* **MIT License:** Permissive open-source research release.
