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
│  Raw PCAP / CSV / Suricata EVE Logs    │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Ingestion
┌────────────────────────────────────────┐
│     Rachid Afaf (Layer 2)              │
│  log_parser.py & timeline_generator.py │
│  ISO 8601 Normalization & Triage       │
└──────────────────┬─────────────────────┘
                   │
                   ▼ Feature Vectors
┌────────────────────────────────────────┐
│     Bhavesh Dalal (Layer 3)            │
│  ML Anomaly Model Training &           │
│  Rule-Based vs. ML Benchmarking        │
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
| **Erick Espinosa** | Infrastructure Lead | Purdue Model testbed, pfSense firewalls, OpenPLC/Conpot emulators, Suricata DPI rules. | Builds VMs/containers & generates traffic. Does not write telemetry scripts. |
| **Rachid Afaf** | Security Architect | Standardized JSON schema, `log_parser.py`, `timeline_generator.py`, incident triage reports. | Ingests & normalizes telemetry. Does not train ML models. |
| **Bhavesh Dalal** | Detection Analytics Lead | Feature vector extraction, supervised ML classifier training (Random Forest/SVM), recall benchmarks. | Trains & evaluates ML models. Does not configure pfSense firewalls. |
| **Anil Kumar** | Security Hardening & Doc Lead | Layer 3/4 pfSense ACL enforcement, NIST SP 800-82r3 threat model mapping, technical editing. | Designs security rules & edits documentation. Does not write telemetry code. |

---

## 📁 Repository Structure

```
CYB691-IT691-CapstoneProjectFall2026/
├── README.md                      # Project overview & execution instructions
├── LICENSE                        # MIT Open-Source License
├── SECURITY.md                    # Security reporting & secret sanitization policy
├── requirements.txt               # Python dependencies
├── .gitignore                     # Git tracking exclusions
│
├── src/                           # Python Source Code (Rachid Afaf)
│   ├── log_parser.py             # Normalization & ingestion engine
│   └── timeline_generator.py      # Triage & Markdown timeline generator
│
└── data/                          # Telemetry Datasets & Triage Reports
    ├── modbus_telemetry_dataset.csv # Raw OT traffic capture (Erick Espinosa)
    ├── normalized_telemetry.json  # Standardized ISO 8601 JSON records
    ├── incident_report.json       # Structured incident metrics (Bhavesh Dalal ML input)
    └── incident_timeline.md       # Executive Markdown triage report
```

---

## 🚀 Quickstart & Pipeline Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Stage 1: Telemetry Ingestion & Normalization
```bash
python src/log_parser.py
```
*Ingests `data/modbus_telemetry_dataset.csv` and outputs `data/normalized_telemetry.json`.*

### 3. Run Stage 2: Incident Triage & Timeline Generation
```bash
python src/timeline_generator.py
```
*Ingests `data/normalized_telemetry.json` and outputs `data/incident_report.json` and `data/incident_timeline.md`.*

---

## 📜 Compliance & Standards
* **NIST SP 800-82 Rev 3:** Guide to Operational Technology (OT) Security.
* **UN Regulation No. 155 / ISO 21434:** Continuous cybersecurity monitoring & threat logging.
* **MIT License:** Permissive open-source research release.
