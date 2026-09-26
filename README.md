# CYB 691 Cybersecurity Capstone: Cyber-Physical and Network Defense Monitoring

**Course:** CYB 691 / IT 691 Cybersecurity Capstone (Fall 2026)  
**Team 4:** Cyber-Physical and Network Defense Monitoring  
**Repository:** [https://github.com/rachidafaf/CYB691-IT691-CapstoneProjectFall2026.git](https://github.com/rachidafaf/CYB691-IT691-CapstoneProjectFall2026.git)  

### Team Members & Roles
* **Rachid Afaf** — Security Architect, Lead Security Analyst & Documentation Lead
* **Erick Espinosa** — Infrastructure & OT Testbed Lead
* **Bhavesh Dalal** — Detection Analytics & Machine Learning Lead

---

## 📌 Executive Summary & Research Scope

Industrial Control Systems (ICS) and Operational Technology (OT) networks relying on legacy protocols like Modbus TCP frequently suffer from an inherent lack of authentication, encryption, and role-based access control. In an unsegmented flat industrial network, adversaries can issue unauthorized state-altering write commands (such as Function Codes `0x05` Write Single Coil or `0x06` Write Single Register) to manipulate physical processes and safety interlocks.

This project evaluates a layered OT defense architecture combining network microsegmentation, stateful Deep Packet Inspection (DPI), normalized telemetry triage, and supervised machine learning classifiers to detect, log, and contain unauthorized Modbus TCP state-altering write commands.

### Key Research Question
> *"How effectively does a layered OT defense architecture—combining network micro-segmentation, Suricata Deep Packet Inspection (DPI), normalized telemetry triage, and machine learning anomaly detection—detect, log, and contain unauthorized Modbus TCP commands in a virtualized OT network compared to an unsegmented flat network baseline?"*

### Performance Target Benchmarks
* **Detection Recall:** $\ge 95\%$ on state-altering write commands (`0x05`, `0x06`, `0x10`).
* **False-Positive Rate (FPR):** $\le 2.0\%$ under routine polling traffic.
* **Triage Processing Latency:** $\le 500\text{ ms}$ per 10,000 log records.

---

## 🏗️ Integrated 3-Layer System Architecture

```
┌──────────────────────────────────────────────────────────┐
│             Layer 1: Virtualized OT Testbed              │
│                 (Erick Espinosa - Lead)                  │
│   Purdue Levels 1-3 | pfSense Firewall | OpenPLC/Conpot  │
│   Outputs: modbus_telemetry_dataset.csv / eve.json       │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼ Ingests Raw Telemetry
┌──────────────────────────────────────────────────────────┐
│      Layer 2: Telemetry Normalization & IR Triage        │
│                  (Rachid Afaf - Lead)                    │
│   ISO 8601 Normalization | Delta-t Calculation           │
│   Scripts: src/log_parser.py & src/timeline_generator.py │
│   Outputs: normalized_telemetry.json / incident_timeline │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼ Ingests Feature Vectors
┌──────────────────────────────────────────────────────────┐
│       Layer 3: Detection Analytics & ML Models           │
│                 (Bhavesh Dalal - Lead)                   │
│   Rule-Based Thresholds vs. Supervised Classifiers       │
│   Metrics: Precision, Recall, FPR & Baseline Comparison  │
└──────────────────────────────────────────────────────────┘
```

---

## 📂 Repository Layout

```text
CYB691-IT691-CapstoneProjectFall2026/
├── README.md                      # Primary project overview and quickstart guide
├── LICENSE                        # MIT Open-Source License
├── SECURITY.md                    # Vulnerability reporting & secret sanitization policy
├── .gitignore                     # Git configuration for Python caches & build artifacts
├── requirements.txt               # Dependency specifications (pandas, numpy, pytest)
│
├── src/                           # Python Telemetry Normalization & Triage Pipeline
│   ├── log_parser.py              # Ingestion & ISO 8601 normalization engine
│   └── timeline_generator.py      # Correlation, metrics & markdown timeline generator
│
└── data/                          # Telemetry Datasets & Incident Artifacts
    ├── modbus_telemetry_dataset.csv  # Raw OT testbed capture
    ├── normalized_telemetry.json     # ISO 8601 normalized JSON event frames
    ├── incident_report.json          # Structured incident summary & metrics
    └── incident_timeline.md          # Chronological Markdown incident triage report
```

---

## 🚀 Quickstart & Pipeline Execution

### 1. Prerequisites & Environment Setup
* **Python:** Version 3.10 or higher (Python 3.12 recommended)
* **Dependencies:** `pandas>=2.0.0`, `numpy>=1.24.0`, `pytest>=7.0.0`

Clone the repository and install requirements:
```bash
# Clone the official repository
git clone https://github.com/rachidafaf/CYB691-IT691-CapstoneProjectFall2026.git
cd CYB691-IT691-CapstoneProjectFall2026

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

---

### 2. Execution Steps

The pipeline executes in two sequential stages:

#### Stage 1: Ingest & Normalize Raw Telemetry (`log_parser.py`)
Parses raw Modbus CSV/JSON captures, standardizes timestamps to ISO 8601, computes inter-arrival delta times ($\Delta t$), categorizes function codes, and assigns threat scores ($0 - 100$).

```bash
# Default execution (ingests data/modbus_telemetry_dataset.csv)
python src/log_parser.py

# Custom path execution
python src/log_parser.py -i data/modbus_telemetry_dataset.csv -o data/normalized_telemetry.json
```

#### Stage 2: Generate Incident Metrics & Timeline (`timeline_generator.py`)
Ingests the normalized JSON feature vectors, computes security metrics (Read/Write ratios, exception counts), and outputs structured JSON and Markdown triage reports.

```bash
# Default execution (ingests data/normalized_telemetry.json)
python src/timeline_generator.py

# Custom path execution
python src/timeline_generator.py -i data/normalized_telemetry.json -o data/incident_report.json -m data/incident_timeline.md
```

---

## 📊 Normalized Data Schema Contract (`normalized_telemetry.json`)

To ensure seamless integration between Layer 2 (Telemetry Normalization) and Layer 3 (ML Anomaly Detection), normalized records strictly follow this schema:

```json
{
  "event_id": "MODBUS-EVT-0005",
  "timestamp_iso": "2026-09-23T02:51:43.175714+00:00",
  "inter_arrival_ms": 201.46,
  "network": {
    "source_ip": "10.0.1.4",
    "dest_ip": "172.17.0.2",
    "destination_port": 502,
    "protocol": "Modbus_TCP"
  },
  "modbus": {
    "unit_id": 1,
    "function_code": 6,
    "function_name": "Write Single Register",
    "category": "WRITE",
    "risk_level": "HIGH",
    "payload_raw": "addr:0 val:1234",
    "payload_parsed": {
      "addr": "0",
      "val": "1234"
    },
    "exception_code": "IllegalDataAddr"
  },
  "security": {
    "action_taken": "monitored_alerted",
    "is_state_altering": true,
    "has_protocol_exception": true,
    "threat_score": 75
  }
}
```

---

## 📜 Regulatory Standards & Governance

* **NIST SP 800-82 Rev. 3:** Aligned with federal guidelines for OT microsegmentation, continuous monitoring, and zone boundary enforcement.
* **UN Regulation No. 155 (UN R155):** Meets requirements for cyber-physical threat logging and continuous security monitoring.
* **ISO/SAE 21434:** Supports risk management and threat modeling (STRIDE) across cyber-physical system interfaces.
* **License & Privacy:** Distributed under the permissive MIT License. Contains zero Personally Identifiable Information (PII) or proprietary vendor keys.
