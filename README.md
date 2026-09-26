# Layer 2: OT Telemetry Normalization & Incident Response Triage Pipeline

**CYB 691 Cybersecurity Capstone — Team 4 (Cyber-Physical & Network Defense Monitoring)**  
**Author / Module Lead:** Rachid Afaf (Security Architect & Lead Security Analyst)  
**Target Platform:** Python 3.10+ (Cross-platform Linux/macOS/Windows)  

---

## 📌 Executive Overview

This module represents **Layer 2 (Telemetry Normalization & Incident Response Triage)** of Team 4's integrated cyber-physical defense architecture. It functions as the crucial bridge between **Layer 1 (Virtualized OT Testbed & Traffic Generation)** and **Layer 3 (Detection Analytics & ML Classifiers)**.

The pipeline ingests raw Operational Technology (OT) traffic captures and Deep Packet Inspection (DPI) alert logs, standardizes events into a unified ISO 8601 JSON event schema, computes operational timing features (such as inter-arrival delta times $\Delta t$), calculates threat risk scores, and synthesizes structured JSON incident reports alongside executive Markdown event timelines.

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
                   ▼ Normalized JSON
┌────────────────────────────────────────┐
│     Bhavesh Dalal (Layer 3)            │
│  ML Anomaly Model Training &           │
│  Rule-Based vs. ML Benchmarking        │
└────────────────────────────────────────┘
```

---

## 🛠️ Repository File Structure

```
.
├── log_parser.py            # Ingestion & ISO 8601 normalization engine
├── timeline_generator.py    # Metrics correlation & incident report generator
├── README.md                # Component documentation & quickstart guide
├── requirements.txt         # Python dependency specification
└── sample_data/
    ├── modbus_telemetry_dataset.csv  # Raw OT capture dataset
    ├── normalized_telemetry.json     # Standardized JSON output
    ├── incident_report.json          # Structured incident metrics
    └── incident_timeline.md          # Generated Markdown triage report
```

---

## 🚀 Quickstart & Installation Guide

### Prerequisites
* **Python 3.10** or higher
* Standard Python modules (`json`, `datetime`, `os`, `sys`) and `pandas`

### Installation Setup
```bash
# 1. Clone the repository
git clone https://github.com/your-team-repo/cyb691-team4-ot-defense.git
cd cyb691-team4-ot-defense/layer2-triage

# 2. Create a virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install required Python packages
pip install pandas
```

---

## ⚙️ Execution Workflow

The pipeline operates in two sequential stages:

### Stage 1: Run Telemetry Ingestion & Normalization
Execute `log_parser.py` to ingest raw Modbus CSV telemetry and output normalized JSON event frames:

```bash
python3 log_parser.py
```

**Key Execution Features:**
* Normalizes timestamps to standardized ISO 8601 strings.
* Categorizes Modbus Function Codes (e.g., distinguishing $0x01/0x03$ Read polling from $0x05/0x06/0x10$ Write state modifications).
* Calculates inter-arrival delta times ($\Delta t$ in milliseconds) between consecutive packets.
* Calculates security threat scores ($0 - 100$) based on state-altering write commands and protocol exception codes (`IllegalDataAddr`).
* Outputs `normalized_telemetry.json`.

### Stage 2: Generate Incident Metrics & Chronological Timeline
Execute `timeline_generator.py` to process normalized JSON records and generate security reports:

```bash
python3 timeline_generator.py
```

**Key Execution Features:**
* Computes Read/Write traffic ratios, protocol exception rates, and high-threat event distributions.
* Outputs `incident_report.json` for downstream ML feature extraction.
* Generates `incident_timeline.md`, an executive Markdown report containing chronological event tables and defensive triage recommendations.

---

## 📊 Normalized Event Schema Contract (`normalized_telemetry.json`)

To ensure seamless integration with Layer 3 (Bhavesh Dalal's ML models), every normalized log record adheres to the following JSON schema:

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

## 🧪 Automated Testing

Verify pipeline functionality using standard Python unittest framework:

```bash
# Run unit tests for parser and timeline generator
python3 -m unittest discover -s tests
```

---

## 📜 License & Compliance

* **License:** MIT License — Open-source capstone repository release.
* **Privacy & Sanitization:** All sample logs contain zero Personally Identifiable Information (PII) or proprietary vendor credentials.
* **Regulatory Alignment:** Designed to support continuous monitoring requirements under **UN Regulation No. 155** and **NIST SP 800-82 Rev. 3**.
