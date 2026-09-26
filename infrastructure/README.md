# OT Testbed Infrastructure, Emulation, and Data Generation

This directory contains the deployment documentation, configuration scripts, and telemetry handoff artifacts for the virtualized Operational Technology (OT) testbed environment.

## 1. Cloud Architecture & Cost Governance
Provisioned within Microsoft Azure under the Virtual Network name `vnet-ot-testbed-dk` in the Denmark East region, utilizing standard cloud resource governance and budgeting controls. Standard HDD storage was utilized to minimize resource costs. Automated budget alerts ($5, $10, and $20 thresholds) and strict virtual machine auto-shutdown policies were enforced to protect student cloud credits.

![Azure Cost Management Budget Dashboard](Azure_Cost_Management_Budget_Dashboard.png)
*(Figure: Azure Cost Management dashboard displaying the active $20.00 monthly budget threshold and current spend tracking)*

## 2. Purdue Model & Subnet Micro-Segmentation
The environment is logically segregated to mirror Purdue Model Levels 1–3:
* **Level 3 (Supervisory/HMI Zone):** Management and monitoring boundary.
* **Level 2 (Control Zone):** Supervisory HMI and firewall routing.
* **Level 1 (Basic Control/PLC Cell):** Isolated containerized industrial emulators communicating over Modbus TCP.

## 3. Industrial Control System (ICS) Protocol Emulation
Containerized instances were deployed via Docker to emulate field devices and control logic:
* **Conpot Modbus TCP Emulator:** Stood up to simulate legacy ICS behavior and respond to polling.
* **OpenPLC v3:** Deployed to mimic programmable logic controller execution and register states.
* **Port Binding:** Actively listening on standard industrial **Modbus TCP Port 502** (mapped internally/externally as required).

## 4. Automated Data Generation & Attack Simulation
Python automation scripts leveraging `pymodbus` were executed to simulate:
* **Legitimate Polling:** Routine read requests (`0x03` Read Holding Registers) representing normal HMI monitoring.
* **Unauthorized Command Injection:** Malicious write commands targeting industrial coil and register states—specifically utilizing Modbus function codes **0x05** (Write Single Coil), **0x06** (Write Single Register), and **0x10** (Write Multiple Registers).

## 5. Deep Packet Inspection (DPI) & Telemetry Handoff
* **Suricata NSM:** Deployed inline to monitor traffic, parsing MBAP headers and payload bytes. Custom rules generated alerts stored in `eve.json` and `fast.log`.
* **Telemetry Handoff Archive:** All raw Suricata logs, firewall drop logs, and normalized CSV datasets have been bundled into `ot_telemetry_handoff_2026-09-23.tar.gz` for ingestion into Rachid's normalization and incident-triage pipeline.
