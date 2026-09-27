# Security Policy

## CYB691 Capstone Team 4 — Cyber-Physical & Network Defense Monitoring

### Supported Versions
This project is developed as part of the CYB691/IT691 Cybersecurity Capstone at SNHU (Fall 2026).

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

As this repository contains research code, virtualized OT infrastructure scripts, and telemetry analysis pipelines for industrial control systems (ICS/OT):

1. **Do NOT open public GitHub issues** for security vulnerabilities, credential disclosures, or infrastructure exposure.
2. Direct all vulnerability reports to the project maintainers:
   - **Rachid Afaf** — Security Architect & Lead Security Analyst (`log_parser.py`, `timeline_generator.py`)
   - **Erick Espinosa** — Infrastructure & OT Virtualization Lead (`infrastructure/traffic_generator.py`, testbed emulators)
   - **Rachid Afaf** — Detection Analytics Lead (`ml_detector.py`)
   - **Anil Kumar** — Security Hardening, Threat Modeling & Documentation Lead (pfSense Layer 3/4 ACLs, NIST validation)

## Data Privacy & Secret Sanitization Policy
- **No Credentials or API Keys:** All code, traffic generation scripts (`traffic_generator.py`), and configuration files are scanned with `Gitleaks` prior to committing.
- **RFC 1918 Private Addressing:** All telemetry, traffic simulation, and network logs strictly utilize private, non-routable IP ranges (e.g., `10.0.1.0/24`, `172.17.0.2/16`).
- **Zero PII:** Sample datasets and captured logs contain strictly synthetic or anonymized Modbus TCP control telemetry with zero personally identifiable information.
- **Safe Traffic Generation:** The `infrastructure/traffic_generator.py` script operates strictly in isolated, team-controlled virtual testbed subnets. It must never be executed against external or production networks.
- **NIST SP 800-82r3 & Purdue Model Alignment:** Security controls, trust boundaries, and pfSense Layer 3/4 ACLs strictly align with federal Operational Technology (OT) defense guidelines and microsegmentation standards.
