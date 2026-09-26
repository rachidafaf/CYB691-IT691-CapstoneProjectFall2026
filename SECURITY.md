# Security Policy

## CYB691 Capstone Team 4 - Cyber-Physical & Network Defense Monitoring

### Supported Versions
This project is developed as part of the CYB691/IT691 Cybersecurity Capstone at SNHU (Fall 2026).

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

As this repository contains research code and telemetry analysis pipelines for industrial control systems (ICS/OT):
1. **Do NOT open public GitHub issues** for security vulnerabilities or unintended credential leaks.
2. Direct all vulnerability reports to the project maintainers via email:
   - Rachid Afaf (Security Architect)
   - Erick Espinosa (Testbed Lead)
   - Bhavesh Dalal (Analytics Lead)

## Data Privacy & Secret Sanitization Policy
- **No Credentials or API Keys:** All code and configuration files are scanned with `Gitleaks` prior to committing.
- **RFC 1918 Private Addressing:** All telemetry and network logs utilize private, non-routable IP ranges (e.g., `10.0.1.0/24`, `172.17.0.0/16`).
- **Zero PII:** Sample datasets contain strictly synthetic or anonymized Modbus TCP control telemetry with zero personally identifiable information.
