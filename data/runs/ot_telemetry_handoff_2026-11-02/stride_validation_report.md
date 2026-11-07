# STRIDE Inventory & Security Property Audit

**Timestamp:** 2026-11-03T15:00:21.581154+00:00  
**Threat model:** `Team 4 Threat Model.json`  
**Conclusion:** FAILED - 1 check(s) failed, 0 warning(s). Threat status is as recorded in the model ({'Open': 37}); this audit does not close threats.

> INVENTORY rows confirm that artifacts exist and are well formed. PROPERTY rows record a security property that was actually exercised. Only PROPERTY rows are evidence of a control working, and none of them closes a threat-model entry by itself.

## Threat model inventory

- 37 threats on 32 components, 5 trust boundaries
- STRIDE: {'Spoofing': 2, 'Tampering': 19, 'Repudiation': 2, 'Denial of Service': 5, 'Elevation of Privilege': 6, 'Information Disclosure': 3}
- Severity: {'High': 27, 'Medium': 5, 'Critical': 5}
- Status recorded in the model: {'Open': 37}

## Checks

| Kind | Check | Result | Details |
| :--- | :--- | :---: | :--- |
| INVENTORY | Threat model structure | INVENTORY | 37 threats on 32 components, 5 trust boundaries; status as recorded in the model: {'Open': 37} |
| INVENTORY | Trust boundary 'OT Network Boundary' | INVENTORY | present in model |
| INVENTORY | Trust boundary 'Analysis Evidence Boundary' | INVENTORY | present in model |
| INVENTORY | Policy & licence files | INVENTORY | present: SECURITY.md, requirements.txt, THIRD_PARTY_LICENSES.md, LICENSE (existence only - not a security test) |
| PROPERTY | P1 Parser controls | PASS | exercised: Tar-Slip and link members refused, '-- No entries --' -> 0 drops, real drop -> 1, non-Modbus EVE ignored, function_raw 6 preserved |
| PROPERTY | P2 Normalized vs raw | PASS | 0 normalized Modbus events == 0 unique raw transactions; function codes {} match; 1 firewall drops == raw drop lines |
| PROPERTY | P3 ML evaluation | FAIL | no model evaluated on the current data: scenario record rejected: /repo/infrastructure/extracted_handoff/ot_telemetry_handoff_2026-11-02/handoff/scenario_file.csv: missing column(s) for ['authorized']; header is ['timestamp', 'source_ip', 'dest_ip', 'function_code', 'action'] |
