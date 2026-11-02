# STRIDE Inventory & Security Property Audit

**Timestamp:** 2026-11-01T15:08:44.745003+00:00  
**Threat model:** `Team 4 Threat Model.json`  
**Conclusion:** PARTIAL - 2 property check(s) passed, 1 warning(s). Threat status is as recorded in the model ({'Open': 37}); this audit does not close threats.

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
| PROPERTY | P2 Normalized vs raw | PASS | 10 normalized Modbus events == 10 unique raw transactions; function codes {1: 2, 3: 2, 5: 1, 6: 3, 16: 2} match; 0 firewall drops == raw drop lines |
| PROPERTY | P3 ML evaluation | WARN | method checks passed; scenario record not yet confirmed by the team (RECONSTRUCTED - PENDING TEAM CONFIRMATION); without function_code, Random Forest recall falls to 0.0%: detection rests on the function code (rule baseline gives the same result); only 10 labelled events: metrics are not statistically stable |
