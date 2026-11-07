# STRIDE Inventory & Security Property Audit

**Timestamp:** 2026-11-03T15:00:06.730174+00:00  
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
| PROPERTY | P2 Normalized vs raw | PASS | 5 normalized Modbus events == 5 unique raw transactions; function codes {3: 3, 5: 1, 6: 1} match; 3 firewall drops == raw drop lines |
| PROPERTY | P3 ML evaluation | FAIL | no model evaluated on the current data: 0 events matched a scenario action ([] label values); at least 2 events of both classes are needed |
