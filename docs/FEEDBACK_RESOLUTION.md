# Report 1 Feedback — Resolution Tracker

**Assessed:** `team4-progress-report-1.docx` (submitted Oct 11), repository revision `707f8f0`, grade 81/100.  
**This tracker:** 2026-11-01 (version/figure/results items updated 2026-11-14; Step 7 content-distinguishable capture added 2026-11-15).

**Status key:**
* ✅ **Resolved in repo:** code, data or documentation changed, with evidence.
* 🟡 **Resolved, team action needed:** the repo change is done, but a fact only the team can supply (or confirm) is still open.
* 📝 **Carry into Report 2:** the fix lives in the report text, and the repo provides the content.

The submitted Report 1 `.docx` is unchanged (it is the graded record). Report 2 must take its text from the README sections cited below.

| # | Deduction (points) | What was wrong | What changed | Where to verify | Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| 1 | Peer-reviewed sources (−2) | Mostly standards and documentation; ML literature not identified; [2] imprecise | Nine peer-reviewed studies added [7]–[15], metadata checked against DOI/publisher records. [2] is now Williams, *Computers in Industry* 24(2–3):141–158, 1994. | README 2, 11; `docs/RESEARCH_SYNTHESIS.md` | 🟡 Each owner must read the full papers |
| 2 | Method-level comparison (−3) | Thematic background only | Comparison table (method / finding / limitation / effect on our design) driving baseline, labels, splits, Isolation Forest purpose | README 2; `docs/RESEARCH_SYNTHESIS.md` 1–5 | 📝 🟡 |
| 3 | Environment specification (−1) | Versions, locations, interfaces, implemented vs planned not established | Component table with status, address, interface and evidence; commands to record each version | `infrastructure/README.md` 1–2, 6; `versions.txt` in each handoff | ✅ **Deployed versions recorded (2026-11-14): Suricata 7.0.3 RELEASE, pymodbus 3.8.6, iptables 1.8.10 (nf_tables); now written into every handoff `versions.txt`** |
| 4 | Parser loses function codes; empty marker accepted (−1) | `function_raw` missed; non-Modbus events normalized; `-- No entries --` became a drop | Parser keeps `modbus.request.function_raw`, normalizes only `event_type == "modbus"`, rejects the empty marker, removes exact duplicates with an audit trail. | `src/log_parser.py`; `data/parser_integrity_report.json`; validator P2; `tests/test_pipeline.py` | ✅ |
| 5 | Unbounded "zero blind spots" requirement (−1) | No case set or observation conditions | R1–R4 rewritten with case set (C1–C6), repetitions, conditions, expected observation and evidence. | README 4 | ✅ |
| 6 | Third-party terms (−1) | Only the MIT licence for own code | Separate tables for tools, libraries/images and captured data; concrete pre-release check (owner, commands, gate). | `THIRD_PARTY_LICENSES.md` | 🟡 Anil to record the data release decision before going public |
| 7 | Matched comparison undefined (−1) | No shared cases, independent ground truth or attribution | Shared case set C1–C6, scenario-record ground truth, evidence-attribution table | README 5; `ablation-results.md` | ✅ **Executed: three matched source-separable captures (11-04, 11-07, 11-14, 360 actions each) + the Step 7 content-distinguishable capture (11-15, 664 actions incl. insider anomalies A1–A5)** |
| 8 | Ground truth from predictor features (−1) | Labels from `threat_score` / `is_state_altering` | Labels come from the scenario record joined by timestamp (`src/scenario.py`). Request-time features only; response-only and operation-encoding features removed; no-function-code ablation and rule baseline added. | `src/ml_detector.py`, `src/scenario.py`; README 6 | ✅ **Scenario record confirmed by Erick** |
| 9 | Oversampling before split (−1) | Copies of the single positive in train and test | Split first, oversample training folds only. Duplicates removed. Leave-one-generator-run-out added. Pooled metrics. | `src/ml_detector.py`; `tests/test_pipeline.py::test_test_fold_rows_are_never_resampled_into_training` | ✅ |
| 10 | Latency mislabelled (−1) | Timer included training; Isolation Forest timer included fit | `training_time_avg_ms`, `prediction_latency_per_sample_ms`, `fit_time_total_ms` and `total_execution_time_ms` stored separately, with definitions and hardware | `data/ml_evaluation_results.json`; README 6.2 | ✅ |
| 11 | No forward schedule with due points (−1) | Schedule covered past weeks | Ten deliverables with owner, due date, reviewer and status | README 8 | ✅ **Steps 7–12 executed; see `docs/ablation-results.md` and `docs/Team4_Progress_Report_2.docx`** |
| 12 | Review / integration / conflict process (−1) | Incomplete | Artifact × author × reviewer × integrator matrix with turnaround times | README 3 | 📝 |
| 13 | Inconsistent environment record (−1) | Report says local OpenPLC/pfSense; README says Azure; screenshot shows nginx | Evidence-derived reconciliation for the 2026-09-26 handoff: Azure VM, Conpot target, nginx placeholder, no firewall in path | `infrastructure/README.md` E1–E8 | 🟡 Report 2 must say "Conpot" for the 09-26 capture. **The Nov-2026 captures use a real pymodbus 3.8.6 PLC with iptables + Suricata; see `infrastructure/README.md` 6** |
| 14 | Inventory presented as security validation (−1) | Parser PASS by grepping source; ML PASS without metrics | Validator separates INVENTORY from PROPERTY (P1 hostile inputs, P2 raw reconciliation, P3 label/feature/timing). Warnings give PARTIAL; any fail gives FAILED. | `validate_stride_threats.py`; `data/stride_validation_report.md`; `tests/test_pipeline.py` | ✅ |
| 15 | AI-use dates and users (−1) | Missing | Every row now has date or period, user and reviewer | README 9 | 🟡 Named reviewers must sign off |
| 16 | No in-text IEEE citations (−1) | Bibliography not linked to claims | Bracketed citations attached to claims in README | README | 📝 Apply the same in the Report 2 body |

## Priorities and metadata items (no point loss)

| Item | Resolution | Status |
| :--- | :--- | :---: |
| Parser corrected | Item 4 | ✅ |
| Independent scenario-derived labels and splits | Items 8, 9 | ✅ (scenario record confirmed by Erick) |
| Comparison and timing valid | Items 7, 10 | ✅ |
| Isolation Forest purpose | **Batch screening of the current capture**: fit and score on the same batch, contamination fixed in advance, labels used only to score. Not claimed as a new-observation detector. | ✅ |
| Dataset filenames and counts (09-26) | 20,074 EVE records; 20 `modbus` records = 10 unique transactions (4 reads, 6 writes); 67 alerts; `iptables_drops.log` empty. `docs/message.txt` (Week 7 post) is a historical submission and is superseded. | ✅ |
| Unconditional success statements | Validator conclusion derived from the checks | ✅ |
| NIST SP 800-82r3 author list | All 10 authors (6 NIST, 4 MITRE) | ✅ |
| Exact Purdue publication [2] | Williams 1994, *Computers in Industry*, doi:10.1016/0166-3615(94)90017-5 | ✅ |
| Modbus spec date | Apr. 26, 2012 | ✅ |
| Langner subtitle | "A Technical Analysis of What Stuxnet's Creators Tried to Achieve" | ✅ |
| Suricata version and sections | Cited as release 7.0.12, 8.15 "Modbus Keyword". **Deployed version recorded: Suricata 7.0.3 RELEASE** (vm-fwsensor, 2026-11-14); align the citation's release number with the deployed one in Report 2. | ✅ |
| MITRE ATT&CK for ICS version and techniques | v20.0 (Oct. 13, 2026): T1692.001, T0836, T0814 | ✅ |
| Old reference [7] | Replaced the unverifiable ICISSP 2015 entry with the verified Gao & Morris, JDFSL 2014. | ✅ |
| Readable threat-model figure | Two clean STRIDE figures produced (Graphviz, PNG+SVG+`.dot`): Figure 1 OT Network Boundary, Figure 2 Analysis/Evidence Boundary, each mapping STRIDE threats to the validated controls. | ✅ |

## New findings surfaced during this review (for Report 2)

1. **Classifier adds nothing beyond a function-code rule.**
   - Without `function_code`, recall drops to 0 % on the 09-26 capture.
   - **Update (2026-11-14): confirmed across three matched captures — ML operates at chance (recall ≈ FPR) because authorized/unauthorized Modbus payloads are byte-identical except source IP; see `ablation-results.md`.** **Update (2026-11-15): the content-distinguishable extension (Step 7) was executed** — insider writes from the authorized HMI with out-of-range address/value and burst timing. The content layer separates them (per-class ~100%), but the content ML (72.11% / 0.68%) is statistically identical to a static content rule (71.81% / 0.68%), so the ML still does not beat the rule — the conclusion holds one layer deeper.
2. **No write succeeded on Conpot.** Conpot's default template returned Illegal Data Address for every request. **Update (2026-11-14): resolved on the pymodbus 3.8.6 PLC — all four write cases (C3–C6) confirmed by read-back (`post == commanded`, `post != pre`); see `readback-verification.md`.**
3. **The archived generator did not produce the 09-26 capture.** Run logs and script versions must be recorded per run. **Update: the Nov captures record versions in `versions.txt` and the generator is the one that ran.**
4. **NUL bytes in captured payloads (09-26).** SQLite `LENGTH()` stops at the first NUL; PostgreSQL rejects NUL in `jsonb`/`text` — both handled.
5. **Privacy:** the 09-26 handoff includes public SSH-client IPs and Azure host names; see `THIRD_PARTY_LICENSES.md` 3.

## Deployed environment (recorded 2026-11-14, Azure `rg-cyb691-lab-dk`)

| Component | VM | Address | Version |
| :--- | :--- | :--- | :--- |
| Suricata IDS/DPI | vm-fwsensor | 10.0.2.4 | 7.0.3 RELEASE |
| iptables firewall | vm-fwsensor | 10.0.2.4 | 1.8.10 (nf_tables) |
| pymodbus PLC server | vm-plc | 10.0.3.10:502 | 3.8.6 |
| HMI (authorized) | vm-hmi | 10.0.1.10 | — |
| Workstation (unauthorized) | vm-ws | 10.0.1.20 | — |

All VMs set to UTC. Versions are captured into each handoff's `versions.txt` at packaging time.
