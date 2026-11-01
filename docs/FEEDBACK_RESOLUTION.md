# Report 1 Feedback — Resolution Tracker

**Assessed:** `team4-progress-report-1.docx` (submitted Oct 11), repository revision `707f8f0`, grade 81/100.  
**This tracker:** 2026-11-01.

**Status key:**
* ✅ **Resolved in repo:** code, data or documentation changed, with evidence.
* 🟡 **Resolved, team action needed:** the repo change is done, but a fact only the team can supply (or confirm) is still open.
* 📝 **Carry into Report 2:** the fix lives in the report text, and the repo provides the content.

The submitted Report 1 `.docx` is unchanged (it is the graded record). Report 2 must take its text from the README sections cited below.

| # | Deduction (points) | What was wrong | What changed | Where to verify | Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| 1 | Peer-reviewed sources (−2) | Mostly standards and documentation; ML literature not identified; [2] imprecise | Nine peer-reviewed studies added [7]–[15], metadata checked against DOI/publisher records. [2] is now Williams, *Computers in Industry* 24(2–3):141–158, 1994. | README §2, §11; `docs/RESEARCH_SYNTHESIS.md` | 🟡 Each owner must read the full papers (due Nov 13) |
| 2 | Method-level comparison (−3) | Thematic background only | Comparison table (method / finding / limitation / effect on our design) driving baseline, labels, splits, Isolation Forest purpose | README §2; `docs/RESEARCH_SYNTHESIS.md` §1–5 | 📝 🟡 |
| 3 | Environment specification (−1) | Versions, locations, interfaces, implemented vs planned not established | Component table with status (Evidenced / Claimed / Placeholder / Planned), address, interface and evidence; commands to record each version | `infrastructure/README.md` §1–2 | 🟡 Erick to fill the "to record/confirm" versions (due Nov 4) |
| 4 | Parser loses function codes; empty marker accepted (−1) | `function_raw` missed; non-Modbus events normalized; `-- No entries --` became a drop | Parser keeps `modbus.request.function_raw`, normalizes only `event_type == "modbus"`, rejects the empty marker, removes exact duplicates with an audit trail. The validator reconciles normalized against raw (10 = 10, identical function codes, 0 drops). | `src/log_parser.py`; `data/parser_integrity_report.json`; validator P2; `tests/test_pipeline.py` | ✅ |
| 5 | Unbounded "zero blind spots" requirement (−1) | No case set or observation conditions | R1–R4 rewritten with case set (C1–C6), repetitions, conditions (sensor drop counter = 0), expected observation and evidence. The phrase "zero blind spots" was removed and the FC 0x10 hex typo ("0x16") fixed. | README §4 | ✅ |
| 6 | Third-party terms (−1) | Only the MIT licence for own code | Separate tables for tools, libraries/images and captured data/reference material; concrete pre-release check (owner, commands, gate). Wrong institution and "synthetic data" wording removed. | `THIRD_PARTY_LICENSES.md` | 🟡 Anil to record the data release decision before going public |
| 7 | Matched comparison undefined (−1) | No shared cases, independent ground truth or attribution | Shared case set C1–C6, scenario-record ground truth, a table of what evidence establishes containment / alerting / detection / outcome, and an observed row with honest status | README §5 | ✅ (runs planned for Nov 9) |
| 8 | Ground truth from predictor features (−1) | Labels from `threat_score` / `is_state_altering` | Labels come from `data/scenario_actions.json` joined by timestamp (`src/scenario.py`). Tests show that flipping features cannot change labels. Request-time features only; the response-only feature and the operation-encoding text feature were removed; no-function-code ablation and rule baseline added. | `src/ml_detector.py`, `src/scenario.py`, `src/database.py`; README §6 | 🟡 Erick to confirm the reconstructed scenario record (due Nov 3) |
| 9 | Oversampling before split (−1) | Copies of the single positive in train and test | Split first, oversample training folds only. Duplicates removed before splitting. Leave-one-generator-run-out added. Pooled metrics, so each event is tested exactly once. A test asserts no test row reaches its training fold. | `src/ml_detector.py`; `tests/test_pipeline.py::test_test_fold_rows_are_never_resampled_into_training` | ✅ |
| 10 | Latency mislabelled (−1) | Timer included training; Isolation Forest timer included fit | `training_time_avg_ms` (fit), `prediction_latency_per_sample_ms` (predict on the unseen fold ÷ rows), `fit_time_total_ms` (Isolation Forest) and `total_execution_time_ms` are stored separately, with written definitions and hardware (OS, CPU, logical CPUs, Python version) | `data/ml_evaluation_results.json` → `timing_definitions`, `workload_and_hardware`; README §6.2 | ✅ |
| 11 | No forward schedule with due points (−1) | Schedule covered past weeks | Ten deliverables with owner, internal due date, reviewer and status from Nov 1 to Nov 15 | README §8 | 🟡 Confirm dates against the Report 2 deadline |
| 12 | Review / integration / conflict process (−1) | Incomplete | Artifact × author × reviewer × integrator matrix with turnaround times; decision, merge, disagreement and escalation steps with timeboxes | README §3 | 📝 |
| 13 | Inconsistent environment record (−1) | Report says local OpenPLC/pfSense; README says Azure; screenshot shows nginx | Evidence-derived reconciliation: the capture came from Azure VM `vm-firewall-gateway`; the Modbus target was **Conpot** (`honeynet/conpot:latest`, 502 → 5020); `openplc_runtime` was an `nginx:alpine` placeholder; no firewall in the path; all requests got exceptions; the archived generator is not the one that made the capture | `infrastructure/README.md` E1–E8 | 🟡 Erick to confirm whether any local deployment exists; Report 2 must say "Conpot" where it said "OpenPLC" |
| 14 | Inventory presented as security validation (−1) | Parser PASS by grepping source; ML PASS without metrics; SUCCESS despite warnings | Validator separates INVENTORY from PROPERTY. P1 imports the parser and drives it with hostile inputs; P2 reconciles with raw evidence; P3 checks labels, features, timing and Isolation Forest, then compares targets. Warnings give PARTIAL; any fail gives FAILED. Your negative control now FAILs all three checks. | `validate_stride_threats.py`; `data/stride_validation_report.md`; `tests/test_pipeline.py::test_validator_negative_control_reproduces_professor_probe` | ✅ |
| 15 | AI-use dates and users (−1) | Missing | Every row now has date or period, user and reviewer | README §9 | 🟡 Named reviewers must sign off the 11-01 rows |
| 16 | No in-text IEEE citations (−1) | Bibliography not linked to claims | Bracketed citations attached to claims in README §1, §2, §4, §6, §7 | README | 📝 Apply the same in the Report 2 body |

## Priorities and metadata items (no point loss)

| Item | Resolution | Status |
| :--- | :--- | :---: |
| Parser corrected | Item 4 | ✅ |
| Independent scenario-derived labels and splits | Items 8, 9 | ✅ / 🟡 confirmation |
| Comparison and timing valid | Items 7, 10 | ✅ |
| Isolation Forest purpose | **Batch screening of the current capture**: fit and score on the same batch, contamination fixed in advance (`auto`, previously derived from the labels), labels used only to score. Not claimed as a new-observation detector. | ✅ |
| Dataset filenames and counts | 20,074 EVE records; 20 `modbus` records = 10 unique transactions (4 reads, 6 writes); 67 alerts; `iptables_drops.log` empty. Used consistently in README, infrastructure README and SECURITY.md. `docs/message.txt` (Week 7 post: "20,075 records", "local", "synthetic") is a historical submission and is superseded. | ✅ |
| Unconditional success statements | Validator conclusion derived from the checks; SECURITY.md output updated | ✅ |
| NIST SP 800-82r3 author list | All 10 authors (6 NIST, 4 MITRE) | ✅ |
| Exact Purdue publication [2] | Williams 1994, *Computers in Industry*, doi:10.1016/0166-3615(94)90017-5 | ✅ |
| Modbus spec date | Apr. 26, 2012 | ✅ |
| Langner subtitle | "A Technical Analysis of What Stuxnet's Creators Tried to Achieve" | ✅ |
| Suricata version and sections | Cited as release 7.0.12, ch. 8, §8.15 "Modbus Keyword" (the section number differs between 7.0.x releases). Deployed version still to be recorded (`suricata -V`). | 🟡 |
| MITRE ATT&CK for ICS version and techniques | v20.0 (Oct. 13, 2026): T1692.001 Command Message (legacy ID T0855 redirects to it), T0836, T0814 | ✅ |
| Old reference [7] | "Morris & Gao, ICISSP 2015, pp. 22–29" could not be verified at that venue. Replaced with the verified Gao & Morris, JDFSL 2014. | ✅ |
| Readable threat-model figure | Not done in the repository. Export from Threat Dragon at ≥ 200 % zoom and split into two figures (OT Network Boundary; Analysis Evidence Boundary). | 🟡 Anil, for Report 2 (Nov 15) |

## New findings surfaced during this review (for Report 2)

1. **Classifier adds nothing beyond a function-code rule on the current capture.**
   - Without `function_code`, recall drops to 0 %.
   - R3 stays unmet. Planned runs add authorized-writer and unauthorized-reader cases so the label is not a function of the function code alone.
2. **No write succeeded.** Conpot's default template answered every request with Illegal Data Address, so the capture shows attempts, not state changes.
3. **The archived generator did not produce the capture.** Run logs and script versions must be recorded per run.
4. **NUL bytes in captured payloads.**
   - SQLite `LENGTH()` stops at the first NUL character, which skewed the Report 1 database feature.
   - PostgreSQL rejects NUL bytes in `jsonb`/`text`, which blocked the Docker deployment until it was fixed.
5. **Privacy:** the handoff includes public SSH-client IPs and Azure host names; see `THIRD_PARTY_LICENSES.md` §3.
