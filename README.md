# Cyber-Physical & Network Defense Monitoring Testbed — OT/Modbus

**CYB 691 / IT 691 Cybersecurity Capstone — Team 4**  
**Repository:** [CYB691-IT691-CapstoneProjectFall2026](https://github.com/rachidafaf/CYB691-IT691-CapstoneProjectFall2026.git)  
**Analysis environment:** Python 3.10–3.14 (pipeline), Docker Compose (deployment, see `docs/DEPLOYMENT_DOCKER.md`)  
**Licence:** [MIT](LICENSE) for Team 4 code only. Third-party tools, libraries and captured data keep their own terms: see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).  
**Report 1 feedback:** every deduction and how it was addressed is tracked in [docs/FEEDBACK_RESOLUTION.md](docs/FEEDBACK_RESOLUTION.md).

---

## 📌 1. Executive Summary & Research Question

Modbus/TCP carries no authentication or integrity protection, so any host that can reach a PLC's Modbus port can issue state-altering write requests [1], [3]. Unauthorized command messages and parameter modification are catalogued ICS attack techniques [6], and Stuxnet showed that manipulating controller behaviour can cause physical damage [4].

**Research question.** Within a defined set of unauthorized Modbus write scenarios, how much does a layered architecture add over an unsegmented baseline? The layers are Purdue-model segmentation [2], [1], Suricata Modbus deep-packet inspection [5], and a learned classifier. We separate the layers' contributions to **containment** (firewall), **alerting** (DPI signatures) and **detection** (classifier).

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Layer 1  Testbed & telemetry (Erick Espinosa)                                │
│   Conpot Modbus target (Docker) + Suricata sensor; traffic_generator.py      │
│   Implemented vs planned components: infrastructure/README.md §2             │
└────────────────────────────────────┬─────────────────────────────────────────┘
                                     │ handoff .tar.gz (SHA-256 pinned)
┌────────────────────────────────────▼─────────────────────────────────────────┐
│ Layer 2  Ingestion & triage (Rachid Afaf)                                    │
│   log_parser.py → 10 unique Modbus events (4 reads, 6 writes, 0 drops)       │
│   timeline_generator.py → incident report                                    │
└────────────────────────────────────┬─────────────────────────────────────────┘
                                     │ request-time features + scenario-record labels
┌────────────────────────────────────▼─────────────────────────────────────────┐
│ Layer 3  Detection (Rachid Afaf)                                             │
│   ml_detector.py: RF / DT / SVM vs rule baseline; Isolation Forest screening │
└────────────────────────────────────┬─────────────────────────────────────────┘
┌────────────────────────────────────▼─────────────────────────────────────────┐
│ Layer 4  Threat model audit & integration (Rachid Afaf, Anil Kumar)          │
│   validate_stride_threats.py: inventory vs exercised security properties     │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 2. Research Synthesis & Method Justification

Prior work is compared below at the level of **method, finding and limitation**, together with the design decision each one drives in this experiment. Full working notes are in [docs/RESEARCH_SYNTHESIS.md](docs/RESEARCH_SYNTHESIS.md).

| Study | Method | Finding | Limitation | What it changes in our experiment |
| :--- | :--- | :--- | :--- | :--- |
| Goldenberg & Wool [8] | Builds a per-channel deterministic finite automaton for HMI–PLC Modbus traffic from about 100 messages. No ML. | Modelled 5 of 7 production PLC channels perfectly, with no false alarms over 111 h. | Assumes periodic polling; 2 of 7 channels were not modelled perfectly. | A simple, non-learning model is a strong baseline. We report a **rule baseline** next to every classifier (§5) and do not credit ML with what a rule already does. |
| Gao & Morris [7] | Lab Modbus testbed; 28 attacks in four classes; standalone and state-based signature rules. | Standalone and state-based signature rules detect the attacks; detection rates are reported per attack class (command injection is our scenario). | Laboratory traffic only; per-class rates are not transferable to production. | Our **alerting** layer is Suricata write-function-code signatures [5]. Signature coverage is judged per write function code (Requirement 2, §3). |
| Morris & Gao [9]; Lemay & Fernandez [10] | Public Modbus datasets from lab/sandbox testbeds, labelled from the **attack actions that were executed** (Lemay & Fernandez ship label CSVs as ground truth). | Labelled captures enable reproducible IDS comparison. | Sandbox traffic is cleaner than production traffic, so models can learn testbed artifacts. | Ground truth comes from a **scenario/action record** (`data/scenario_actions.json`), not from features or parser scores (§5.1). |
| Beaver et al. [11] | Compares several ML classifiers on labelled RTU traffic with command- and data-injection scenarios. | Frames injection detection as supervised classification over labelled benign and malicious command traffic, and reports results per classifier. | One testbed; results depend on how attacks are injected and labelled. | We compare **several model families** under one protocol, with the same splits and timing definitions. |
| Arp et al. [12] | Systematic review of ML-in-security papers; defines ten pitfalls. | Data snooping, spurious correlations, label inaccuracy and missing baselines are widespread. | General guidance, not Modbus-specific. | Features restricted to **request-time** observables (no response-only fields); a parser-text feature that encoded the operation name was **removed**; a no-function-code **ablation** and a rule baseline are reported. |
| Santos et al. [13] | Compares oversampling before vs. inside cross-validation on imbalanced data. | Oversampling before splitting puts copies of test patterns in training and gives over-optimistic results. | Generic tabular data. | Split first, then oversample **training folds only**. Exact-duplicate EVE records were removed before splitting. A **leave-one-generator-run-out** scheme is also reported. |
| Sommer & Paxson [14] | Position paper on anomaly-based network IDS. | Anomaly detectors find "unusual", not "malicious", and struggle with diverse benign traffic and the cost of errors. | Conceptual, not an empirical benchmark. | Isolation Forest [15] is used only for **batch screening** of the current capture; it is not claimed to detect new attacks (§5.4). |

**Gap this project addresses:** the studies above evaluate detection *or* prevention on their own datasets. We measure containment, alerting and detection on one shared, matched case set (§4), with evidence attributed to each layer.

---

## 👥 3. Team Working Agreement, Roles & Governance

### Roles
| Member | Primary role | Scope | Hand-off owned |
| :--- | :--- | :--- | :--- |
| **Erick Espinosa** | Infrastructure & Emulation Lead | Testbed, firewall, Modbus target containers, `traffic_generator.py`, Suricata rules | Produces testbed traffic captures and the hashed `.tar.gz` handoff; confirms `data/scenario_actions.json` against the run log |
| **Rachid Afaf** | Security Architect & Detection Analytics Lead | `log_parser.py`, `timeline_generator.py`, `ml_detector.py`, `validate_stride_threats.py`, deployment | Ingests the handoff, runs the evaluation, maintains the threat model |
| **Anil Kumar** | Documentation, Review & Integration Lead | Report editing, IEEE citations, artifact provenance, integration | Owns `main`; final reviewer of every merge and report section |

### Review & integration matrix
| Artifact | Author | Required reviewer | Integration owner | Review turnaround |
| :--- | :--- | :--- | :--- | :--- |
| `infrastructure/` (scripts, configs, captures) | Erick | Rachid | Anil | 48 h |
| `src/`, `validate_stride_threats.py`, `deploy/`, tests | Rachid | Erick (functional) + Anil (merge) | Anil | 48 h |
| Report sections & README | Section owner | Anil, plus the owner of the evidence cited | Anil | 72 h |
| Threat model (`Team 4 Threat Model.json`) | Rachid | Erick | Anil | 72 h |

### Decision & conflict procedure
1. **Default:** decisions are made at the weekly stand-up and recorded in the meeting notes with the evidence used.
2. **Merges:** pull request → CI and tests green → reviewer approval → Anil merges. Nobody merges their own pull request.
3. **Disagreement:** the owner of the affected artifact writes a one-paragraph trade-off (options, evidence, effect on requirements) within 48 h. The team decides at the next stand-up by consensus; if there is no consensus, by 2-of-3 vote.
4. **Escalation:** if still unresolved after one further meeting, or if it affects scope or grading, Anil raises it with the course instructor within 24 h.

---

## 🛡️ 4. Bounded & Testable Security Requirements

Each requirement names its **case set**, **observation conditions**, **expected observation** and **evidence**. The case set is the matched set in §5.1.

* **R1 — Write containment (firewall layer).**  
  *Cases:* C3–C6 (FC 0x05, 0x06, 0x0F, 0x10 writes) sent from the enterprise workstation to the PLC zone, plus C1–C2 (reads) as controls.  
  *Conditions:* layered topology with pfSense ACLs active between the enterprise and PLC zones; each case executed 30 times.  
  *Expected:* 30/30 attempts per write case blocked; read cases from the authorized HMI source still succeed.  
  *Evidence:* a firewall log line for each blocked attempt (matching source, destination and port), no Modbus response captured beyond the firewall, and an unchanged PLC register dump.

* **R2 — Signature alerting coverage (Suricata layer).**  
  *Cases:* C3–C6, each executed 30 times in the baseline topology with the sensor attached.  
  *Conditions:* Suricata with Modbus app-layer parsing enabled [5]; sensor packet drop counter (`capture.kernel_drops` in `stats`) = 0 for the run.  
  *Expected:* each write case raises a write-specific signature (not only the generic Modbus traffic rule) on 30/30 attempts.  
  *Evidence:* the `eve.json` alert with the same `flow_id` as the case's `modbus` record, and the run's `stats` record.  
  *Current status:* in the 2026-09-26 handoff, FC 0x06 (3/3) and FC 0x10 (2/2) raised write-specific alerts; FC 0x05 (0/1) did not; FC 0x0F was not exercised.

* **R3 — Learned detection (classifier layer).**  
  *Cases:* all labelled events from §5.1.  
  *Conditions:* labels from the scenario record; request-time features only; splits made before oversampling; ≥ 30 events per class before any target is claimed.  
  *Expected:* recall ≥ 95 % and FPR ≤ 2 % in **leave-one-run-out** evaluation, **and** better than the rule baseline on at least one case type. Prediction latency ≤ 10 ms/sample, measured as `model.predict` time only, on the hardware recorded in the results file.  
  *Evidence:* `data/ml_evaluation_results.json`.

* **R4 — Evidence integrity (ingestion layer).**  
  *Cases:* the pinned handoff archive plus hostile archives (Tar-Slip `../` member, symbolic-link member) and an empty firewall log (`-- No entries --`).  
  *Expected:* hostile archives refused before extraction; the empty marker yields 0 drop events; every unique raw Modbus transaction appears exactly once in the normalized data with its original function code.  
  *Evidence:* `data/parser_integrity_report.json` (hashes and the de-duplication audit) and validator checks P1/P2 (`data/stride_validation_report.md`).

---

## ⚖️ 5. Matched Baseline vs. Layered Defense Comparison

### 5.1 Shared case set and independent ground truth
Both topologies receive **the same scripted cases** from the same workstation, with the same timing and target. Ground truth is the action log of the generator, not any detector output.

| Case | Command | Scenario step | Label |
| :--- | :--- | :--- | :---: |
| C1 | FC 0x01 Read Coils | authorized baseline poll | 0 |
| C2 | FC 0x03 Read Holding Registers | authorized baseline poll | 0 |
| C3 | FC 0x05 Write Single Coil | unauthorized write | 1 |
| C4 | FC 0x06 Write Single Register | unauthorized write | 1 |
| C5 | FC 0x0F Write Multiple Coils | unauthorized write *(planned; not in current capture)* | 1 |
| C6 | FC 0x10 Write Multiple Registers | unauthorized write | 1 |

The record for the existing capture is `data/scenario_actions.json` (10 actions over 3 generator runs). It was **reconstructed from the capture** because the 2026-09-23 run log is not in the handoff, and it is pending Erick's confirmation. Future runs must log each action (timestamp, actor, command, authorized yes/no) **at execution time**.

### 5.2 What each layer's evidence can establish
| Question | Evidence that answers it | Attributed to |
| :--- | :--- | :--- |
| Was the write **contained**? | Firewall drop line plus absence of a PLC response plus unchanged register dump | Firewall (layered only) |
| Was it **alerted**? | Write-specific Suricata alert sharing the case's `flow_id` | DPI signatures |
| Was it **detected** by the classifier? | Classifier prediction for that event under leave-one-run-out | Classifier |
| Did it **succeed** on the PLC? | Normal (non-exception) Modbus response and changed register value | Neither (outcome) |

### 5.3 Results matrix
| Tier | Containment | Alerting | Detection | Evidence |
| :--- | :---: | :---: | :---: | :--- |
| **Baseline (flat), expected** | 0 % blocked | none (no sensor) | none | PLC register dump |
| **Layered, target** | R1: 100 % of write cases | R2: 100 % per write case | R3 targets | firewall log, `eve.json`, results JSON |
| **Observed, 2026-09-26 handoff** | Not tested. Traffic ran over the Docker bridge (`10.0.1.4 → Conpot 172.17.0.2:5020`) with no firewall in the path; `iptables_drops.log` holds only `-- No entries --`. | 5/6 writes raised a write-specific alert (FC6 3/3, FC16 2/2, FC5 0/1); all 10 matched the generic Modbus rule | Same as the rule baseline (§6) | handoff, `parser_integrity_report.json`, `ml_evaluation_results.json` |

**Outcome caveat:** the target was the Conpot honeypot (`honeynet/conpot:latest`), not OpenPLC. The `openplc_runtime` container was an `nginx:alpine` placeholder (infrastructure README §1). All 10 requests received a Modbus **exception** response (Illegal Data Address), so none of the 6 writes changed a register. The capture shows attempted writes, not successful ones. R1 needs a target whose register map accepts the writes in the baseline topology.

---

## 📊 6. Machine Learning Evaluation (Layer 3)

### 6.1 Method
1. **Ground truth** is the scenario/action record joined to events by timestamp (`src/scenario.py`). Editing a feature, `threat_score` or `is_state_altering` cannot change a label (tested in `tests/test_pipeline.py`).
2. **Features available at detection time.** The primary set uses request-time observables only: `inter_arrival_ms`, `function_code`, `destination_port`, `unit_id`, `pdu_length_bytes` (request PDU length per the Modbus specification [3]).
   - `has_protocol_exception` is only known from the PLC's *response*, so it is excluded.
   - The Report 1 feature `payload_length` measured the parser's own text (`"read:…"`/`"write:…"`). It encoded the operation name, a spurious shortcut [12], so it was removed. SQLite `LENGTH()` also stopped at a NUL byte in the FC16 payload.
3. **Splits before resampling** [13]. Two schemes are reported:
   - stratified 4-fold over transactions;
   - **leave-one-generator-run-out** (3 runs; no run is in both training and testing).
   
   Oversampling touches training folds only. Metrics are **pooled** over test folds, so every event is tested exactly once.
4. **Timing.** These are stored separately in `data/ml_evaluation_results.json` → `timing_definitions`:
   - `training_time_avg_ms` = `fit` only;
   - `prediction_latency_per_sample_ms` = `predict` on the unseen fold ÷ rows;
   - `total_execution_time_ms` = the whole script.
5. **Run recorded below:** Python 3.13.18, Linux x86_64, 2 logical CPUs, scikit-learn 1.9.1, pandas 3.0.5, 10 labelled events (6 unauthorized writes, 4 authorized reads). Timings depend on the machine.

### 6.2 Results (10 events)
| Feature set → scheme | Random Forest recall / FPR | Decision Tree recall / FPR | SVM recall / FPR |
| :--- | :---: | :---: | :---: |
| Request-time → stratified 4-fold | 100 % / 0 % | 100 % / 0 % | 0 % / 25 % |
| Request-time → leave-one-run-out | 100 % / 0 % | 100 % / 0 % | 16.7 % / 0 % |
| **Without `function_code`** → stratified 4-fold | **0 % / 75 %** | **0 % / 75 %** | 0 % / 25 % |
| **Without `function_code`** → leave-one-run-out | 66.7 % / 100 % | 66.7 % / 100 % | 16.7 % / 0 % |
| **Rule baseline** (FC ∈ {5, 6, 15, 16}, no training) | 100 % / 0 % | | |
| Isolation Forest (batch screening, `contamination=auto`) | 50 % / 25 % (4 of 10 flagged) | | |

| Timing (request-time, stratified) | Random Forest | Decision Tree | SVM |
| :--- | :---: | :---: | :---: |
| `fit` per fold | 53.6 ms | 1.3 ms | 1.6 ms |
| `predict` per sample (2–3-row folds) | 1.47 ms | 0.12 ms | 0.14 ms |

### 6.3 Interpretation
* **Detection reduces to the function code.** With it, Random Forest and Decision Tree match the rule baseline exactly. Without it, they detect nothing in stratified CV. Random Forest importance: `function_code` 0.80, `inter_arrival_ms` 0.11, `pdu_length_bytes` 0.09.
  - On this capture, the classifier adds **no** detection value over a write-function-code rule. R3 therefore remains **unmet**, even though recall is 100 %.
* **Why the earlier figure changed.** The earlier Random Forest recall of 75 % came from the removed text-length feature and fold-averaged metrics. It is superseded by the table above.
* **Not statistically stable.** Ten events in three runs cannot support the R3 targets; R3 requires at least 30 events per class.
* **Isolation Forest purpose.** It screens **the current batch** for outliers: it is fitted and scored on the same capture, with a contamination setting fixed before looking at labels [15]. It is not evaluated, and not claimed, as a detector of new observations [14].
* **Next run (Week 9):** at least 30 executions of each case C1–C6, including writes from an authorized HMI address and reads from the unauthorized address. That way the function code alone no longer determines the label, and the behavioural features have to carry the signal.

---

## 🛡️ 7. Threat Model & Audit

`Team 4 Threat Model.json` (OWASP Threat Dragon v2.3.0) records **37 threats**, all with status **Open**, on 32 components and 5 trust boundaries (STRIDE: S 2, T 19, R 2, I 3, D 5, E 6; severity: Critical 5, High 27, Medium 5). Relevant ICS techniques are listed in [6].

`validate_stride_threats.py` reports two kinds of result and never mixes them:
* **INVENTORY:** the model and policy files exist and are well formed. This is *not* evidence that a control works.
* **PROPERTY:** a control was exercised.
  - **P1:** parser functions driven with a Tar-Slip archive, a link member, the `-- No entries --` marker and a non-Modbus EVE event.
  - **P2:** normalized data reconciled with the raw `eve.json` (10 = 10 unique transactions, identical function codes, 0 drops = 0 real drop lines).
  - **P3:** ML results checked for scenario labels, request-time features, separate timing and label-free Isolation Forest, then compared with the targets.

The current run gives P1 PASS, P2 PASS and P3 WARN, so the overall result is **PARTIAL** (details in `data/stride_validation_report.md`). The professor's negative control (an empty parser, an empty data object, an empty model-results object) now produces FAIL on all three checks; see `tests/test_pipeline.py::test_validator_negative_control_reproduces_professor_probe`. The audit does not close threats.

---

## 📅 8. Forward Schedule & Internal Due Points

Status as of **2026-11-01**. Dates for Weeks 9–10 are proposed; confirm them at the next stand-up against the Report 2 deadline.

| # | Deliverable (evidence product) | Owner | Internal due | Reviewer | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Parser fix (function codes, Modbus-only events, empty marker), de-duplication audit, unit tests | Rachid | Oct 25 | Anil | ✅ Done |
| 2 | Scenario-record labels, request-time features, ablation, leave-one-run-out, timing separation, behavioural validator | Rachid | Nov 1 | Anil | ✅ Done; awaiting review |
| 3 | Confirm or replace `data/scenario_actions.json` against the 2026-09-23 run log and generator version | Erick | **TBD** | Rachid | ⏳ Open |
| 4 | Record deployed versions, interfaces and the real topology (infrastructure README §2 table "to confirm" fields) | Erick | **TBD** | Anil | ⏳ Open |
| 5 | Generator logs each action at execution time (scenario record written automatically) | Erick + Rachid | **TBD** | Anil | ⏳ Open |
| 6 | Firewall ACLs active in the layered topology; firewall log captured (R1 evidence) | Erick | **Nov 6** (was Nov 1) | Rachid | ⏳ Open, slipped |
| 7 | Matched runs: 30 × C1–C6 in baseline and layered topologies, with authorized-writer and unauthorized-reader variants | Erick + Rachid | **TBD** | Anil | ⏳ Open |
| 8 | Re-run pipeline, validator and Docker smoke test on the new captures; update §5–§6 tables | Rachid | **TBD** | Erick | ⏳ Open |
| 9 | Report 2 draft: synthesis (§2) reviewed against the full papers, citations checked | Anil | **TBD** | Rachid + Erick | ⏳ Open |
| 10 | Report 2 final: threat-model status updates, AI-use log, final figures (readable threat-model figure) | Anil | **TBD** | Team | ⏳ Open |

---

## 🤖 9. Generative AI Use Disclosure

| Date / period | Used by | Reviewed by | Tool | Purpose | Prompt (summary) | Verification & changes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-09-24 – 09-26 | Rachid Afaf | Anil Kumar | Claude 3.5 Sonnet / Gemini | Schema boilerplate for `log_parser.py` | "Review a Python script parsing Suricata EVE JSON into ISO 8601 format" | Added Modbus function map; fixed path bugs; UTC timestamps |
| 2026-10-01 – 10-02 | Rachid Afaf | Anil Kumar | Claude 3.5 Sonnet | AST helpers for `validate_stride_threats.py` | "Review the Python code using ast module to inspect function definitions" | Integrated into the auditor (later replaced, see 11-01 row) |
| 2026-10-24 | Rachid Afaf, Anil Kumar | Erick Espinosa | Gemini | Timing refactor | "Refactor cross-validation loop to isolate model.predict timing from model.fit" | Checked with `time.perf_counter()`; unit tests |
| 2026-10-31 – 11-01 | Rachid Afaf | *Pending: Anil Kumar* | Claude (Anthropic) | Duplicate-record fix (`log_parser.py`), stale-row fix (`database.py`), fold-count fix, Docker deployment (`deploy/`, `docs/DEPLOYMENT_DOCKER.md`) | "Fix the data issue and run …"; "make it deployable in Docker only" | Pipeline re-run by Rachid on Windows (10/10 tests, smoke test 21/21); code review pending |
| 2026-11-01 | Rachid Afaf | *Pending: Anil Kumar (code), Erick Espinosa (scenario record, environment)* | Claude (Anthropic) | Report 1 feedback resolution: scenario-record labels, feature/ablation/CV redesign, behavioural validator, research synthesis draft and reference verification, environment reconciliation, licence terms | "See if all feedback is implemented and resolved … implement it all" | Tests re-run; sources checked against publisher/DOI pages; **team must read the cited papers and confirm the scenario record and environment facts before submission** |

---

## 🚀 10. Quickstart

```bash
pip install -r requirements.txt
python src/log_parser.py            # 10 unique Modbus events; de-duplication audit in data/parser_integrity_report.json
python src/timeline_generator.py    # incident report + timeline
python src/ml_detector.py           # labels from data/scenario_actions.json; results in data/ml_evaluation_results.json
python validate_stride_threats.py   # inventory + exercised property checks → data/stride_validation_report.md
pytest -v tests/test_pipeline.py
```

**Using your local PostgreSQL instead of SQLite.** Set one environment variable and every script (`log_parser.py`, `timeline_generator.py`, `ml_detector.py`, `src/database.py`) reads and writes PostgreSQL. Tables go into schema `cyb691` of the database in the URL. SQLite stays the default when the variable is unset.

```powershell
pip install -r requirements.txt                       # includes psycopg2-binary
$env:CYB691_DATABASE_URL = "postgresql://postgres@localhost:5432/postgres"
$env:PGPASSWORD = "<your postgres password>"          # or put it in %APPDATA%\postgresql\pgpass.conf
python src/database.py                                # creates schema cyb691 and its tables
python src/log_parser.py; python src/timeline_generator.py; python src/ml_detector.py
```

Each script also accepts `--db <sqlite path | postgresql:// URL>`. Never put the password in the URL, in a committed run configuration or in the repo. In PyCharm, add the two variables under *Run → Edit Configurations → Environment variables*. To see the tables in the Database tool window, open `postgres@localhost` → *Schemas* and tick `cyb691`.

**Containerised deployment (Docker only).** See [`docs/DEPLOYMENT_DOCKER.md`](docs/DEPLOYMENT_DOCKER.md).

```powershell
.\deploy\docker\up.ps1        # Windows; Linux/macOS: deploy/docker/up.sh
pytest -q tests/deployment     # deployment unit, recovery and static security tests
```

---

## 📚 11. References (IEEE)

[1] K. Stouffer, M. Pease, C. Tang, T. Zimmerman, V. Pillitteri, S. Lightman, A. Hahn, S. Saravia, A. Sherule, and M. Thompson, "Guide to Operational Technology (OT) Security," NIST Special Publication 800-82 Rev. 3, National Institute of Standards and Technology, Gaithersburg, MD, USA, Sep. 2023, doi: 10.6028/NIST.SP.800-82r3.  
[2] T. J. Williams, "The Purdue enterprise reference architecture," *Computers in Industry*, vol. 24, no. 2–3, pp. 141–158, Sep. 1994, doi: 10.1016/0166-3615(94)90017-5.  
[3] Modbus Organization, "MODBUS Application Protocol Specification V1.1b3," Apr. 26, 2012. [Online]. Available: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf  
[4] R. Langner, "To Kill a Centrifuge: A Technical Analysis of What Stuxnet's Creators Tried to Achieve," The Langner Group, Arlington, VA, USA, Nov. 2013.  
[5] Open Information Security Foundation, "Suricata User Guide, release 7.0.12," ch. 8 "Suricata Rules," §8.15 "Modbus Keyword," and the EVE JSON output chapter. [Online]. Available: https://docs.suricata.io/en/suricata-7.0.12/ *(the deployed Suricata version is still to be recorded; cite the matching release)*  
[6] The MITRE Corporation, "MITRE ATT&CK for ICS," v20.0, Oct. 13, 2026: T1692.001 Unauthorized Message: Command Message (legacy ID T0855, which redirects to it), T0836 Modify Parameter, T0814 Denial of Service. [Online]. Available: https://attack.mitre.org/matrices/ics/  
[7] W. Gao and T. H. Morris, "On cyber attacks and signature based intrusion detection for Modbus based industrial control systems," *Journal of Digital Forensics, Security and Law*, vol. 9, no. 1, 2014, doi: 10.15394/jdfsl.2014.1162.  
[8] N. Goldenberg and A. Wool, "Accurate modeling of Modbus/TCP for intrusion detection in SCADA systems," *International Journal of Critical Infrastructure Protection*, vol. 6, no. 2, pp. 63–75, 2013, doi: 10.1016/j.ijcip.2013.05.001.  
[9] T. Morris and W. Gao, "Industrial control system traffic data sets for intrusion detection research," in *Critical Infrastructure Protection VIII* (IFIP AICT, vol. 441), J. Butts and S. Shenoi, Eds. Berlin, Germany: Springer, 2014, pp. 65–78, doi: 10.1007/978-3-662-45355-1_5.  
[10] A. Lemay and J. M. Fernandez, "Providing SCADA network data sets for intrusion detection research," in *Proc. 9th Workshop on Cyber Security Experimentation and Test (CSET '16)*, Austin, TX, USA: USENIX, Aug. 2016.  
[11] J. M. Beaver, R. C. Borges-Hink, and M. A. Buckner, "An evaluation of machine learning methods to detect malicious SCADA communications," in *Proc. 12th Int. Conf. Machine Learning and Applications (ICMLA)*, Miami, FL, USA, 2013, pp. 54–59, doi: 10.1109/ICMLA.2013.105.  
[12] D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro, and K. Rieck, "Dos and don'ts of machine learning in computer security," in *Proc. 31st USENIX Security Symposium*, Boston, MA, USA, 2022, pp. 3971–3988.  
[13] M. S. Santos, J. P. Soares, P. H. Abreu, H. Araújo, and J. Santos, "Cross-validation for imbalanced datasets: Avoiding overoptimistic and overfitting approaches," *IEEE Computational Intelligence Magazine*, vol. 13, no. 4, pp. 59–76, Nov. 2018, doi: 10.1109/MCI.2018.2866730.  
[14] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in *Proc. IEEE Symposium on Security and Privacy*, Oakland, CA, USA, 2010, pp. 305–316, doi: 10.1109/SP.2010.25.  
[15] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation forest," in *Proc. 8th IEEE Int. Conf. Data Mining (ICDM)*, Pisa, Italy, 2008, pp. 413–422, doi: 10.1109/ICDM.2008.17.
