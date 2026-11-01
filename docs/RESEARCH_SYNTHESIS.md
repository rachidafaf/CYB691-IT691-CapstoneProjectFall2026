# Research Synthesis — Working Notes (Team 4)

**Purpose:** support README §2 and the Report 2 literature section with a method-level comparison of prior work, and record what each source changes in our experiment.  
**Status (2026-11-01):** draft. Bibliographic metadata was checked against publisher, DOI or Crossref records. **Findings were checked only against abstracts and publisher summaries.** Before Report 2, each source's owner must read the full paper, confirm or correct the "Finding" and "Limitation" cells, and add page-level citations.

| # | Source (IEEE number in README) | Type | Metadata check | Full text read by | Due |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Goldenberg & Wool 2013 [8] | Journal (IJCIP) | DOI 10.1016/j.ijcip.2013.05.001 | — | Nov 13 |
| 2 | Gao & Morris 2014 [7] | Journal (JDFSL) | DOI 10.15394/jdfsl.2014.1162 | — | Nov 13 |
| 3 | Morris & Gao 2014 [9] | Book chapter (IFIP AICT 441) | DOI 10.1007/978-3-662-45355-1_5, pp. 65–78 | — | Nov 13 |
| 4 | Lemay & Fernandez 2016 [10] | Workshop (USENIX CSET '16) | USENIX programme page | — | Nov 13 |
| 5 | Beaver et al. 2013 [11] | Conference (ICMLA) | DOI 10.1109/ICMLA.2013.105, pp. 54–59 | — | Nov 13 |
| 6 | Arp et al. 2022 [12] | Conference (USENIX Security) | USENIX page, pp. 3971–3988 | — | Nov 13 |
| 7 | Santos et al. 2018 [13] | Magazine (IEEE CIM, peer-reviewed) | DOI 10.1109/MCI.2018.2866730 | — | Nov 13 |
| 8 | Sommer & Paxson 2010 [14] | Conference (IEEE S&P) | DOI 10.1109/SP.2010.25 | — | Nov 13 |
| 9 | Liu, Ting & Zhou 2008 [15] | Conference (IEEE ICDM) | DOI 10.1109/ICDM.2008.17 | — | Nov 13 |
| 10 | Williams 1994 [2] | Journal (Computers in Industry) | DOI 10.1016/0166-3615(94)90017-5 | — | Nov 13 |

---

## 1. Theme A — How Modbus write attacks have been detected

**Specification-/model-based (no ML).** Goldenberg & Wool [8] observe that HMI–PLC traffic is highly periodic. They learn one deterministic finite automaton per channel from about 100 messages. On a production network, 5 of 7 channels were modelled perfectly, with no false alarms over 111 hours, and the detector also flagged a misconfigured PLC and technician activity. The limitation is the periodicity assumption: the remaining 2 of 7 channels were not modelled perfectly (read the full paper for why).

**Signature-based.** Gao & Morris [7] define 28 attacks against Modbus systems in four classes (reconnaissance, response injection, command injection, denial of service). They write standalone and state-based intrusion detection rules and report detection rates per class in a laboratory environment.

**Supervised ML.** Beaver et al. [11] treat command- and data-injection detection in RTU traffic as supervised classification over labelled benign and malicious traffic and compare several learning methods.

**What we take from Theme A**
- A rule on the write function code is the natural **baseline** for "unauthorized write" detection. It matches our Suricata write signatures [5] and the signature approach of [7].
- A learned model must be shown to do **better than that rule on some case**. Otherwise the ML layer adds cost without value. Our current result (README §6.3) is that it does not, on 10 events, so the planned runs add cases where the function code alone cannot decide the label: writes from an authorized HMI address and reads from the unauthorized address.
- [8]'s low false-alarm rate came from modelling *sequence*. Our `inter_arrival_ms` is a first step toward that; a per-channel sequence model is a candidate extension if time allows.

## 2. Theme B — Ground truth and datasets

**Labels from executed attack actions.** Morris & Gao [9] publish four Modbus datasets covering 28 attacks on two laboratory systems. Lemay & Fernandez [10] generate benign and malicious Modbus traffic in a SCADA sandbox with real attack tools, and ship **CSV label files as ground truth**. Both note that laboratory or sandbox traffic is cleaner than production traffic.

**Pitfalls.** Arp et al. [12] list *label inaccuracy* (P2), *data snooping* (P3: training on information not available in practice), *spurious correlations* (P4: artifacts that let a model separate classes for reasons unrelated to the security problem) and *inappropriate baseline* (P6).

**What we take from Theme B**
- Ground truth is a **scenario/action record** (`data/scenario_actions.json`) listing each executed action and whether the actor was authorized, joined to events by timestamp. It mirrors the label-file approach of [10] and removes the Report 1 problem, where labels came from model inputs.
- **Data snooping:** `has_protocol_exception` is only known after the PLC responds, so it is excluded from the request-time feature set.
- **Spurious correlation:** the Report 1 feature `payload_length` measured the parser's text (`"read:…"` vs `"write:…"`) and leaked the operation name. It was replaced with the request PDU length defined by the Modbus specification [3].
- **Lab-only traffic** ([9], [10], [12] P9) applies to us too. All conclusions are scoped to the testbed.

## 3. Theme C — Evaluation protocol with few, imbalanced samples

Santos et al. [13] show that oversampling *before* cross-validation places copies of test patterns in training and inflates results; the correct protocol oversamples inside the training folds only. Arp et al. [12] add that related samples (for example, from the same session) should not straddle the split.

**What we take from Theme C**
- Exact-duplicate EVE records (each transaction was logged twice) are removed before splitting.
- Splits come first, and oversampling touches training folds only.
- Besides stratified k-fold, we report **leave-one-generator-run-out**: no run contributes to both training and testing.
- Metrics are pooled over folds, and we state plainly that 10 events cannot support the 95 %/2 % targets.

## 4. Theme D — Unsupervised screening

Liu, Ting & Zhou [15] introduce Isolation Forest: anomalies are isolated in fewer random partitions than normal points, and the method needs no labels. Sommer & Paxson [14] argue that anomaly detection finds the *unusual*, not necessarily the *malicious*, that benign network traffic is highly diverse, and that errors are costly in operations.

**What we take from Theme D**
- Isolation Forest is used only to **screen the current batch** for outliers. It is fitted and scored on the same capture, with a contamination setting fixed in advance (`auto`), never derived from labels. Labels are used only afterwards, to describe what it flagged.
- We do not claim it detects new or zero-day observations. That would require a held-out, later capture and is out of scope for Report 2 unless time allows.

## 5. Theme E — Architecture framing

Williams [2] describes the Purdue Enterprise Reference Architecture. NIST SP 800-82 Rev. 3 [1] uses the Purdue model levels to recommend segmentation and boundary protection for OT networks. These justify the zone layout and the firewall layer (requirement R1). ATT&CK for ICS [6] names the techniques exercised: unauthorized command message (T1692.001, legacy ID T0855) and modify parameter (T0836).
