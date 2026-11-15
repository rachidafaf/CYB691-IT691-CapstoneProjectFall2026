# Step 8 — Four-Tier Ablation: Results

**Capstone:** Layered cybersecurity monitoring and defense for OT networks (Modbus TCP), Team 4
**Prepared for:** Report 2 results section
**Captures analyzed:** source-separable baseline — `ot_telemetry_handoff_2026-11-04`, `ot_telemetry_handoff_2026-11-07`, `ot_telemetry_handoff_2026-11-14` (three independent, matched captures); content-distinguishable — `ot_telemetry_handoff_2026-11-15` (Step 7 insider anomalies; see "Content-distinguishable capture" below)
**Ground truth:** source IP — HMI `10.0.1.10` = authorized, WS `10.0.1.20` = unauthorized; scenario CSV **confirmed by Erick** as matching commands actually sent.
**Reproduced by:** `analyze_ablation.py <capture-date>` (repo root) → `data/runs/<handoff>/ablation_summary.json`

## Method

The ablation measures what each defense layer adds on top of the layers beneath it, separating two distinct quantities:

- **Containment (prevention):** did the unauthorized command fail to reach the PLC? — provided by the **firewall (Tier 1)**.
- **Detection (visibility):** was the unauthorized command flagged by a sensor? — provided by **Suricata (Tier 2)** and **ML (Tier 3)**.

Detection is evaluated on the **flat/baseline phase**, where unauthorized traffic actually reaches the PLC and the sensors have something to see. In the enforced (layered) phase the firewall drops the traffic before the sensors inspect it, so measuring detection there would understate the sensors' intrinsic capability.

Each capture ran 90 unauthorized Modbus commands from the WS host: 30 reads (cases C1–C2) and 60 writes (cases C3–C6).

## Containment ladder

| Tier | Layer | Reached PLC (flat) | Reached PLC (enforced) | Contained | Marginal |
|---|---|---|---|---|---|
| 0 | Flat network | 90 / 90 | — | 0% | — |
| 1 | Firewall ACL (source) | — | 0 / 90 | **100%** | **+100%** |
| 2 | Suricata DPI | — | — | — | +0% (detection layer) |
| 3 | ML anomaly | — | — | — | +0% (detection layer) |

Firewall drop-logs: **91** (11-04), **93** (11-07), **91** (11-14) — the small surplus over 90 attempts is TCP SYN retransmissions of blocked connections. Zero authorized traffic affected, in all three captures.

## Detection ladder (on the 90 unauthorized commands that flow in the flat case)

| Layer | Mechanism | Recall | FPR | Note |
|---|---|---|---|---|
| Firewall drop-log | source (L3/L4) | 100% | 0% | logs every attempt when enforcing |
| Suricata | source + write-FC signature | **66.7% (60/90)** | **0% (0/180)** | flags all 60 writes; **misses all 30 reads** |
| ML (best model) | content (request-time) | 25–52% | 20–47% | **at chance** (recall ≈ FPR) |
| — rule baseline | write function codes | 64–68% | 67–70% | content heuristic, non-discriminative |
| — isolation forest | unsupervised | 14–43% | 22–43% | flags ≈ as many normal as anomalous |

Per capture (best supervised model): **11-04** Random Forest 38.2% recall / 36.5% FPR; **11-07** SVM 25.0% / 19.6%; **11-14** Random Forest 52.2% / 46.7%. In every case recall ≈ FPR.

## Interpretation (report-ready)

Under the flat baseline (Tier 0), all 90 unauthorized Modbus commands reached the PLC. Adding least-privilege firewall ACLs (Tier 1) contained 100% of them with zero impact on authorized traffic. The Suricata DPI layer (Tier 2) detected 66.7% of unauthorized commands at a 0% false-positive rate, correctly flagging every unauthorized write but no unauthorized read — leaving reconnaissance reads invisible to signature detection. The machine-learning layer (Tier 3) performed at chance across all six model/validation configurations in every capture; recall approximated the false-positive rate for every detector, indicating no discriminative signal.

This is expected and is the central finding: **authorization in this scenario is defined by source identity, while the Modbus payloads of authorized and unauthorized commands are otherwise identical, so content-based detection has nothing to separate.** The marginal contribution of each layer is therefore: Tier 1 provides complete containment; Tier 2 adds precise but incomplete (write-only) application-layer visibility; Tier 3 adds nothing for a source-separable threat. The result is stable across three independent captures spanning ten days (Suricata recall exactly 60/90 in all three; containment 100% in all three), confirming the testbed is repeatable and the ablation reflects the architecture rather than any single capture.

**This quantifies the motivation for content-distinguishable threats, now executed in the 2026-11-15 capture (see "Content-distinguishable capture (2026-11-15)" below):** only when unauthorized commands differ in payload — insider writes from an authorized host, out-of-range registers, abnormal values, or burst timing — can Tiers 2 and 3 contribute coverage the source-based firewall cannot. At that point authorization is no longer source-defined, and Tier 3 detection must be scored against the scenario CSV join rather than source IP.

## Content-distinguishable capture (2026-11-15) — the true four-tier result

The fourth capture (`ot_telemetry_handoff_2026-11-15`, Step 7) adds **content-distinguishable insider anomalies issued from the authorized HMI** (`10.0.1.10`), so the source-based firewall allows them and only a content-aware layer can catch them. It retains the WS source-separable block as a control. Ground truth here is the **scenario CSV `authorized` flag** (declared in the generator, never derived from source IP), joined by timestamp — **485 labelled events (337 attacks, 148 benign)**; firewall-dropped WS commands have no Modbus event and are correctly excluded.

Anomaly classes (all from the HMI, `authorized=0`): `oor_address` (A1, write outside the legitimate register map), `oor_value` (A2/A3, register value outside the legitimate band), `ro_write` (A5, write to a read-only measurement register), `burst` (A4, rapid write burst). The content features given to the ML are **raw observables only** (`is_write`, `write_address`, `write_quantity`, `write_value_max/min`); the boundary booleans that *define* the anomaly (`address_in_map`, `value_in_band`) are withheld from every ML feature set and used **only in the content rule baseline** — so ML-vs-rule is an honest comparison (Arp et al. P3 data-snooping / P6 inappropriate baseline).

### Per-class detection (content rule; the content ML matches it within noise)

| anomaly class | source | n | Firewall (source ACL) | Content rule / ML |
|---|---|---|---|---|
| `oor_address` (A1) | HMI | 24 | passes (authorized source) | **24/24 = 100%** |
| `oor_value` (A2/A3) | HMI | 48 | passes | **48/48 = 100%** |
| `ro_write` (A5) | HMI | 25 | passes | **25/25 = 100%** |
| `burst` (A4) | HMI | 150 | passes | **145/150 = 96.7%** |
| `unauth_source` (WS) | WS | 90 | **contained 100%** (layered) | 0/90 = 0% |
| `normal` | HMI | 148 | passes (authorized) | 1/148 = 0.68% FP |

### Overall detection ladder (scenario ground truth, 485 events)

| Layer | Recall | FPR | Note |
|---|---|---|---|
| Content rule (address / value / burst) | **71.81%** | **0.68%** | static content DPI; per-class ~100% on insider classes |
| ML — best model (Random Forest, `content` set) | **72.11%** | **0.68%** | stratified k-fold; statistically identical to the rule |
| ML — `content_only` ablation (RF/DT) | 77.74% | 16.89% | content alone, no timing/header features |
| rule baseline (write function codes) | 91.1% | **67.57%** | flags every write — the inappropriate baseline |
| isolation forest (unsupervised) | 22.55% | 47.3% | flags ≈ as many normal as anomalous |

### Findings

1. **Content ML ≈ content rule.** Random Forest on the `content` set (72.11% / 0.68%) is statistically identical to the static content rule (71.81% / 0.68%, same FPR to the decimal). The learned model adds **no value over the rule**, now shown with a non-leaking feature set — the same conclusion as the source-separable captures, one layer deeper: once the anomaly is content-visible, a simple rule already catches it.
2. **The ML recall is memorization, not generalization.** The injected anomalies are constant-valued (A1 is always address 600, A2 always value 65000), so under cross-validation the classifier memorizes those constants rather than learning "out of range." The content rule generalizes to any out-of-range value and needs no training, so it is the honest comparator; the function-code baseline's 91.1% recall at **67.57% FPR** shows what "flag every write" costs.
3. **The firewall and the content layer are exact complements.** The firewall contains 100% of the source-only unauthorized writes (identical payload, caught by IP) and 0% of the insider anomalies (authorized source). The content layer does the mirror image: ~100% of the insider content anomalies, 0% of the source-only writes. Neither alone covers the threat; together they do. This is the layered-defense result the three source-separable captures only motivated.
4. **Capture-quality notes.** The 5 missed `burst` events are the *first* write of each burst (large inter-arrival from the preceding case, so the rate rule correctly does not yet see a burst). Separately, ~30 of the 180 burst writes sent were never logged at all (Suricata dropped them at 20 ms spacing) — a real DPI visibility gap that argues for source-based rate limiting over relying on the IDS to see every packet.

**Reproduced by:** `analyze_ablation.py 2026-11-15` (containment + the two labelled ground truths) and the per-class join over `ml_detector.py`'s `content` / `content_only` feature sets and `content_rule_baseline`.

## Secondary findings / caveats

1. **No Suricata alerts in the layered phase** — the firewall drops WS packets before DPI inspects them, so the IDS has no visibility into contained traffic. (Reinforces why detection is evaluated on the flat case.)
2. **Edge-collector `LOCAL_ALERT` fires on 120/180 authorized commands** — a noisy local heuristic, not part of the layered controls; exclude from Tier results.
3. **Phase-split caveat** — the baseline/layered split uses the first firewall drop as the boundary. Because the layered-policy HMI run precedes the layered WS run, authorized events from both policies group under "baseline." This does not affect the unauthorized containment/detection numbers (read from unauthorized rows, which split correctly) but means authorized-side per-policy FPR is not separated by this method.
4. **Scenario matching** — the 11-14 capture labels 270/270 reachable actions (only firewall-contained WS commands are excluded, correctly), a cleaner match than 11-04 (216). Containment is computed from DB `MODBUS_DPI`-by-source counts, independent of the scenario join.

## Related

- Step 9 read-back verification (`readback-verification.md`) confirms authorized writes change PLC state, so the 100% containment result is measured against a system where writes genuinely take effect.