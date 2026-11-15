# Step 7 — Content-Distinguishable Capture: Specification

**Capstone:** Layered cybersecurity monitoring and defense for OT networks (Modbus TCP), Team 4
**Purpose:** Design the next capture so that detection does **not** depend on source identity alone, giving Tiers 2 (Suricata DPI) and 3 (ML) a genuine content signal — turning the ablation into a true four-tier differentiation.
**Builds on:** `ablation-results.md` (source-separable finding), `readback-verification.md`.

> **Status — EXECUTED (2026-11-15).** Run as `ot_telemetry_handoff_2026-11-15` (485 labelled events; read-back 4/4 PASS). Results in `ablation-results.md` → "Content-distinguishable capture (2026-11-15)". Headline: the content layer separates the insider anomalies (per-class ~100%), but the content ML (72.11% / 0.68% FPR) is **statistically identical to a static content rule** (71.81% / 0.68%) — so the ML does **not** beat the rule. That null result is the finding (see the annotated acceptance criteria at the end).

## 1. Why this capture is needed

In the three captures to date, authorized (HMI `10.0.1.10`) and unauthorized (WS `10.0.1.20`) traffic are **byte-identical apart from source IP**. So:

- the **source-based firewall** contains 100% of the unauthorized traffic, and
- the **content layers** (Suricata signatures, ML) have nothing to separate — ML sits at chance (recall ≈ FPR) in all three captures.

To show Tiers 2–3 adding value, the threat must differ in **payload content**, and it must come from a host the firewall allows — i.e., a **compromised/insider HMI**. This is the standard "the firewall lets the operator through; the attacker *is* the operator" threat that motivates DPI and anomaly detection in ICS.

## 2. Design principles

1. **Authorization is declared, not derived.** The generator writes the true label (`authorized` 0/1) per the scenario design. Insider-anomaly actions have `source_ip = 10.0.1.10` (HMI) **and** `authorized = 0`.
2. **Content carries the signal.** Anomalies differ in **address**, **value**, or **timing** — not in source or (mostly) function code.
3. **Features observed, labels declared.** ML/DPI features come from the **observed** Modbus telemetry (Suricata `eve.json` request fields, or PCAP), never from the scenario CSV. The scenario CSV supplies the label only, matched by timestamp. (Avoids Arp et al. data snooping / label leakage.)
4. **Keep the source-separable baseline.** Retain the WS `C1–C6` block so the firewall/source layer is still measured and the two threat types can be compared.

## 3. Legitimate HMI profile (the "normal" the anomalies violate)

Define and document the legitimate operating envelope so "anomalous" is well-specified:

| Point class | Address range | Function codes | Value band | Cadence |
|---|---|---|---|---|
| Setpoint holding registers | HR[0]–HR[4] | FC6, FC16 | 0–1000 | ~1 op / 2 s |
| Actuator coils | CO[0]–CO[4] | FC5, FC15 | 0 / 1 | ~1 op / 2 s |
| Measurement registers (read-only by convention) | HR[20]–HR[24] | FC3 (read only) | — | polled |
| Status coils (read-only by convention) | CO[10]–CO[14] | FC1 (read only) | — | polled |

Configure `run_server.py`'s datastore so these ranges exist (the current `[0]*999` blocks already cover them; the "read-only" convention is enforced by the *scenario design*, not the server).

## 4. New case set

All anomaly cases (A1–A5) are issued **from the HMI `10.0.1.10`** so they pass the layered firewall; the firewall cannot see them. `N` is legitimate HMI traffic; the WS block is the retained source-separable baseline.

| Case | Source | FC | Address | Value / arg | Cadence | authorized | anomaly_class | What separates it |
|---|---|---|---|---|---|---|---|---|
| **N** (normal) | HMI 10.0.1.10 | FC5/FC6/FC15/FC16 | in-map (0–4) | in-band (reg 0–1000, coil 0/1) | ~2 s | **1** | `normal` | — (legitimate) |
| **A1** out-of-range address | HMI | FC6 | **HR[600]** (outside map) | 50 (in-band) | ~2 s | 0 | `oor_address` | **address** |
| **A2** out-of-range value | HMI | FC6 | HR[2] (in-map) | **65000** (outside band) | ~2 s | 0 | `oor_value` | **value** |
| **A3** mixed-block anomaly | HMI | FC16 | HR[0]–HR[2] | **[50, 65000, 90]** (one out-of-band) | ~2 s | 0 | `oor_value` | **value** |
| **A4** write burst | HMI | FC5 | CO[0] (in-map) | toggle 0/1 | **~20 ms, 30×** | 0 | `burst` | **timing (inter-arrival)** |
| **A5** read-only-point write | HMI | FC6 | **HR[20]** (measurement reg) | 10 | ~2 s | 0 | `ro_write` | **address (role)** |
| **C1–C6** (retain) | WS 10.0.1.20 | FC1/3/5/6/15/16 | in-map | as today | ~2 s | 0 | `unauth_source` | **source** |

All values are within Modbus 16-bit limits and the simulated datastore, so nothing stresses the lab beyond ordinary writes. "Out-of-range" is relative to the **legitimate profile** in §3, not the protocol.

This dataset has the property you need:

| Feature used alone | Separates… | Misses… |
|---|---|---|
| source IP | WS block only | all insider anomalies A1–A5 |
| function code | (writes vs reads) | A1,A2,A3,A5 use legitimate write FCs |
| **address** | A1, A5 | A2, A3, A4 |
| **value** | A2, A3 | A1, A4, A5 |
| **inter-arrival** | A4 | A1, A2, A3, A5 |

→ No single field separates all anomalies, so a learned model combining address/value/timing can beat every static rule on *some* class — which is exactly what Requirement R3 ("better than the rule baseline on at least one case type") asks for.

## 5. Scenario CSV schema (extended)

Add the content and timing columns, and make `authorized` an explicit declared field:

```
timestamp_utc, run_id, topology, case_id, source_ip, dest_ip, unit_id,
function_code, address, quantity, value, inter_arrival_ms, authorized, anomaly_class
```

| Column | Meaning | Notes |
|---|---|---|
| `address` | starting register/coil address | integer |
| `quantity` | number of registers/coils written | 1 for FC5/FC6 |
| `value` | written value(s) | single int, or `;`-joined list for FC15/FC16 (e.g. `50;65000;90`) |
| `inter_arrival_ms` | ms since the previous action on this host | lets the burst case be labelled and audited |
| `authorized` | **true label, 0/1, set by the generator's intent** | **decoupled from source_ip** |
| `anomaly_class` | `normal \| oor_address \| oor_value \| ro_write \| burst \| unauth_source` | for per-class analysis, **not** an ML feature |

**Critical rule:** the generator must stamp `authorized` and `anomaly_class` from the scenario design, never compute `authorized` from `source_ip`. For A1–A5, `source_ip = 10.0.1.10` and `authorized = 0`.

## 6. Telemetry requirement — content must be *observable* (no leakage)

ML/DPI features must come from the **observed** telemetry, not the scenario CSV. So the address and value must appear in what the sensor records:

- **Preferred:** enable Suricata Modbus logging of request detail so `eve.json` modbus records carry the write **address** and **value(s)** (and `quantity`). Verify a sample `eve.json` modbus record includes them before the full run.
- **Fallback:** capture PCAP on vm-fwsensor (`tcpdump -i any -n 'tcp port 502' -w capture.pcap`) and extract address/value with `tshark`/`pyshark`. Package the pcap in the handoff and feed it to `correlate_telemetry.py --pcap`.

The scenario CSV's `address`/`value` are used **only** to (a) assign the label by timestamp match and (b) verify the observed values — never as model features. State this explicitly in the methods section (Arp et al. P3).

## 7. ML pipeline changes (`src/ml_detector.py`, `src/scenario.py`)

1. **Label join:** keep timestamp-nearest matching to the scenario row (each action has a unique timestamp), but take the label from the declared `authorized` column — do **not** assume `authorized == (source == HMI)`.
2. **New request-time features (from observed telemetry):**
   - `write_address` (and `address_in_map` only if derived from *observed* address vs the documented map — document the map as prior knowledge, not ground-truth leakage),
   - `written_value_max`, `written_value_min`, `value_in_band` (computed from observed values against the documented band),
   - `quantity`, `inter_arrival_ms`, `function_code`, `pdu_length_bytes` (as today).
3. **Ablations to report:**
   - **without `source_ip`** — proves content (not source) carries the signal;
   - **without address/value** — shows the content features are doing the work;
   - **per-anomaly-class recall** — which class each layer catches.
4. **Rule baselines (the DPI equivalents), so ML must beat them on some class:**
   - address-out-of-map rule → catches A1, A5;
   - value-out-of-band rule → catches A2, A3;
   - rate rule (inter-arrival threshold) → catches A4;
   - the point is that **no single static rule catches all**, and ML combining the features should.

## 8. What the four-tier ablation then shows

| Tier | Source-separable threat (WS block) | Content threat (insider A1–A5) |
|---|---|---|
| 1 Firewall (source) | **100% contained** | **0% — same source as the operator** |
| 2 Suricata DPI (address/value/FC rules) | alerts on write FCs | catches the classes its rules cover (A1/A5 address, A2/A3 value) |
| 3 ML (content) | redundant | **catches the classes the static rules miss** (notably A4 timing, borderline values) — the first capture where Tier 3 earns marginal recall |

That is the genuine four-tier story: the firewall owns the source-separable threat; DPI and ML split the content threat; and ML's marginal value is measurable for the first time.

## 9. Run plan

- Keep the existing structure: baseline (flat) and layered policies, 3 runs each, so the firewall contrast is preserved for the WS block.
- Per run, interleave: the **N** legitimate stream (so there is a realistic "normal" class), the **WS C1–C6** block (source-separable), and the **A1–A5** insider anomalies from the HMI.
- Target ≥30 instances of each anomaly class so R3's "≥30 events per class" precondition is met for at least the aggregate anomaly-vs-normal split.
- Restart `run_server.py` before the run (fresh datastore) and run Step 9 read-back as before.
- Package: `eve.json` (with request detail), `iptables_drops.log`, `scenario_file.csv` (extended schema), `versions.txt`, rules, read-back JSONs, and the pcap if used.

## 10. Safety and scope

- All traffic is generated by the testbed generator on the **HMI VM** to the **lab pymodbus PLC**; the "insider" is a lab emulation of a compromised-HMI threat (standard in ICS IDS research), not a real compromise.
- All values stay within Modbus 16-bit limits and the simulated datastore; nothing targets a real device, and the analysis/ATMOS side never issues control commands.
- `authorized`/`anomaly_class` are declared ground truth for evaluation only.

## 11. Acceptance criteria

1. Scenario CSV carries `address`, `value`, `inter_arrival_ms`, and an `authorized` field that is **not** a function of `source_ip` (an insider row has HMI source and `authorized=0`). **→ MET** — 14-column CSV; `authorized`/`anomaly_class` declared by the generator, never derived from source IP.
2. `eve.json` (or pcap) carries the observed write address and value. **→ MET** — Suricata `request.write.{address,data}`; multi-register writes decoded losslessly by `content_features.decode_write_values`, so no pcap was needed.
3. ML, trained **without** `source_ip`, achieves recall on the insider-anomaly classes well above chance **and** beats at least one static rule baseline on at least one class. **→ PARTIAL.** Recall on the insider classes is well above chance (per-class ~100%), but the content ML (Random Forest 72.11% / 0.68% FPR) does **not** beat the static content rule (71.81% / 0.68%) — it ties it. The "beats a rule" half is **not met**, and that is the finding: once the anomaly is content-visible, a rule already catches it and the ML adds no value (consistent with the three source-separable captures).
4. The four-tier ablation shows Tier 1 containment = 0% for the insider threat (same source) while Tiers 2–3 provide non-zero, differentiated detection. **→ MET** — the firewall passes every insider anomaly (authorized source); the content rule/ML catch them per-class ~100%, the exact complement of the firewall's source-only 100% containment.