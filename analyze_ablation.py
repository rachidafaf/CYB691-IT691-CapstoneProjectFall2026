#!/usr/bin/env python3
"""
analyze_ablation.py  --  Step 8 four-tier ablation report generator.

Regenerates the layered-defense ablation (containment + marginal detection)
for one telemetry handoff, in one command:

    python analyze_ablation.py                # newest handoff under data/runs/
    python analyze_ablation.py 2026-11-07     # by capture date
    python analyze_ablation.py ot_telemetry_handoff_2026-11-07

It reads two sources that it does NOT have to trust each other:

  * Tiers 0-2 and containment  <-  PostgreSQL telemetry_events, scoped to the
    capture's calendar date, split by source IP (ground truth) and by policy
    phase (baseline = before the first firewall drop, layered = from it on).
    The query is run through `docker compose exec postgres psql`, so no Python
    database driver is required.

  * Tier 3 (ML)                <-  data/runs/<handoff>/3-ml_detector.log, the
    confirmed-format benchmark summary your ml_detector.py already writes.

Output: the two ladders printed to the console, plus a machine-readable
data/runs/<handoff>/ablation_summary.json you can cite in the report.

Ground truth for THIS threat model is source IP:
    HMI 10.0.1.10 = authorized,  WS 10.0.1.20 = unauthorized.
When Step 7 introduces content-distinguishable threats from an authorized
host, extend --auth-ip / --unauth-ip or move to a scenario-CSV join.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# --- repo-relative locations (this file lives at the repo root) ---------------
REPO = Path(__file__).resolve().parent
COMPOSE = REPO / "deploy" / "docker" / "docker-compose.yml"
RUNS = REPO / "data" / "runs"

AUTH_IP_DEFAULT = "10.0.1.10"      # HMI  -> authorized
UNAUTH_IP_DEFAULT = "10.0.1.20"    # WS   -> unauthorized
HANDOFF_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


# --- helpers -----------------------------------------------------------------
def die(msg: str, code: int = 1) -> "typing.NoReturn":  # noqa: F821
    print(f"[analyze_ablation] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def resolve_handoff(arg: str | None) -> tuple[str, str]:
    """Return (handoff_name, capture_date 'YYYY-MM-DD')."""
    if not RUNS.is_dir():
        die(f"no run directory at {RUNS} (run the pipeline first)")

    candidates = sorted(
        (p for p in RUNS.iterdir() if p.is_dir() and p.name.startswith("ot_telemetry_handoff_")),
        key=lambda p: p.name,
    )
    if not candidates:
        die(f"no ot_telemetry_handoff_* run directories under {RUNS}")

    if arg is None:
        chosen = candidates[-1]  # newest by name (date-sorted)
    elif (RUNS / arg).is_dir():
        chosen = RUNS / arg
    else:
        # treat arg as a date fragment
        matches = [p for p in candidates if arg in p.name]
        if not matches:
            die(f"no run directory matches '{arg}'. Available: "
                + ", ".join(p.name for p in candidates))
        chosen = matches[-1]

    m = HANDOFF_RE.search(chosen.name)
    if not m:
        die(f"cannot find a YYYY-MM-DD date in '{chosen.name}'")
    return chosen.name, m.group(1)


def run_matrix_sql(capture_date: str, auth_ip: str, unauth_ip: str) -> dict[tuple[str, str, str], int]:
    """Run the phase/truth/event_type matrix through docker compose psql."""
    sql = f"""
WITH ev AS (
  SELECT *,
    CASE WHEN src_ip='{unauth_ip}' THEN 'unauth'
         WHEN src_ip='{auth_ip}'   THEN 'auth'
         ELSE 'other' END AS truth
  FROM telemetry_events
  WHERE timestamp_utc::date = DATE '{capture_date}'
),
sw AS (SELECT min(timestamp_utc) AS layered_start FROM ev WHERE event_type='FIREWALL_DROP'),
lab AS (
  SELECT ev.*,
    CASE WHEN sw.layered_start IS NOT NULL AND ev.timestamp_utc >= sw.layered_start
         THEN 'layered' ELSE 'baseline' END AS phase
  FROM ev CROSS JOIN sw
)
SELECT phase, truth, event_type, count(*) AS n
FROM lab
GROUP BY 1,2,3
ORDER BY 1,2,3;
""".strip()

    cmd = [
        "docker", "compose", "-f", str(COMPOSE), "exec", "-T", "postgres",
        "psql", "-U", "cyb691_admin", "-d", "cyb691",
        "-At", "-F", "|", "-c", sql,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        die("`docker` not found on PATH. Start Docker Desktop and run from the repo root.")
    except subprocess.CalledProcessError as e:
        die("psql query failed:\n" + (e.stderr or e.stdout or "").strip())

    matrix: dict[tuple[str, str, str], int] = {}
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) != 4:
            continue
        phase, truth, etype, n = parts
        matrix[(phase.strip(), truth.strip(), etype.strip())] = int(n)
    if not matrix:
        die(f"no telemetry_events on {capture_date}. Is this capture ingested? "
            "Check `timestamp_utc::date` matches the traffic day.")
    return matrix


def parse_ml_log(run_dir: Path) -> dict:
    """Parse 3-ml_detector.log for supervised models, rule baseline, iso-forest."""
    log = run_dir / "3-ml_detector.log"
    if not log.is_file():
        return {"available": False, "reason": f"{log.name} not found"}
    text = log.read_text(encoding="utf-8", errors="replace")

    sec_re = re.compile(r">\s*Feature set '([^']+)'\s*\|\s*(\w+)")
    mdl_re = re.compile(r"-\s+(.+?)\s{2,}recall\s+([\d.]+)%\s+FPR\s+([\d.]+)%\s+acc\s+([\d.]+)%")
    rule_re = re.compile(r"Rule baseline:.*?recall\s+([\d.]+)%,\s*FPR\s+([\d.]+)%")
    iso_re = re.compile(r"Isolation Forest.*?flagged\s+(\d+)/(\d+),\s*recall\s+([\d.]+)%,\s*FPR\s+([\d.]+)%")
    rec_re = re.compile(r"Records:\s*(\d+)\s*\((\d+)\s+unauthorized[^,]*,\s*(\d+)\s+authorized")

    feature, cv = None, None
    models: list[dict] = []
    for line in text.splitlines():
        s = sec_re.search(line)
        if s:
            feature, cv = s.group(1), s.group(2)
            continue
        m = mdl_re.search(line)
        if m:
            models.append({
                "model": m.group(1).strip(),
                "feature_set": feature,
                "cv": cv,
                "recall_pct": float(m.group(2)),
                "fpr_pct": float(m.group(3)),
                "accuracy_pct": float(m.group(4)),
            })

    out: dict = {"available": True, "n_models": len(models), "models": models}
    if models:
        best = max(models, key=lambda d: d["accuracy_pct"])
        out["best_supervised"] = best
        out["accuracy_range_pct"] = [min(d["accuracy_pct"] for d in models),
                                     max(d["accuracy_pct"] for d in models)]
        out["recall_range_pct"] = [min(d["recall_pct"] for d in models),
                                   max(d["recall_pct"] for d in models)]
    r = rule_re.search(text)
    if r:
        out["rule_baseline"] = {"recall_pct": float(r.group(1)), "fpr_pct": float(r.group(2))}
    i = iso_re.search(text)
    if i:
        out["isolation_forest"] = {
            "flagged": int(i.group(1)), "total": int(i.group(2)),
            "recall_pct": float(i.group(3)), "fpr_pct": float(i.group(4)),
        }
    c = rec_re.search(text)
    if c:
        out["labelled_records"] = {
            "total": int(c.group(1)), "unauthorized": int(c.group(2)), "authorized": int(c.group(3)),
        }
    return out


def pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 1) if den else 0.0


# --- main --------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Four-tier OT-defense ablation report for one handoff.")
    ap.add_argument("handoff", nargs="?", help="capture date (YYYY-MM-DD) or handoff name; default = newest")
    ap.add_argument("--auth-ip", default=AUTH_IP_DEFAULT, help=f"authorized source IP (default {AUTH_IP_DEFAULT})")
    ap.add_argument("--unauth-ip", default=UNAUTH_IP_DEFAULT, help=f"unauthorized source IP (default {UNAUTH_IP_DEFAULT})")
    args = ap.parse_args()

    name, date = resolve_handoff(args.handoff)
    run_dir = RUNS / name
    matrix = run_matrix_sql(date, args.auth_ip, args.unauth_ip)

    def g(phase: str, truth: str, etype: str) -> int:
        return matrix.get((phase, truth, etype), 0)

    # --- containment (prevention): unauthorized Modbus reaching the PLC -------
    flat_reached = g("baseline", "unauth", "MODBUS_DPI")      # no firewall
    enf_reached = g("layered", "unauth", "MODBUS_DPI")        # with firewall
    drops = g("layered", "unauth", "FIREWALL_DROP")
    contained_pct = pct(flat_reached - enf_reached, flat_reached)

    # --- detection on the flat traffic (the commands that actually flowed) ----
    pop = flat_reached  # denominator = unauthorized commands reaching the PLC
    suri_hits = g("baseline", "unauth", "SURICATA_ALERT")
    suri_recall = pct(suri_hits, pop)
    suri_fp = g("baseline", "auth", "SURICATA_ALERT")
    suri_fpr = pct(suri_fp, g("baseline", "auth", "MODBUS_DPI"))

    ml = parse_ml_log(run_dir)

    # --- data-quality / secondary findings, auto-detected --------------------
    findings: list[str] = []
    if g("other", "", "") or any(k[1] == "other" for k in matrix):
        findings.append("Some events have a source IP that is neither the authorized nor the "
                        "unauthorized host (truth='other') - check --auth-ip/--unauth-ip.")
    if g("layered", "unauth", "SURICATA_ALERT") == 0 and drops > 0:
        findings.append("No Suricata alerts in the layered phase: the firewall drops WS packets "
                        "before DPI inspects them, so the IDS has no visibility into contained traffic.")
    la_auth = g("baseline", "auth", "LOCAL_ALERT")
    la_auth_pop = g("baseline", "auth", "MODBUS_DPI")
    if la_auth and la_auth_pop and (la_auth / la_auth_pop) > 0.25:
        findings.append(f"Edge-collector LOCAL_ALERT fires on {la_auth}/{la_auth_pop} authorized "
                        "commands (high false-positive heuristic); not part of the layered controls.")
    if ml.get("available") and "best_supervised" in ml:
        b = ml["best_supervised"]
        if abs(b["recall_pct"] - b["fpr_pct"]) < 10:
            findings.append(f"ML operates at chance: best model recall {b['recall_pct']}% "
                            f"vs FPR {b['fpr_pct']}% (recall approx FPR = no discriminative signal).")
    if enf_reached == 0 and flat_reached == 0:
        findings.append("No unauthorized Modbus events in either phase - nothing reached the PLC to "
                        "measure; confirm the capture actually ran the unauthorized host.")
    if drops == 0:
        findings.append("No firewall drops found: the layered phase may be missing, so containment "
                        "cannot be measured (all events fell into 'baseline').")

    # --- print ---------------------------------------------------------------
    bar = "=" * 72
    print(bar)
    print(f" FOUR-TIER ABLATION  |  {name}  |  capture date {date}")
    print(f" ground truth: authorized={args.auth_ip}  unauthorized={args.unauth_ip}")
    print(bar)

    print("\n CONTAINMENT LADDER (prevention: did the unauthorized command reach the PLC?)")
    print(" " + "-" * 70)
    print(f" {'Tier':<5}{'Layer':<26}{'Reached PLC':<14}{'Contained':<12}{'Marginal'}")
    print(f" {'0':<5}{'Flat network':<26}{str(flat_reached)+'/'+str(flat_reached):<14}{'0%':<12}{'-'}")
    print(f" {'1':<5}{'Firewall ACL (source)':<26}"
          f"{str(enf_reached)+'/'+str(flat_reached):<14}{str(contained_pct)+'%':<12}"
          f"+{contained_pct}%  ({drops} drop-logs)")
    print(f" {'2':<5}{'Suricata DPI':<26}{'-':<14}{'-':<12}+0%  (detection layer)")
    print(f" {'3':<5}{'ML anomaly':<26}{'-':<14}{'-':<12}+0%  (detection layer)")

    print("\n DETECTION LADDER (on the "
          f"{pop} unauthorized commands that flow in the flat case)")
    print(" " + "-" * 70)
    print(f" {'Layer':<30}{'Recall':<12}{'FPR':<12}{'Note'}")
    print(f" {'Firewall drop-log (source)':<30}"
          f"{str(pct(drops, pop))+'%':<12}{'0%':<12}logs every attempt when enforcing")
    print(f" {'Suricata (signature)':<30}{str(suri_recall)+'%':<12}{str(suri_fpr)+'%':<12}"
          f"{suri_hits}/{pop} flagged")
    if ml.get("available") and "best_supervised" in ml:
        b = ml["best_supervised"]
        print(f" {'ML (content, best model)':<30}{str(b['recall_pct'])+'%':<12}"
              f"{str(b['fpr_pct'])+'%':<12}{b['model']} / {b['feature_set']} / {b['cv']}")
        if "rule_baseline" in ml:
            rb = ml["rule_baseline"]
            print(f" {'  rule baseline (write FCs)':<30}{str(rb['recall_pct'])+'%':<12}"
                  f"{str(rb['fpr_pct'])+'%':<12}function-code heuristic")
        if "isolation_forest" in ml:
            iso = ml["isolation_forest"]
            print(f" {'  isolation forest (unsup.)':<30}{str(iso['recall_pct'])+'%':<12}"
                  f"{str(iso['fpr_pct'])+'%':<12}{iso['flagged']}/{iso['total']} flagged")
    else:
        print(f"   ML: {ml.get('reason', 'not parsed')}")

    if findings:
        print("\n FINDINGS / CAVEATS")
        print(" " + "-" * 70)
        for f in findings:
            print(f"  * {f}")

    # --- machine-readable summary -------------------------------------------
    summary = {
        "handoff": name,
        "capture_date": date,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ground_truth": {"authorized_ip": args.auth_ip, "unauthorized_ip": args.unauth_ip},
        "containment": {
            "unauth_reached_plc_flat": flat_reached,
            "unauth_reached_plc_enforced": enf_reached,
            "firewall_drops": drops,
            "contained_pct": contained_pct,
        },
        "detection_on_flat": {
            "population": pop,
            "firewall_source": {"recall_pct": pct(drops, pop), "fpr_pct": 0.0},
            "suricata": {"hits": suri_hits, "recall_pct": suri_recall, "fpr_pct": suri_fpr},
            "ml": ml,
        },
        "raw_matrix": {"|".join(k): v for k, v in sorted(matrix.items())},
        "findings": findings,
    }
    out_path = run_dir / "ablation_summary.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\n[+] wrote {out_path}")
    print(bar)


if __name__ == "__main__":
    main()