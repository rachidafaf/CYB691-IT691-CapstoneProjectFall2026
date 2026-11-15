#!/usr/bin/env python3
"""
correlate_telemetry.py
Correlate scenario_file.csv (ground truth) with firewall drops, Suricata eve.json
(modbus + alerts), optional PCAP packets, and optional per-action ML predictions,
by shared test identifiers and UTC timestamps.

Run against an extracted handoff, e.g.:
    python correlate_telemetry.py \
        --scenario infrastructure/extracted_handoff/ot_telemetry_handoff_2026-11-14/scenario_file.csv \
        --eve      infrastructure/extracted_handoff/ot_telemetry_handoff_2026-11-14/eve.json \
        --drops    infrastructure/extracted_handoff/ot_telemetry_handoff_2026-11-14/iptables_drops.log \
        --out      data/runs/ot_telemetry_handoff_2026-11-14/correlated_results.csv

Handles the real testbed data:
  * iptables_drops.log is BSD-syslog format ("Nov 14 20:00:01 ..."); parsed with a
    year hint from the scenario, and SRC= required so only kernel drop lines count.
  * Suricata eve.json logs the Modbus function code as a NAME ("RdCoils", "WrSingleReg",
    ...), so function codes are normalized to 1/3/5/6/15/16 before matching.
  * Match window is symmetric (+/- tol, 2s default) to tolerate second-resolution drop
    timestamps and small inter-host clock skew.
"""
import argparse, csv, json, re, subprocess
from datetime import datetime, timezone

RX_RFC = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))")
RX_BSD = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
RX_KV = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT)=(\S+)")

# Modbus function code: numeric or Suricata name -> canonical int.
_FC_NAMES = {
    "1": 1, "rdcoils": 1, "readcoils": 1,
    "2": 2, "rddiscreteinputs": 2, "readdiscreteinputs": 2,
    "3": 3, "rdholdregs": 3, "rdholdingregs": 3, "readholdingregisters": 3,
    "4": 4, "rdinputregs": 4, "readinputregisters": 4,
    "5": 5, "wrsinglecoil": 5, "writesinglecoil": 5, "forcesinglecoil": 5,
    "6": 6, "wrsinglereg": 6, "writesingleregister": 6, "presetsingleregister": 6,
    "15": 15, "wrmultcoils": 15, "writemultiplecoils": 15, "forcemultiplecoils": 15,
    "16": 16, "wrmultregs": 16, "writemultipleregisters": 16, "presetmultipleregisters": 16,
}


def norm_fc(v):
    """Map a numeric or named Modbus function code to its canonical int, or None."""
    if v is None:
        return None
    s = re.sub(r"[^a-z0-9]", "", str(v).lower())
    if s in _FC_NAMES:
        return _FC_NAMES[s]
    try:
        return int(s)
    except ValueError:
        return None


def parse_ts(ts: str, year: int | None = None):
    """Parse RFC3339 or BSD-syslog timestamp to an epoch float (UTC). None on failure."""
    ts = ts.strip()
    t = ts.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", t):
        t = t[:-5] + t[-5:-2] + ":" + t[-2:]
    try:
        return datetime.fromisoformat(t).timestamp()
    except ValueError:
        pass
    try:
        y = year or datetime.now(timezone.utc).year
        dt = datetime.strptime(ts, "%b %d %H:%M:%S").replace(year=y, tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def scenario_year(scenario_path: str) -> int:
    with open(scenario_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            ts = row.get("timestamp_utc")
            if ts:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).year
    return datetime.now(timezone.utc).year


def load_iptables_drops(path: str, year: int):
    drops = []
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return drops
    with f:
        for line in f:
            if "CYB691-DROP" not in line or "SRC=" not in line:
                continue
            m = RX_RFC.search(line) or RX_BSD.search(line)
            if not m:
                continue
            t = parse_ts(m.group(1), year)
            if t is None:
                continue
            kv = dict(RX_KV.findall(line))
            drops.append({"ts": t, "src": kv.get("SRC"), "dst": kv.get("DST"), "dpt": kv.get("DPT")})
    return drops


def load_eve(path: str):
    modbus_evts, alerts = [], []
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return modbus_evts, alerts
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            etype = rec.get("event_type")
            if etype not in ("modbus", "alert"):
                continue
            mb = rec.get("modbus", {}) or {}
            req = mb.get("request", {}) or {}
            # Suricata may put the code (numeric or named) in any of these:
            fc = mb.get("function_code")
            if fc is None:
                fc = mb.get("function") or req.get("function_code") or req.get("function")
            item = {
                "ts": parse_ts(rec["timestamp"]),
                "src": rec.get("src_ip"),
                "dst": rec.get("dest_ip"),
                "modbus_fc": fc,
                "alert_sig": (rec.get("alert", {}) or {}).get("signature") if etype == "alert" else None,
            }
            (modbus_evts if etype == "modbus" else alerts).append(item)
    return modbus_evts, alerts


def load_pcap_syns(pcap_path: str):
    if not pcap_path:
        return []
    cmd = ["tshark", "-r", pcap_path, "-Y", "tcp.port==502", "-T", "fields",
           "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return []
    pkts = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 3:
            pkts.append({"ts": float(p[0]), "src": p[1], "dst": p[2]})
    return pkts


def load_ml(ml_path: str):
    """Optional per-action ML predictions. ml_detector does NOT emit this today;
    leave --ml unset unless you add a per-sample CSV
    (columns: run_id, case_id, source_ip, prediction, score)."""
    if not ml_path:
        return []
    rows = []
    with open(ml_path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            rows.append({
                "run_id": r.get("run_id"), "case_id": r.get("case_id"),
                "src": r.get("source_ip") or r.get("src_ip"),
                "pred": r.get("prediction") or r.get("label") or r.get("anomaly"),
                "score": r.get("score") or r.get("anomaly_score"),
            })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="scenario_file.csv")
    ap.add_argument("--eve", default="eve.json")
    ap.add_argument("--drops", default="iptables_drops.log")
    ap.add_argument("--pcap", default=None)
    ap.add_argument("--ml", default=None)
    ap.add_argument("--tol", type=float, default=2.0, help="match tolerance in seconds (+/-)")
    ap.add_argument("--out", default="correlated_results.csv")
    args = ap.parse_args()

    year = scenario_year(args.scenario)
    drops = load_iptables_drops(args.drops, year)
    modbus_evts, alerts = load_eve(args.eve)
    pcaps = load_pcap_syns(args.pcap)
    ml_rows = load_ml(args.ml)

    out_fields = ["timestamp_utc", "run_id", "topology", "case_id", "source_ip", "dest_ip",
                  "function_code", "authorized", "fw_decision", "fw_drop_count",
                  "pcap_pkt_count", "suricata_modbus_count", "suricata_alert_count",
                  "suricata_signatures", "ml_prediction", "ml_score"]

    n, n_drop, n_alerted, n_modbus_seen = 0, 0, 0, 0
    with open(args.scenario, newline="", encoding="utf-8-sig") as fin, \
         open(args.out, "w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=out_fields)
        writer.writeheader()
        for row in csv.DictReader(fin):
            n += 1
            t0 = parse_ts(row["timestamp_utc"])
            src, dst = row["source_ip"], row["dest_ip"]
            fc = norm_fc(row.get("function_code"))

            def win(x):
                return x["src"] == src and x["dst"] == dst and t0 is not None \
                    and abs(x["ts"] - t0) <= args.tol

            def win_mb(x):
                if not win(x):
                    return False
                nf = norm_fc(x["modbus_fc"])
                if nf is not None and fc is not None:
                    return nf == fc
                return True

            m_drops = [d for d in drops if win(d)]
            m_mb = [m for m in modbus_evts if win_mb(m)]
            m_al = [a for a in alerts if win(a)]
            m_pcap = [p for p in pcaps if win(p)]
            m_ml = [m for m in ml_rows if m.get("run_id") == row["run_id"]
                    and m.get("case_id") == row["case_id"] and m.get("src") == src]

            fw_decision = "DROP" if m_drops else "ALLOW"
            sigs = ";".join(sorted({a["alert_sig"] for a in m_al if a["alert_sig"]}))
            n_drop += bool(m_drops)
            n_alerted += bool(m_al)
            n_modbus_seen += bool(m_mb)

            writer.writerow({
                "timestamp_utc": row["timestamp_utc"], "run_id": row["run_id"],
                "topology": row["topology"], "case_id": row["case_id"],
                "source_ip": src, "dest_ip": dst,
                "function_code": row["function_code"], "authorized": row["authorized"],
                "fw_decision": fw_decision, "fw_drop_count": len(m_drops),
                "pcap_pkt_count": len(m_pcap), "suricata_modbus_count": len(m_mb),
                "suricata_alert_count": len(m_al), "suricata_signatures": sigs,
                "ml_prediction": m_ml[0]["pred"] if m_ml else "",
                "ml_score": m_ml[0]["score"] if m_ml else "",
            })

    print(f"Wrote {args.out}")
    print(f"  actions={n}  fw_DROP={n_drop}  fw_ALLOW={n - n_drop}")
    print(f"  reached-PLC (modbus seen)={n_modbus_seen}  alerted={n_alerted}")
    print(f"  loaded: drops={len(drops)} modbus={len(modbus_evts)} alerts={len(alerts)} "
          f"pcap={len(pcaps)} ml={len(ml_rows)}")
    if len(drops) == 0:
        print("  NOTE: 0 drop lines parsed - check the drops file path/format.")
    if len(modbus_evts) and n_modbus_seen == 0:
        print("  NOTE: modbus events loaded but none matched - check clock skew or the fc field.")


if __name__ == "__main__":
    main()