#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: Scenario/Action Record - independent ground truth (scenario.py)
===============================================================================
Ground truth for the detection experiment comes from what the experiment DID,
not from the features a model sees. `data/scenario_actions.json` lists every
action the traffic generator performed (who sent which command to which
target, and whether that actor was authorized to perform it). Labels are joined
to normalized telemetry by the event timestamp.

Changing a feature (function code, payload, threat score...) of an event can
never change its label: only editing the scenario record can.

Two record formats are accepted:
  * data/scenario_actions.json  (cyb691-scenario-actions/1.0, actions with timestamp_utc)
  * a generator CSV written at execution time, e.g. infrastructure/logs/scenario_file.csv:
      timestamp[_utc], scenario_id|case_id, network_mode|topology, source_ip,
      [dest_ip], function_code, authorized_yes_no|authorized, [run_id]
    Every timestamp must carry a zone (Z or +hh:mm); a CSV row without one is rejected
    rather than guessed. label = 1 when the row is NOT authorized.

Joining: an action matches the event with exactly its timestamp; a CSV action (which
records when the command was SENT, not when the sensor saw it) otherwise matches the
nearest Modbus event from the same source IP with the same function code within
CYB691_SCENARIO_MATCH_TOLERANCE_S seconds (default 2). Each event matches at most one action.

  python src/scenario.py infrastructure/logs/scenario_file.csv [data/normalized_telemetry.json]
prints how many actions match events, and why the others do not.
===============================================================================
"""

import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_SCENARIO_PATH = os.path.join(REPO_ROOT, "data", "scenario_actions.json")
UNLABELED = -1


def _ts_key(ts):
    """Normalizes an ISO-8601 timestamp to a canonical UTC string for joining."""
    if not ts:
        return None
    s = str(ts).strip().replace("Z", "+00:00")
    if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":     # +0000 -> +00:00
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


MATCH_TOLERANCE_S = float(os.environ.get("CYB691_SCENARIO_MATCH_TOLERANCE_S", "2.0"))

_CSV_COLUMNS = {
    "timestamp": ("timestamp_utc", "timestamp"),
    "case": ("case_id", "scenario_id"),
    "mode": ("topology", "network_mode"),
    "source": ("source_ip",),
    "dest": ("dest_ip",),
    "fc": ("function_code",),
    "authorized": ("authorized", "authorized_yes_no"),
    "run": ("run_id",),
}
_YES, _NO = {"1", "yes", "y", "true", "t"}, {"0", "no", "n", "false", "f"}


def _col(row, key):
    for name in _CSV_COLUMNS[key]:
        if name in row and str(row[name]).strip() != "":
            return str(row[name]).strip()
    return None


def load_scenario_csv(path):
    """Converts a generator scenario CSV into the scenario-record structure used here."""
    with open(path, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    actions = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [k for k in ("timestamp", "source", "fc", "authorized")
                   if not any(n in (reader.fieldnames or []) for n in _CSV_COLUMNS[k])]
        if missing:
            raise ValueError(f"{path}: missing column(s) for {missing}; header is {reader.fieldnames}")
        for i, row in enumerate(reader, start=2):              # line 1 is the header
            row = {(k or "").strip(): v for k, v in row.items()}
            ts = _col(row, "timestamp")
            if _ts_key(ts) is None:
                raise ValueError(f"{path} line {i}: timestamp {ts!r} is missing or has no timezone")
            auth = (_col(row, "authorized") or "").lower()
            if auth not in _YES | _NO:
                raise ValueError(f"{path} line {i}: authorized value {auth!r} is not yes/no/1/0")
            try:
                fc = int(_col(row, "fc"), 0) if str(_col(row, "fc")).lower().startswith("0x") else int(_col(row, "fc"))
            except (TypeError, ValueError):
                raise ValueError(f"{path} line {i}: function_code {_col(row, 'fc')!r} is not a number")
            run = _col(row, "run") or "R1"
            authorized = auth in _YES
            actions.append({
                "action_id": f"{run}-L{i}", "run": run, "timestamp_utc": ts,
                "case_id": _col(row, "case"), "network_mode": _col(row, "mode"),
                "actor_ip": _col(row, "source"), "target": _col(row, "dest"),
                "function_code": fc, "authorized": authorized, "label": 0 if authorized else 1,
            })
    return {
        "schema": "cyb691-scenario-actions/1.0",
        "scenario_id": os.path.splitext(os.path.basename(path))[0],
        "capture": {"scenario_csv": os.path.relpath(path, REPO_ROOT).replace(os.sep, "/"), "scenario_csv_sha256": sha},
        "label_definition": "label = 1 if the generator logged the action as not authorized (authorized = 0/no)",
        "provenance": {"status": "generator CSV (as delivered)", "confirmed_by": None, "confirmed_on": None},
        "actions": actions,
    }


def load_scenario(path=None):
    path = path or os.environ.get("CYB691_SCENARIO_PATH") or DEFAULT_SCENARIO_PATH
    if not os.path.exists(path):
        return None
    if path.lower().endswith(".csv"):
        doc = load_scenario_csv(path)
        if not doc["actions"]:
            raise ValueError(f"{path}: no actions")
        return doc
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or not isinstance(doc.get("actions"), list):
        raise ValueError(f"{path}: not a scenario action record (missing 'actions' list)")
    for a in doc["actions"]:
        if a.get("label") not in (0, 1):
            raise ValueError(f"{path}: action {a.get('action_id')} has no 0/1 label")
        if _ts_key(a.get("timestamp_utc")) is None:
            raise ValueError(f"{path}: action {a.get('action_id')} has an invalid timestamp_utc")
    return doc


def action_index(scenario):
    """Maps canonical timestamp -> action row."""
    if not scenario:
        return {}
    return {_ts_key(a["timestamp_utc"]): a for a in scenario["actions"]}


def _event_src_fc(r):
    net, mb = r.get("network") or {}, r.get("modbus") or {}
    return net.get("source_ip") or r.get("src_ip"), mb.get("function_code")


def match_actions(records, scenario, tolerance_s=None):
    """Returns {record index: action}. Exact timestamp first; then, for actions that name an
    actor IP and a function code, the nearest unmatched event from that source with that
    function code within the tolerance."""
    tol = MATCH_TOLERANCE_S if tolerance_s is None else tolerance_s
    actions = (scenario or {}).get("actions") or []
    keys = [_ts_key(r.get("timestamp_iso")) for r in records]
    by_key = {}
    for i, k in enumerate(keys):
        by_key.setdefault(k, []).append(i)
    out, used = {}, set()
    pending = []
    for a in actions:
        hit = [i for i in by_key.get(_ts_key(a.get("timestamp_utc")), []) if i not in used]
        if hit:
            out[hit[0]] = a
            used.add(hit[0])
        elif a.get("actor_ip") and a.get("function_code") is not None:
            pending.append(a)
    times = [datetime.fromisoformat(k) if k else None for k in keys]
    for a in pending:
        at = datetime.fromisoformat(_ts_key(a["timestamp_utc"]))
        best, best_d = None, None
        for i, r in enumerate(records):
            if i in used or times[i] is None:
                continue
            src, fc = _event_src_fc(r)
            if src != a["actor_ip"] or fc != a["function_code"]:
                continue
            d = abs((times[i] - at).total_seconds())
            if d <= tol and (best_d is None or d < best_d):
                best, best_d = i, d
        if best is not None:
            out[best] = a
            used.add(best)
    return out


def join_labels(records, scenario):
    """
    Returns (labels, groups, matched_actions, unmatched_event_ids) for normalized records.
    labels[i] is the scenario label (0/1) or UNLABELED; groups[i] is the generator run.
    """
    hits = match_actions(records, scenario)
    labels, groups, matched, unmatched = [], [], [], []
    for i, r in enumerate(records):
        a = hits.get(i)
        if a is None:
            labels.append(UNLABELED)
            groups.append(None)
            unmatched.append(r.get("event_id"))
        else:
            labels.append(int(a["label"]))
            groups.append(a.get("run"))
            matched.append(a["action_id"])
    return labels, groups, matched, unmatched


def explain_unmatched(records, scenario, tolerance_s=None):
    """For each action with no event: the closest same-source, same-function-code event and how far away it is."""
    tol = MATCH_TOLERANCE_S if tolerance_s is None else tolerance_s
    matched = {id(a) for a in match_actions(records, scenario, tol).values()}
    rows = []
    for a in (scenario or {}).get("actions") or []:
        if id(a) in matched:
            continue
        at = datetime.fromisoformat(_ts_key(a["timestamp_utc"]))
        cands = []
        for r in records:
            src, fc = _event_src_fc(r)
            k = _ts_key(r.get("timestamp_iso"))
            if k and src == a.get("actor_ip") and fc == a.get("function_code"):
                cands.append(((datetime.fromisoformat(k) - at).total_seconds(), r.get("timestamp_iso")))
        near = min(cands, key=lambda c: abs(c[0])) if cands else None
        rows.append({"action_id": a.get("action_id"), "case_id": a.get("case_id"), "timestamp_utc": a.get("timestamp_utc"),
                     "actor_ip": a.get("actor_ip"), "function_code": a.get("function_code"),
                     "nearest_event": near[1] if near else None,
                     "offset_s": round(near[0], 3) if near else None,
                     "reason": ("no Modbus event from this source with this function code" if not near else
                                f"nearest matching event is {near[0]:+.1f} s away (tolerance {tol} s)")})
    return rows


def provenance_summary(scenario, path=None):
    if not scenario:
        return {"source": None, "status": "MISSING"}
    prov = scenario.get("provenance", {})
    return {
        "source": os.path.relpath(path or DEFAULT_SCENARIO_PATH, REPO_ROOT).replace(os.sep, "/"),
        "scenario_id": scenario.get("scenario_id"),
        "label_definition": scenario.get("label_definition"),
        "status": prov.get("status"),
        "confirmed_by": prov.get("confirmed_by"),
        "confirmed_on": prov.get("confirmed_on"),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sc = load_scenario(sys.argv[1])
    norm = sys.argv[2] if len(sys.argv) > 2 else os.path.join(REPO_ROOT, "data", "normalized_telemetry.json")
    with open(norm, encoding="utf-8") as f:
        recs = json.load(f)
    recs = recs if isinstance(recs, list) else recs.get("records", [])
    labels, _, matched, _ = join_labels(recs, sc)
    print(f"{len(sc['actions'])} actions, {len(recs)} events, {len(matched)} actions matched "
          f"(tolerance {MATCH_TOLERANCE_S} s)")
    for row in explain_unmatched(recs, sc):
        print(f"  unmatched {row['action_id']} {row['case_id'] or ''} {row['timestamp_utc']} "
              f"{row['actor_ip']} FC{row['function_code']}: {row['reason']}")
