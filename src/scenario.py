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
===============================================================================
"""

import json
import os
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


def load_scenario(path=None):
    path = path or DEFAULT_SCENARIO_PATH
    if not os.path.exists(path):
        return None
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


def join_labels(records, scenario):
    """
    Returns (labels, groups, matched_actions, unmatched_event_ids) for normalized records.
    labels[i] is the scenario label (0/1) or UNLABELED; groups[i] is the generator run.
    """
    idx = action_index(scenario)
    labels, groups, matched, unmatched = [], [], [], []
    for r in records:
        a = idx.get(_ts_key(r.get("timestamp_iso")))
        if a is None:
            labels.append(UNLABELED)
            groups.append(None)
            unmatched.append(r.get("event_id"))
        else:
            labels.append(int(a["label"]))
            groups.append(a.get("run"))
            matched.append(a["action_id"])
    return labels, groups, matched, unmatched


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
