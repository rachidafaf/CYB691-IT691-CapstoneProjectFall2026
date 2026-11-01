#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: OWASP STRIDE Threat-Model Inventory & Security Property Auditor
        (validate_stride_threats.py)
Author: Rachid Afaf (Security Architect & Security Hardening Lead)
===============================================================================
Two kinds of result are reported and never mixed:

  INVENTORY  - the threat model and repository artifacts exist and are well formed
               (counts of threats, components, trust boundaries, policy files).
               An inventory result says nothing about whether a threat is mitigated.

  PROPERTY   - a security property was actually exercised:
     P1 Parser controls: the real functions in src/log_parser.py are imported and
        driven with hostile inputs (Tar-Slip archive, link member, empty-log marker,
        non-Modbus EVE event). Source text is never grepped.
     P2 Normalized data vs raw evidence: normalized_telemetry.json is reconciled
        against the raw eve.json (unique Modbus transactions and function codes)
        and against parser_integrity_report.json.
     P3 ML evaluation method: ml_evaluation_results.json must carry scenario-record
        ground truth, request-time-only primary features, separate fit/predict
        timing and a label-free Isolation Forest; targets are compared, not assumed.

The overall conclusion is derived from the checks: any FAIL -> FAILED; any WARN ->
PARTIAL. Threat status (OPEN/MITIGATED...) is read from the model, not asserted.

  python validate_stride_threats.py [--root <repo>] [--model <json>] [--no-write]
===============================================================================
"""

import argparse
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
from collections import Counter
from datetime import datetime, timezone

GREEN, RED, YELLOW, CYAN, BOLD, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"
WRITE_FCS, READ_FCS = {5, 6, 15, 16}, {1, 2, 3, 4}


def _log(colour, tag, msg):
    print(f"{colour}[{tag}]{RESET} {msg}")


def log_info(msg): _log(CYAN, "INFO", msg)
def log_pass(msg): _log(GREEN, "PASS", msg)
def log_warn(msg): _log(YELLOW, "WARN", msg)
def log_fail(msg): _log(RED, "FAIL", msg)


def get_repo_root(root=None):
    if root:
        return os.path.abspath(root)
    for c in (os.path.abspath(os.path.dirname(__file__)),
              os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), os.path.abspath(".")):
        if os.path.exists(os.path.join(c, "Team 4 Threat Model.json")):
            return c
    return os.path.abspath(os.path.dirname(__file__))


def locate_threat_model_json(custom_path=None, root=None):
    if custom_path and os.path.exists(custom_path):
        return custom_path
    r = get_repo_root(root)
    for name in ("Team 4 Threat Model.json", "Team_4_Threat_Model.json"):
        for d in (r, os.path.join(r, "data")):
            if os.path.exists(os.path.join(d, name)):
                return os.path.join(d, name)
    return None


def locate_artifact_file(filename, root=None):
    r = get_repo_root(root)
    for d in (r, os.path.join(r, "src"), os.path.join(r, "data"), os.path.join(r, "infrastructure")):
        p = os.path.join(d, filename)
        if os.path.exists(p):
            return p
    return None


class Checks:
    def __init__(self):
        self.items = []

    def add(self, kind, check, status, details):
        self.items.append({"kind": kind, "check": check, "status": status, "details": details})
        {"PASS": log_pass, "WARN": log_warn, "FAIL": log_fail, "INVENTORY": log_info}[status](
            f"{kind} | {check}: {details}")

    def count(self, status):
        return sum(1 for c in self.items if c["status"] == status)


# =============================================================================
# INVENTORY: threat model
# =============================================================================
def inventory_threat_model(json_path, checks):
    with open(json_path, "r", encoding="utf-8") as f:
        tm = json.load(f)
    diagrams = tm.get("detail", {}).get("diagrams", [])
    threats, boundaries, components = [], [], set()
    for d in diagrams:
        for cell in d.get("cells", []):
            data = cell.get("data", {}) or {}
            name = data.get("name", cell.get("id", "unknown"))
            if cell.get("shape") == "trust-boundary-curve" or data.get("isTrustBoundary"):
                boundaries.append({"id": cell.get("id"), "name": name})
            for t in data.get("threats", []) or []:
                components.add(name)
                threats.append({**t, "component_name": name})
    stride = Counter()
    for t in threats:
        ty = str(t.get("type", "")).lower()
        key = next((k for k, words in (("Spoofing", ("spoof",)), ("Tampering", ("tamper",)),
                                       ("Repudiation", ("repudiation",)),
                                       ("Information Disclosure", ("information", "disclosure")),
                                       ("Denial of Service", ("denial",)),
                                       ("Elevation of Privilege", ("elevation", "privilege")))
                    if any(w in ty for w in words)), "Other")
        stride[key] += 1
    status = Counter(str(t.get("status", "Unknown")) for t in threats)
    severity = Counter(str(t.get("severity", "Unknown")) for t in threats)
    inv = {"title": tm.get("summary", {}).get("title"), "schema_version": tm.get("version"),
           "diagrams": len(diagrams), "threats": len(threats), "components_with_threats": len(components),
           "trust_boundaries": boundaries, "stride_counts": dict(stride), "status_counts": dict(status),
           "severity_counts": dict(severity)}
    if not diagrams or not threats:
        checks.add("INVENTORY", "Threat model structure", "FAIL", "no diagrams or no threats in the model")
    else:
        checks.add("INVENTORY", "Threat model structure", "INVENTORY",
                   f"{len(threats)} threats on {len(components)} components, {len(boundaries)} trust boundaries; "
                   f"status as recorded in the model: {dict(status)}")
    for expected in ("OT Network Boundary", "Analysis Evidence Boundary"):
        found = any(expected.lower() in b["name"].lower() for b in boundaries)
        checks.add("INVENTORY", f"Trust boundary '{expected}'", "INVENTORY" if found else "WARN",
                   "present in model" if found else "missing from model")
    return inv


# =============================================================================
# PROPERTY P1: parser controls, exercised for real
# =============================================================================
def _import_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.dirname(path))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod


def _tar_with(member_name, link_target=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(member_name)
        if link_target:
            info.type, info.linkname = tarfile.SYMTYPE, link_target
            tar.addfile(info)
        else:
            payload = b"x"
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def property_parser_controls(root, checks):
    path = locate_artifact_file("log_parser.py", root)
    if not path:
        checks.add("PROPERTY", "P1 Parser controls", "FAIL", "src/log_parser.py not found")
        return
    try:
        lp = _import_module(path, "cyb691_audit_log_parser")
    except Exception as exc:
        checks.add("PROPERTY", "P1 Parser controls", "FAIL", f"log_parser.py cannot be imported: {exc!r}")
        return
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        # (a) Tar-Slip: '../' member must be refused and nothing written outside the target
        try:
            evil = os.path.join(tmp, "evil.tar.gz")
            with open(evil, "wb") as f:
                f.write(_tar_with("../escaped.txt"))
            out = os.path.join(tmp, "out")
            refused = False
            try:
                lp.safe_extract_tarball(evil, out)
            except Exception:
                refused = True
            results["tar_slip_refused"] = refused and not os.path.exists(os.path.join(tmp, "escaped.txt"))
        except AttributeError:
            results["tar_slip_refused"] = False
        # (b) link member pointing outside must be refused
        try:
            link = os.path.join(tmp, "link.tar.gz")
            with open(link, "wb") as f:
                f.write(_tar_with("var/log/innocent", link_target="/etc/passwd"))
            refused = False
            try:
                lp.safe_extract_tarball(link, os.path.join(tmp, "out2"))
            except Exception:
                refused = True
            results["link_member_refused"] = refused
        except AttributeError:
            results["link_member_refused"] = False
        # (c) empty-log marker yields zero firewall drops; a real drop line yields one
        try:
            empty = os.path.join(tmp, "empty.log")
            with open(empty, "w", encoding="utf-8") as f:
                f.write("-- No entries --\n")
            real = os.path.join(tmp, "real.log")
            with open(real, "w", encoding="utf-8") as f:
                f.write("Sep 23 02:51:43 fw kernel: [DROP] IN=eth0 OUT= SRC=10.0.1.4 DST=10.0.3.10 "
                        "PROTO=TCP SPT=41238 DPT=502\n")
            results["empty_marker_rejected"] = len(lp.normalize_iptables_drops(empty)) == 0
            results["real_drop_accepted"] = len(lp.normalize_iptables_drops(real)) == 1
        except Exception:
            results["empty_marker_rejected"] = results["real_drop_accepted"] = False
        # (d) EVE: only event_type == modbus is normalized, and function_raw is preserved
        try:
            eve = os.path.join(tmp, "eve.json")
            lines = [
                {"timestamp": "2026-09-23T02:51:43.175714+0000", "event_type": "modbus", "flow_id": 1,
                 "src_ip": "10.0.1.4", "dest_ip": "172.17.0.2", "dest_port": 5020, "proto": "TCP",
                 "modbus": {"request": {"transaction_id": 3, "unit_id": 1, "function_raw": 6,
                                        "function_code": "WrSingleReg", "write": {"address": 0, "data": 1}}}},
                {"timestamp": "2026-09-23T02:51:44.000000+0000", "event_type": "dns", "flow_id": 2,
                 "src_ip": "10.0.1.4", "dest_ip": "168.63.129.16", "dest_port": 53},
            ]
            with open(eve, "w", encoding="utf-8") as f:
                f.write("\n".join(json.dumps(x) for x in lines) + "\n")
            events = lp.normalize_suricata_eve_json(eve)
            results["only_modbus_events"] = len(events) == 1
            results["function_code_preserved"] = len(events) == 1 and int(events[0].get("fcode", -1)) == 6
        except Exception:
            results["only_modbus_events"] = results["function_code_preserved"] = False
    failed = [k for k, v in results.items() if not v]
    if failed:
        checks.add("PROPERTY", "P1 Parser controls", "FAIL", f"exercised; failed: {', '.join(failed)}")
    else:
        checks.add("PROPERTY", "P1 Parser controls", "PASS",
                   "exercised: Tar-Slip and link members refused, '-- No entries --' -> 0 drops, real drop "
                   "-> 1, non-Modbus EVE ignored, function_raw 6 preserved")


# =============================================================================
# PROPERTY P2: normalized telemetry reconciled with raw evidence
# =============================================================================
def _raw_unique_modbus(eve_path):
    seen, fcs = set(), Counter()
    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("event_type") != "modbus":
                continue
            key = json.dumps(rec, sort_keys=True, separators=(",", ":"))
            if key in seen:
                continue
            seen.add(key)
            req = (rec.get("modbus") or {}).get("request") or {}
            fcs[int(req.get("function_raw", 0) or 0)] += 1
    return len(seen), fcs


def property_normalized_vs_raw(root, checks):
    norm_path = locate_artifact_file("normalized_telemetry.json", root)
    if not norm_path:
        checks.add("PROPERTY", "P2 Normalized vs raw", "FAIL", "data/normalized_telemetry.json not found")
        return
    try:
        with open(norm_path, "r", encoding="utf-8") as f:
            norm = json.load(f)
    except ValueError as exc:
        checks.add("PROPERTY", "P2 Normalized vs raw", "FAIL", f"unparseable: {exc}")
        return
    if not isinstance(norm, list) or not norm or not all(isinstance(r, dict) and r for r in norm):
        checks.add("PROPERTY", "P2 Normalized vs raw", "FAIL", "empty dataset or empty records")
        return
    required = ("event_id", "timestamp_iso", "network", "modbus", "security")
    if not all(all(k in r for k in required) for r in norm):
        checks.add("PROPERTY", "P2 Normalized vs raw", "FAIL", f"records missing one of {required}")
        return
    modbus = [r for r in norm if str(r.get("network", {}).get("protocol", "")).lower().startswith("modbus")]
    norm_fcs = Counter(int(r["modbus"].get("function_code", 0) or 0) for r in modbus)
    drops = [r for r in norm if "drop" in str(r.get("security", {}).get("action_taken", "")).lower()]
    if norm_fcs.get(0):
        checks.add("PROPERTY", "P2 Normalized vs raw", "FAIL", f"{norm_fcs[0]} Modbus records with function code 0")
        return
    eve = os.path.join(get_repo_root(root), "infrastructure", "extracted_handoff", "var", "log", "suricata", "eve.json")
    if not os.path.exists(eve):
        checks.add("PROPERTY", "P2 Normalized vs raw", "WARN",
                   f"raw eve.json not extracted; structure only: {len(modbus)} Modbus records, fcs {dict(norm_fcs)}")
        return
    raw_n, raw_fcs = _raw_unique_modbus(eve)
    problems = []
    if raw_n != len(modbus):
        problems.append(f"raw has {raw_n} unique Modbus transactions, normalized has {len(modbus)}")
    if raw_fcs != norm_fcs:
        problems.append(f"function codes differ: raw {dict(raw_fcs)} vs normalized {dict(norm_fcs)}")
    fw = os.path.join(get_repo_root(root), "infrastructure", "extracted_handoff", "iptables_drops.log")
    if os.path.exists(fw):
        with open(fw, "r", encoding="utf-8", errors="replace") as f:
            real_lines = [l for l in f if l.strip() and "no entries" not in l.lower()]
        if len(drops) != len(real_lines):
            problems.append(f"firewall: {len(real_lines)} real raw lines but {len(drops)} normalized drops")
    integ = locate_artifact_file("parser_integrity_report.json", root)
    if integ:
        with open(integ, "r", encoding="utf-8") as f:
            rep = json.load(f)
        with open(eve, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        stated = (rep.get("eve_json") or {}).get("sha256") or rep.get("eve_json_sha256")
        if stated and stated != digest:
            problems.append("parser_integrity_report SHA-256 does not match the raw eve.json")
    if problems:
        checks.add("PROPERTY", "P2 Normalized vs raw", "FAIL", "; ".join(problems))
    else:
        checks.add("PROPERTY", "P2 Normalized vs raw", "PASS",
                   f"{len(modbus)} normalized Modbus events == {raw_n} unique raw transactions; function codes "
                   f"{dict(sorted(norm_fcs.items()))} match; {len(drops)} firewall drops == raw drop lines")


# =============================================================================
# PROPERTY P3: ML evaluation method and targets
# =============================================================================
def property_ml_method(root, checks):
    path = locate_artifact_file("ml_evaluation_results.json", root)
    if not path:
        checks.add("PROPERTY", "P3 ML evaluation", "FAIL", "data/ml_evaluation_results.json not found")
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            ml = json.load(f)
    except ValueError as exc:
        checks.add("PROPERTY", "P3 ML evaluation", "FAIL", f"unparseable: {exc}")
        return
    sup = ml.get("supervised_models") or {}
    if not isinstance(sup, dict) or not sup:
        checks.add("PROPERTY", "P3 ML evaluation", "FAIL", "no supervised model results")
        return
    gt = ml.get("ground_truth") or {}
    ds = ml.get("dataset_summary") or {}
    fails, warns = [], []
    if not str(gt.get("source", "")).endswith("scenario_actions.json"):
        fails.append("ground truth is not taken from the scenario/action record")
    elif not gt.get("confirmed_by"):
        warns.append(f"scenario record not yet confirmed by the team ({gt.get('status')})")
    avail = (ml.get("evaluations", {}).get(ds.get("primary_feature_set"), {}) or {}).get("feature_availability", {})
    if not avail or any(v != "request-time" for v in avail.values()):
        fails.append("primary feature set is not restricted to request-time features")
    for name, m in sup.items():
        if "training_time_avg_ms" not in m or "prediction_latency_per_sample_ms" not in m:
            fails.append(f"{name}: fit and predict timing not reported separately")
    iso = ml.get("unsupervised_models") or {}
    if iso and iso.get("labels_used_for_fitting") is not False:
        fails.append("Isolation Forest does not declare label-free fitting")
    rf = sup.get("Random Forest Classifier", {})
    rec, fpr = rf.get("recall"), rf.get("false_positive_rate")
    if rec is None or fpr is None or rec < 95.0 or fpr > 2.0:
        warns.append(f"Random Forest recall {rec}% / FPR {fpr}% vs targets >=95% / <=2%")
    ablation = ml.get("evaluations", {}).get("request_time_without_function_code", {}).get("stratified_kfold", {})
    rf_ab = ablation.get("Random Forest Classifier", {})
    if rf_ab and (rf_ab.get("recall") or 0) < 95.0:
        warns.append(f"without function_code, Random Forest recall falls to {rf_ab.get('recall')}%: detection "
                     f"rests on the function code (rule baseline gives the same result)")
    if (ds.get("total_records") or 0) < 30:
        warns.append(f"only {ds.get('total_records')} labelled events: metrics are not statistically stable")
    if fails:
        checks.add("PROPERTY", "P3 ML evaluation", "FAIL", "; ".join(fails + warns))
    elif warns:
        checks.add("PROPERTY", "P3 ML evaluation", "WARN", "method checks passed; " + "; ".join(warns))
    else:
        checks.add("PROPERTY", "P3 ML evaluation", "PASS", f"method checks passed; RF recall {rec}%, FPR {fpr}%")


def inventory_policy(root, checks):
    present = [n for n in ("SECURITY.md", "requirements.txt", "THIRD_PARTY_LICENSES.md", "LICENSE")
               if (p := locate_artifact_file(n, root)) and os.path.getsize(p) > 10]
    missing = sorted({"SECURITY.md", "requirements.txt", "THIRD_PARTY_LICENSES.md", "LICENSE"} - set(present))
    checks.add("INVENTORY", "Policy & licence files", "INVENTORY" if not missing else "WARN",
               f"present: {', '.join(present)}" + (f"; missing/empty: {', '.join(missing)}" if missing else "")
               + " (existence only - not a security test)")


# =============================================================================
def run_audit(root=None, model_path=None, write_reports=True):
    root = get_repo_root(root)
    log_info(f"{BOLD}STRIDE inventory and security property audit{RESET} (repository: {root})")
    checks = Checks()
    json_path = locate_threat_model_json(model_path, root)
    inventory = None
    if not json_path:
        checks.add("INVENTORY", "Threat model file", "FAIL", "'Team 4 Threat Model.json' not found")
    else:
        try:
            inventory = inventory_threat_model(json_path, checks)
        except ValueError as exc:
            checks.add("INVENTORY", "Threat model file", "FAIL", f"unparseable: {exc}")
    inventory_policy(root, checks)
    property_parser_controls(root, checks)
    property_normalized_vs_raw(root, checks)
    property_ml_method(root, checks)

    n_fail, n_warn, n_pass = checks.count("FAIL"), checks.count("WARN"), checks.count("PASS")
    if n_fail:
        status, text = "FAILED", f"FAILED - {n_fail} check(s) failed, {n_warn} warning(s)."
    elif n_warn:
        status, text = "PARTIAL", f"PARTIAL - {n_pass} property check(s) passed, {n_warn} warning(s)."
    else:
        status, text = "PROPERTIES_PASSED", f"{n_pass} property check(s) passed, no warnings."
    if inventory:
        text += (f" Threat status is as recorded in the model ({inventory['status_counts']}); "
                 f"this audit does not close threats.")

    if write_reports:
        out_dir = os.path.join(root, "data")
        os.makedirs(out_dir, exist_ok=True)
        report = {"audit_timestamp": datetime.now(timezone.utc).isoformat(),
                  "threat_model_file": os.path.relpath(json_path, root) if json_path else None,
                  "inventory": inventory, "checks": checks.items, "audit_status": status,
                  "audit_conclusion": text}
        with open(os.path.join(out_dir, "stride_validation_report.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        md = [f"# STRIDE Inventory & Security Property Audit", "",
              f"**Timestamp:** {report['audit_timestamp']}  ",
              f"**Threat model:** `{report['threat_model_file']}`  ",
              f"**Conclusion:** {text}", "",
              "> INVENTORY rows confirm that artifacts exist and are well formed. PROPERTY rows record a "
              "security property that was actually exercised. Only PROPERTY rows are evidence of a control "
              "working, and none of them closes a threat-model entry by itself.", ""]
        if inventory:
            md += ["## Threat model inventory", "",
                   f"- {inventory['threats']} threats on {inventory['components_with_threats']} components, "
                   f"{len(inventory['trust_boundaries'])} trust boundaries",
                   f"- STRIDE: {inventory['stride_counts']}",
                   f"- Severity: {inventory['severity_counts']}",
                   f"- Status recorded in the model: {inventory['status_counts']}", ""]
        md += ["## Checks", "", "| Kind | Check | Result | Details |", "| :--- | :--- | :---: | :--- |"]
        md += [f"| {c['kind']} | {c['check']} | {c['status']} | {c['details'].replace('|', '/')} |"
               for c in checks.items]
        with open(os.path.join(out_dir, "stride_validation_report.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(md) + "\n")

    colour = RED if n_fail else (YELLOW if n_warn else GREEN)
    print("\n" + "=" * 70 + f"\n{colour}{BOLD}AUDIT {status}{RESET}: {text}\n" + "=" * 70)
    return {"status": status, "checks": checks.items, "inventory": inventory}


def validate_stride_threat_model(model_path=None, root=None, write_reports=True):
    """Backwards-compatible entry point. Returns 1 if any check failed, else 0."""
    return 1 if run_audit(root, model_path, write_reports)["status"] == "FAILED" else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[5])
    ap.add_argument("--root", default=None, help="repository root to audit (default: this repository)")
    ap.add_argument("--model", default=None, help="threat model JSON path")
    ap.add_argument("--no-write", action="store_true", help="do not write data/stride_validation_report.*")
    a = ap.parse_args()
    sys.exit(validate_stride_threat_model(a.model, a.root, not a.no_write))
