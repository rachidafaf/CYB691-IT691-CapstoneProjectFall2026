#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: Layer 3 Machine Learning Anomaly Classifier (ml_detector.py)
Author: Rachid Afaf (Detection Analytics Lead)
===============================================================================
Evaluation design (responds to Report 1 feedback items 8-10):

  1. Ground truth (y) comes from the scenario/action record
     data/scenario_actions.json (see src/scenario.py): which actions the
     generator performed and whether the actor was authorized. It is joined to
     events by timestamp and is NEVER computed from a model feature, a parser
     flag (is_state_altering) or a derived score (threat_score).
  2. Features (X) are restricted to what a sensor can observe when the request
     is on the wire ("request-time"). has_protocol_exception is only known
     after the PLC answers, so it is excluded from the primary feature set and
     reported separately. An ablation without function_code shows how much of
     the result is the function code alone.
  3. Independent observations are split FIRST; random oversampling is applied
     to the training fold only. Two schemes are reported: stratified k-fold
     over transactions, and leave-one-generator-run-out (no run contributes to
     both training and testing).
  4. Timing: training time = model.fit per fold; prediction latency =
     model.predict on the unseen test fold divided by its size; total
     execution time = whole script. They are stored under separate names.
  5. Isolation Forest is a BATCH SCREENING tool: it is fitted and scored on the
     same capture without labels, with a fixed contamination setting that does
     not depend on the labels. Labels are used only afterwards to score it. It
     is not evaluated as a detector of new, unseen observations.
===============================================================================
"""

import os
import sys
import json
import time
import platform
import argparse
import numpy as np
from datetime import datetime, timezone

from sklearn.model_selection import StratifiedKFold, LeaveOneGroupOut
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

try:
    from src.database import (load_telemetry_records, save_ml_benchmarks_to_db, database_available,
                              describe_target, DEFAULT_DB_PATH)
    from src.scenario import load_scenario, join_labels, provenance_summary, DEFAULT_SCENARIO_PATH, UNLABELED
except ImportError:
    from database import (load_telemetry_records, save_ml_benchmarks_to_db, database_available,
                          describe_target, DEFAULT_DB_PATH)
    from scenario import load_scenario, join_labels, provenance_summary, DEFAULT_SCENARIO_PATH, UNLABELED

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(REPO_ROOT, "data")

RECALL_TARGET = 0.95
FPR_TARGET = 0.02

# Every candidate feature, with the moment it becomes observable on the wire.
FEATURE_CATALOG = {
    "inter_arrival_ms":       {"available": "request-time",  "source": "time since the previous Modbus request"},
    "function_code":          {"available": "request-time",  "source": "MBAP/PDU function code of the request"},
    "destination_port":       {"available": "request-time",  "source": "TCP destination port"},
    "unit_id":                {"available": "request-time",  "source": "MBAP unit identifier"},
    "pdu_length_bytes":       {"available": "request-time",  "source": "request PDU length in bytes (= MBAP length "
                                                                   "field - 1), per the Modbus specification"},
    "payload_length":         {"available": "request-time",  "source": "length of the parser's payload TEXT "
                                                                   "('read:...'/'write:...'); Report 1 only - it "
                                                                   "encodes the operation name, a spurious shortcut"},
    "has_protocol_exception": {"available": "response-time", "source": "exception flag in the PLC's response"},
}
FEATURE_SETS = {
    # Primary: what an inline sensor can use to decide before the PLC acts on the request.
    "request_time": ["inter_arrival_ms", "function_code", "destination_port", "unit_id", "pdu_length_bytes"],
    # Ablation: how much detection is left without the function code.
    "request_time_without_function_code": ["inter_arrival_ms", "destination_port", "unit_id", "pdu_length_bytes"],
    # Report 1 feature set, kept for comparison only (includes a response-time feature).
    "report1_all_six": ["inter_arrival_ms", "function_code", "has_protocol_exception",
                        "destination_port", "unit_id", "payload_length"],
}
PRIMARY_FEATURE_SET = "request_time"


def request_pdu_length(mb):
    """
    Request PDU length in bytes as it appears on the wire (MBAP length field minus the unit id),
    from the Modbus Application Protocol Specification V1.1b3: FC1-4 and FC5/6 = 5 bytes,
    FC15 = 6 + ceil(quantity/8), FC16 = 6 + 2 x quantity. Returns 0 when it cannot be derived.
    """
    fc = int(mb.get("function_code", 0) or 0)
    parsed = mb.get("payload_parsed", {}) or {}
    if fc in (1, 2, 3, 4, 5, 6):
        return 5
    if fc in (15, 16):
        qty = parsed.get("quantity")
        if qty is None:
            value = parsed.get("value")
            nbytes = len(value) if isinstance(value, str) else 0
            qty = nbytes // 2 if fc == 16 else nbytes * 8
        qty = int(qty or 0)
        return 6 + (2 * qty if fc == 16 else -(-qty // 8))
    return 0


def feature_value(record, name):
    net = record.get("network", {}) or {}
    mb = record.get("modbus", {}) or {}
    sec = record.get("security", {}) or {}
    if name == "inter_arrival_ms":
        return float(record.get("inter_arrival_ms", 0.0) or 0.0)
    if name == "function_code":
        return float(mb.get("function_code", 0) or 0)
    if name == "destination_port":
        return float(net.get("destination_port", 502) or 502)
    if name == "unit_id":
        return float(mb.get("unit_id", 1) or 1)
    if name == "pdu_length_bytes":
        return float(request_pdu_length(mb))
    if name == "payload_length":
        return float(len(str(mb.get("payload_raw", ""))))
    if name == "has_protocol_exception":
        return 1.0 if sec.get("has_protocol_exception", False) else 0.0
    raise KeyError(name)


def extract_features(records, feature_names=None):
    """Builds X from observable fields only. Labels are NOT produced here."""
    feature_names = list(feature_names or FEATURE_SETS[PRIMARY_FEATURE_SET])
    X = np.array([[feature_value(r, n) for n in feature_names] for r in records], dtype=np.float64)
    return X, feature_names


def extract_features_and_ground_truth(records, scenario=None, feature_names=None):
    """
    Returns (X, y, feature_names, groups) for records that have a scenario label.
    y comes from the scenario/action record joined by timestamp (src/scenario.py);
    records without a matching action are dropped and must be reported by the caller.
    """
    if scenario is None:
        scenario = load_scenario()
    if scenario is None:
        raise FileNotFoundError("scenario action record not found (data/scenario_actions.json)")
    labels, groups, _, _ = join_labels(records, scenario)
    keep = [i for i, lab in enumerate(labels) if lab != UNLABELED]
    kept = [records[i] for i in keep]
    X, names = extract_features(kept, feature_names)
    y = np.array([labels[i] for i in keep], dtype=np.int32)
    g = np.array([groups[i] for i in keep])
    return X, y, names, g


def resample_training_fold_only(X_train, y_train, target_samples_per_class=10):
    """Random oversampling of the TRAINING fold only (test rows are never passed in)."""
    classes, counts = np.unique(y_train, return_counts=True)
    if len(classes) < 2:
        return X_train, y_train
    max_count = max(np.max(counts), target_samples_per_class)
    X_list, y_list = [X_train], [y_train]
    rng = np.random.RandomState(42)
    for cls, count in zip(classes, counts):
        if count < max_count:
            idx = np.where(y_train == cls)[0]
            pick = rng.choice(idx, size=max_count - count, replace=True)
            X_list.append(X_train[pick])
            y_list.append(y_train[pick])
    return np.vstack(X_list), np.concatenate(y_list)


def _models():
    return {
        "Random Forest Classifier": RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5),
        "Decision Tree Classifier": DecisionTreeClassifier(random_state=42, max_depth=4),
        "Support Vector Machine (SVM)": SVC(kernel="rbf", random_state=42),
    }


def _splits(X, y, groups, scheme):
    if scheme == "stratified_kfold":
        _, counts = np.unique(y, return_counts=True)
        k = int(min(5, counts.min())) if len(counts) > 1 and counts.min() >= 2 else 2
        return list(StratifiedKFold(n_splits=k, shuffle=True, random_state=42).split(X, y)), k
    if scheme == "leave_one_run_out":
        splits = list(LeaveOneGroupOut().split(X, y, groups))
        return splits, len(splits)
    raise ValueError(scheme)


def evaluate_supervised_models(X, y, feature_names, groups=None, scheme="stratified_kfold"):
    """
    Split first, oversample the training fold only, then time fit and predict separately.
    Metrics are pooled over all test folds (every transaction is tested exactly once), which
    stays defined when a fold has no benign or no attack rows (leave-one-run-out).
    """
    if groups is None:
        groups = np.zeros(len(y))
    splits, n_folds = _splits(X, y, groups, scheme)
    results = {}
    for name, model in _models().items():
        y_true_all, y_pred_all = [], []
        fit_ms, pred_ms_per_sample, fold_rows = [], [], []
        for fold_no, (tr, te) in enumerate(splits, 1):
            X_tr, y_tr = resample_training_fold_only(X[tr], y[tr])
            if len(np.unique(y_tr)) < 2:
                fold_rows.append({"fold": fold_no, "skipped": "training fold has a single class"})
                continue
            t0 = time.perf_counter()
            model.fit(X_tr, y_tr)
            fit_ms.append((time.perf_counter() - t0) * 1000.0)
            t0 = time.perf_counter()
            pred = model.predict(X[te])
            pred_ms_per_sample.append((time.perf_counter() - t0) * 1000.0 / len(te))
            y_true_all.extend(y[te].tolist())
            y_pred_all.extend(pred.tolist())
            fold_rows.append({"fold": fold_no, "test_size": int(len(te)),
                              "test_groups": sorted({str(g) for g in groups[te]}),
                              "test_attacks": int(y[te].sum()), "correct": int((pred == y[te]).sum())})
        if not y_true_all:
            results[name] = {"error": "no evaluable folds"}
            continue
        yt, yp = np.array(y_true_all), np.array(y_pred_all)
        tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else None
        results[name] = {
            "cv_scheme": scheme,
            "cross_validation_folds": int(n_folds),
            "accuracy": round(accuracy_score(yt, yp) * 100, 2),
            "precision": round(precision_score(yt, yp, zero_division=0) * 100, 2),
            "recall": round(rec * 100, 2),
            "false_positive_rate": None if fpr is None else round(fpr * 100, 2),
            "f1_score": round(f1_score(yt, yp, zero_division=0) * 100, 2),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "training_time_avg_ms": round(float(np.mean(fit_ms)), 3),
            "prediction_latency_per_sample_ms": round(float(np.mean(pred_ms_per_sample)), 4),
            # kept for the SQLite table / earlier readers; same value as prediction_latency_per_sample_ms
            "inference_latency_per_sample_ms": round(float(np.mean(pred_ms_per_sample)), 4),
            "meets_recall_target": bool(rec >= RECALL_TARGET),
            "meets_fpr_target": None if fpr is None else bool(fpr <= FPR_TARGET),
            "folds": fold_rows,
        }
        if hasattr(model, "feature_importances_"):
            # Importances from a model fitted on the (oversampled) full labelled set: descriptive only,
            # not used for any reported metric.
            X_full, y_full = resample_training_fold_only(X, y)
            model.fit(X_full, y_full)
            imp = {feature_names[i]: round(float(v), 4) for i, v in enumerate(model.feature_importances_)}
            results[name]["feature_importances"] = dict(sorted(imp.items(), key=lambda kv: kv[1], reverse=True))
    return results


def evaluate_unsupervised_isolation_forest(X, y, contamination="auto"):
    """
    Batch outlier screening of the current capture. Fitted and scored on the same batch,
    without labels; `contamination` is a fixed setting chosen before looking at labels.
    Labels are used only to score the screening result afterwards.
    """
    iso = IsolationForest(contamination=contamination, random_state=42)
    t0 = time.perf_counter()
    iso.fit(X)
    fit_ms = (time.perf_counter() - t0) * 1000.0
    t0 = time.perf_counter()
    raw = iso.predict(X)
    pred_ms = (time.perf_counter() - t0) * 1000.0 / len(X) if len(X) else 0.0
    preds = np.where(raw == -1, 1, 0)
    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else None
    return {
        "model_type": "Unsupervised Isolation Forest",
        "intended_purpose": "Batch outlier screening of the current capture (fit and score on the same batch; "
                            "not evaluated as a detector of new observations)",
        "contamination_setting": contamination,
        "labels_used_for_fitting": False,
        "outliers_flagged": int(preds.sum()),
        "accuracy": round(accuracy_score(y, preds) * 100, 2),
        "precision": round(precision_score(y, preds, zero_division=0) * 100, 2),
        "recall": round(recall_score(y, preds, zero_division=0) * 100, 2),
        "false_positive_rate": None if fpr is None else round(fpr * 100, 2),
        "f1_score": round(f1_score(y, preds, zero_division=0) * 100, 2),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "fit_time_total_ms": round(fit_ms, 3),
        "prediction_latency_per_sample_ms": round(pred_ms, 4),
        "inference_latency_per_sample_ms": round(pred_ms, 4),
    }


def evaluate_rule_baseline(records_fc, y):
    """
    Non-learning baseline (Arp et al. pitfall P6): flag every request whose function code is a
    state-altering write (5, 6, 15, 16) - what a write-signature rule in Suricata does. No training.
    """
    preds = np.array([1 if int(fc) in (5, 6, 15, 16) else 0 for fc in records_fc])
    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else None
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "model_type": "Rule baseline: function code in {5, 6, 15, 16}",
        "accuracy": round(accuracy_score(y, preds) * 100, 2),
        "precision": round(precision_score(y, preds, zero_division=0) * 100, 2),
        "recall": round(rec * 100, 2),
        "false_positive_rate": None if fpr is None else round(fpr * 100, 2),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "note": "Applied to every labelled event; no training data needed.",
    }


def resolve_input_path(custom_path=None):
    if custom_path and os.path.exists(custom_path):
        return custom_path
    for c in (os.path.join(DEFAULT_DATA_DIR, "normalized_telemetry.json"),
              os.path.join("data", "normalized_telemetry.json"), "normalized_telemetry.json"):
        if os.path.exists(c):
            return c
    return os.path.join(DEFAULT_DATA_DIR, "normalized_telemetry.json")


def _fmt(v, suffix="%"):
    return "n/a" if v is None else f"{v}{suffix}"


def main():
    t_total_start = time.perf_counter()
    ap = argparse.ArgumentParser(description="Layer 3 Machine Learning Anomaly Classifier Engine")
    ap.add_argument("-i", "--input", default=None, help="normalized telemetry JSON (used if the DB is unavailable)")
    ap.add_argument("-o", "--output", default=None, help="output evaluation JSON")
    ap.add_argument("--db", default=DEFAULT_DB_PATH,
                    help="SQLite path or postgresql:// URL (default: $CYB691_DATABASE_URL, else data/telemetry.db)")
    ap.add_argument("--scenario", default=DEFAULT_SCENARIO_PATH, help="scenario/action record with ground truth")
    ap.add_argument("--if-contamination", default="auto",
                    help="Isolation Forest contamination ('auto' or a fraction), fixed before looking at labels")
    args = ap.parse_args()

    records, source = None, None
    if database_available(args.db):
        try:
            records = load_telemetry_records(args.db)
            source = args.db
            print(f"[*] Loaded {len(records)} records from {describe_target(args.db)}")
        except Exception as e:
            print(f"[-] Database load failed ({e}); falling back to JSON.")
    if records is None:
        path = resolve_input_path(args.input)
        if not os.path.exists(path):
            print(f"[-] Error: '{path}' not found. Run log_parser.py first.")
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            records = json.load(f)
        source = path
        print(f"[*] Loaded {len(records)} records from JSON: {path}")

    scenario = load_scenario(args.scenario)
    if scenario is None:
        print(f"[-] Error: scenario action record '{args.scenario}' not found; ground truth cannot be assigned.")
        sys.exit(1)
    labels, groups, matched, unmatched = join_labels(records, scenario)
    print(f"[*] Ground truth from scenario record: {len(matched)} events labelled, {len(unmatched)} without a "
          f"matching action (excluded){': ' + ', '.join(map(str, unmatched)) if unmatched else ''}")
    prov = provenance_summary(scenario, args.scenario)
    if prov.get("confirmed_by") is None:
        print(f"[!] Scenario record status: {prov.get('status')} (not yet confirmed by the team)")

    evaluations = {}
    y = g = None
    for set_name, names in FEATURE_SETS.items():
        X, y, _, g = extract_features_and_ground_truth(records, scenario, names)
        evaluations[set_name] = {
            "features": names,
            "feature_availability": {n: FEATURE_CATALOG[n]["available"] for n in names},
            "stratified_kfold": evaluate_supervised_models(X, y, names, g, "stratified_kfold"),
            "leave_one_run_out": evaluate_supervised_models(X, y, names, g, "leave_one_run_out"),
        }
    X_primary, y, names_primary, g = extract_features_and_ground_truth(records, scenario,
                                                                       FEATURE_SETS[PRIMARY_FEATURE_SET])
    contamination = args.if_contamination if args.if_contamination == "auto" else float(args.if_contamination)
    unsupervised = evaluate_unsupervised_isolation_forest(X_primary, y, contamination)
    fc_col = names_primary.index("function_code")
    rule_baseline = evaluate_rule_baseline(X_primary[:, fc_col], y)
    total_ms = round((time.perf_counter() - t_total_start) * 1000.0, 2)

    attack_count, benign_count = int(y.sum()), int(len(y) - y.sum())
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input_source": (describe_target(source) if str(source).lower().startswith("postgres")
                         else os.path.relpath(source, REPO_ROOT).replace(os.sep, "/")) if source else None,
        "workload_and_hardware": {
            "operating_system": platform.platform(),
            "cpu_architecture": platform.machine(),
            "processor": platform.processor(),
            "logical_cpus": os.cpu_count(),
            "python_version": platform.python_version(),
            "total_records_evaluated": int(len(y)),
            "total_execution_time_ms": total_ms,
        },
        "timing_definitions": {
            "training_time_avg_ms": "mean wall time of model.fit on one oversampled training fold",
            "prediction_latency_per_sample_ms": "wall time of model.predict on one unseen test fold divided by "
                                                 "its row count, averaged over folds (batch of 1-5 rows, so it "
                                                 "includes per-call overhead)",
            "fit_time_total_ms": "Isolation Forest fit on the whole batch",
            "total_execution_time_ms": "whole ml_detector.py run including loading, all evaluations and I/O",
        },
        "ground_truth": {**prov, "events_labelled": len(matched), "events_excluded_unlabelled": unmatched},
        "dataset_summary": {
            "total_records": int(len(y)),
            "attack_samples_count": attack_count,
            "benign_samples_count": benign_count,
            "generator_runs": sorted({int(x) for x in g if x is not None}),
            "primary_feature_set": PRIMARY_FEATURE_SET,
            "features_used": names_primary,
            "ground_truth_method": "Scenario/action record (data/scenario_actions.json): 1 = unauthorized "
                                   "state-altering write, 0 = authorized baseline read",
        },
        "supervised_models": evaluations[PRIMARY_FEATURE_SET]["stratified_kfold"],
        "evaluations": evaluations,
        "unsupervised_models": unsupervised,
        "rule_baseline": rule_baseline,
    }
    out = args.output or os.path.join(DEFAULT_DATA_DIR, "ml_evaluation_results.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Layer 3 ML evaluation saved to: {out}")
    try:
        n = save_ml_benchmarks_to_db(report, db_path=args.db)
        print(f"[+] Saved {n} ML benchmark rows to {describe_target(args.db)}")
    except Exception as e:
        print(f"[-] Warning: could not persist ML benchmarks to {describe_target(args.db)}: {e}")

    print("\n=================== MODEL BENCHMARK SUMMARY ===================")
    print(f"Records: {len(y)} ({attack_count} unauthorized writes, {benign_count} authorized reads); "
          f"labels from {prov.get('source')} [{prov.get('status')}]")
    for set_name, ev in evaluations.items():
        for scheme in ("stratified_kfold", "leave_one_run_out"):
            print(f"\n> Feature set '{set_name}' | {scheme}")
            for model_name, m in ev[scheme].items():
                if "error" in m:
                    print(f"  - {model_name}: {m['error']}")
                    continue
                print(f"  - {model_name:<30} recall {_fmt(m['recall'])}  FPR {_fmt(m['false_positive_rate'])}  "
                      f"acc {_fmt(m['accuracy'])}  fit {m['training_time_avg_ms']} ms  "
                      f"predict {m['prediction_latency_per_sample_ms']} ms/sample")
    rb = rule_baseline
    print(f"\n> {rb['model_type']}: recall {_fmt(rb['recall'])}, FPR {_fmt(rb['false_positive_rate'])}")
    u = unsupervised
    print(f"\n> Isolation Forest ({u['intended_purpose']}): flagged {u['outliers_flagged']}/{len(y)}, "
          f"recall {_fmt(u['recall'])}, FPR {_fmt(u['false_positive_rate'])}, fit {u['fit_time_total_ms']} ms")
    print(f"\nTotal execution time: {total_ms} ms")
    print("===============================================================\n")


if __name__ == "__main__":
    main()
