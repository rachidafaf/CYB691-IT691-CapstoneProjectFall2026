#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Pipeline runner: refreshes every analysis layer after a new handoff has been ingested.

The handoff-watcher service writes <name>.tar.gz.sha256 (a receipt containing "processed_at_utc")
next to each ot_telemetry_handoff_*.tar.gz it ingests into the Docker stack. For every receipted
handoff this runner has not processed yet (oldest date first), it runs, from the repository root:

  1. python src/log_parser.py -i <handoff>      -> data/normalized_telemetry.json, parser_integrity_report.json
  2. python src/timeline_generator.py           -> data/incident_report.json, incident_timeline.md
  3. python src/ml_detector.py                  -> data/ml_evaluation_results.json
     (Random Forest, Decision Tree, SVM, Isolation Forest; ground truth from the handoff's own
      scenario_file.csv; without one there is no ground truth and the ML step reports that)
  4. python validate_stride_threats.py          -> data/stride_validation_report.{json,md}

Every step runs even if an earlier analysis step fails (the validator is meant to report such
failures), except that nothing after a failed log_parser is run. Each run is kept in
data/runs/<handoff name>/: one log per step, a copy of every output, and run.json (commands,
exit codes, durations, handoff SHA-256). data/ itself always ends up describing the NEWEST
handoff: if an older handoff is processed later, the newest one is re-run afterwards.

  python deploy/pipeline/run_pipeline.py            watch and run (the pipeline-runner service)
  python deploy/pipeline/run_pipeline.py --once     process what is pending, then exit (host use)
  python deploy/pipeline/run_pipeline.py --rerun ot_telemetry_handoff_2026-11-01.tar.gz
"""

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO = os.path.abspath(os.environ.get("CYB691_REPO_ROOT") or os.path.join(os.path.dirname(__file__), "..", ".."))
HANDOFF_DIR = os.environ.get("CYB691_HANDOFF_WATCH_DIR") or os.path.join(REPO, "infrastructure", "logs")
DATA = os.path.join(REPO, "data")
RUNS = os.path.join(DATA, "runs")
STATE = os.environ.get("CYB691_PIPELINE_STATE") or os.path.join(RUNS, ".pipeline_state.json")
POLL_SECONDS = float(os.environ.get("CYB691_PIPELINE_POLL_SECONDS", "30"))
RETRY_SECONDS = float(os.environ.get("CYB691_PIPELINE_RETRY_SECONDS", "600"))
STEP_TIMEOUT = int(os.environ.get("CYB691_PIPELINE_STEP_TIMEOUT", "1800"))
HEARTBEAT = os.environ.get("CYB691_PIPELINE_HEARTBEAT", "/tmp/pipeline.alive")
NAME = re.compile(r"^(ot_telemetry_handoff_(\d{4}[-_]\d{2}[-_]\d{2})[\w.-]*?)\.tar\.gz$")
OUTPUTS = ("normalized_telemetry.json", "parser_integrity_report.json", "incident_report.json",
           "incident_timeline.md", "ml_evaluation_results.json", "stride_validation_report.json",
           "stride_validation_report.md")


def now():
    return datetime.now(timezone.utc).isoformat()


def receipted(handoff_dir=None):
    handoff_dir = handoff_dir or HANDOFF_DIR
    """[(date, name, archive path, receipt fingerprint)] for handoffs the watcher has ingested."""
    out = []
    for p in glob.glob(os.path.join(handoff_dir, "ot_telemetry_handoff_*.tar.gz")):
        m = NAME.match(os.path.basename(p))
        r = p + ".sha256"
        if not m or not os.path.exists(r):
            continue
        text = open(r, "rb").read()
        if b"processed_at_utc" in text:
            out.append((m.group(2).replace("_", "-"), os.path.basename(p), p, hashlib.sha256(text).hexdigest()))
    return sorted(out)


def load_state(path=None):
    path = path or STATE
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state, path=None):
    path = path or STATE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def scenario_for(name, repo=REPO):
    """The handoff's own scenario_file.csv (as extracted by log_parser), if it has one."""
    hits = sorted(glob.glob(os.path.join(repo, "infrastructure", "extracted_handoff", name, "**", "scenario_file.csv"),
                            recursive=True))
    return hits[0] if hits else None


def run_handoff(archive, repo=REPO, python=sys.executable, runner=subprocess.run):
    base = os.path.basename(archive)
    name = NAME.match(base).group(1)
    run_dir = os.path.join(repo, "data", "runs", name)
    os.makedirs(run_dir, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", MPLCONFIGDIR=os.environ.get("MPLCONFIGDIR", "/tmp"))
    t_start = time.time() - 1
    record = {"handoff": base, "handoff_sha256": hashlib.sha256(open(archive, "rb").read()).hexdigest(),
              "started_at_utc": now(), "database": env.get("CYB691_DATABASE_URL") or "data/telemetry.db (SQLite)",
              "steps": []}

    def step(label, args, extra_env=None):
        t0 = time.monotonic()
        try:
            cp = runner([python] + args, cwd=repo, env=dict(env, **(extra_env or {})), capture_output=True,
                        text=True, timeout=STEP_TIMEOUT)
            code, out = cp.returncode, (cp.stdout or "") + (("\n--- stderr ---\n" + cp.stderr) if cp.stderr else "")
        except subprocess.TimeoutExpired as exc:
            code, out = -1, f"timed out after {STEP_TIMEOUT}s\n{exc.stdout or ''}"
        with open(os.path.join(run_dir, f"{len(record['steps']) + 1}-{label}.log"), "w", encoding="utf-8") as f:
            f.write(out)
        record["steps"].append({"step": label, "command": "python " + " ".join(args), "exit_code": code,
                                "seconds": round(time.monotonic() - t0, 2)})
        print(json.dumps({"event": "pipeline_step", "handoff": base, "step": label, "exit_code": code}), flush=True)
        return code

    rel = os.path.relpath(archive, repo)
    if step("log_parser", ["src/log_parser.py", "-i", rel]) == 0:
        scen = scenario_for(name, repo)
        scen_env = {"CYB691_SCENARIO_PATH": scen} if scen else {}
        record["scenario"] = os.path.relpath(scen, repo).replace(os.sep, "/") if scen else "none in this handoff"
        step("timeline_generator", ["src/timeline_generator.py"])
        step("ml_detector", ["src/ml_detector.py"] + (["--scenario", scen] if scen else []), scen_env)
        step("validate_stride_threats", ["validate_stride_threats.py"])
    for f in OUTPUTS:
        src = os.path.join(repo, "data", f)
        if os.path.exists(src) and os.path.getmtime(src) >= t_start:      # written by this run
            shutil.copy2(src, os.path.join(run_dir, f))
    codes = {s["step"]: s["exit_code"] for s in record["steps"]}
    record["finished_at_utc"] = now()
    record["status"] = ("COMPLETED" if all(c == 0 for c in codes.values()) and len(codes) == 4 else
                        "PARSER_FAILED" if codes.get("log_parser") else "COMPLETED_WITH_FAILURES")
    with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1)
    print(json.dumps({"event": "pipeline_run", "handoff": base, "status": record["status"], "steps": codes}), flush=True)
    return record


def _needs_retry(base, repo=REPO):
    """A run whose log_parser failed (e.g. a configuration problem since fixed) is retried, at most
    once every CYB691_PIPELINE_RETRY_SECONDS, instead of being skipped for good."""
    p = os.path.join(repo, "data", "runs", NAME.match(base).group(1), "run.json")
    try:
        failed = json.load(open(p, encoding="utf-8")).get("status") == "PARSER_FAILED"
    except (OSError, ValueError):
        return False
    return failed and os.path.getmtime(p) < time.time() - RETRY_SECONDS


def process_pending(state=None, handoff_dir=None, **kw):
    state = load_state() if state is None else state
    items = receipted(handoff_dir)
    repo = kw.get("repo", REPO)
    todo = [it for it in items if state.get(it[1]) != it[3] or _needs_retry(it[1], repo)]
    results = []
    for _, base, path, fp in todo:
        results.append(run_handoff(path, **kw))
        state[base] = fp
        save_state(state)
    if todo and items and todo[-1][1] != items[-1][1]:
        # an older handoff was processed last: bring data/ back to the newest one
        results.append(run_handoff(items[-1][2], **kw))
    return results


def main():
    ap = argparse.ArgumentParser(description="Refresh all analysis layers after each ingested handoff")
    ap.add_argument("--once", action="store_true", help="process pending handoffs and exit")
    ap.add_argument("--rerun", metavar="FILE", help="run the pipeline again for one handoff file name")
    a = ap.parse_args()
    if a.rerun:
        path = os.path.join(HANDOFF_DIR, os.path.basename(a.rerun))
        if not os.path.exists(path):
            print(f"not found: {path}", file=sys.stderr)
            return 2
        return 0 if run_handoff(path)["status"] == "COMPLETED" else 1
    if a.once:
        process_pending()
        return 0
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    print(json.dumps({"event": "watching", "dir": HANDOFF_DIR, "every_s": POLL_SECONDS}), flush=True)
    while not stop:
        try:
            process_pending()
        except Exception as exc:          # keep the service alive; the next poll retries
            print(json.dumps({"event": "pipeline_error", "error": str(exc)}), flush=True)
        open(HEARTBEAT, "w").close()
        for _ in range(int(max(POLL_SECONDS, 1))):
            if stop:
                break
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
