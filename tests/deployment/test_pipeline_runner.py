"""deploy/pipeline/run_pipeline.py: which handoffs trigger a run, in what order, and what is recorded."""

import os
import subprocess
import sys

from conftest import DEPLOY

sys.path.insert(0, os.path.join(DEPLOY, "pipeline"))
import run_pipeline as rp  # noqa: E402


def _handoff(logs, date, receipt=True):
    p = logs / f"ot_telemetry_handoff_{date}.tar.gz"
    p.write_bytes(date.encode())
    if receipt:
        (logs / (p.name + ".sha256")).write_text(f"{'0' * 64}  {p.name}\n# processed_at_utc=2026-11-03T00:00:00Z\n")
    return p


class FakeRunner:
    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def __call__(self, args, **kw):
        self.calls.append(args[1:])
        code = 1 if os.path.basename(args[1]).replace(".py", "") in self.fail else 0
        return subprocess.CompletedProcess(args, code, stdout="ok", stderr="")


def _setup(tmp_path):
    logs = tmp_path / "infrastructure" / "logs"
    logs.mkdir(parents=True)
    (tmp_path / "data").mkdir()
    return logs


def test_only_receipted_handoffs_run_oldest_first_and_once(tmp_path):
    logs = _setup(tmp_path)
    _handoff(logs, "2026-11-01"); _handoff(logs, "2026-09-26"); _handoff(logs, "2026-12-01", receipt=False)
    state, fake = {}, FakeRunner()
    rp.STATE = str(tmp_path / "data" / "runs" / ".state.json")
    res = rp.process_pending(state, str(logs), repo=str(tmp_path), runner=fake)
    assert [r["handoff"] for r in res] == ["ot_telemetry_handoff_2026-09-26.tar.gz", "ot_telemetry_handoff_2026-11-01.tar.gz"]
    assert [c[0] for c in fake.calls[:4]] == ["src/log_parser.py", "src/timeline_generator.py",
                                              "src/ml_detector.py", "validate_stride_threats.py"]
    assert rp.process_pending(state, str(logs), repo=str(tmp_path), runner=fake) == []
    assert os.path.exists(tmp_path / "data" / "runs" / "ot_telemetry_handoff_2026-11-01" / "run.json")


def test_older_handoff_arriving_later_is_followed_by_newest_rerun(tmp_path):
    logs = _setup(tmp_path)
    _handoff(logs, "2026-11-01")
    state, fake = {}, FakeRunner()
    rp.STATE = str(tmp_path / "state.json")
    rp.process_pending(state, str(logs), repo=str(tmp_path), runner=fake)
    _handoff(logs, "2026-09-26")
    res = rp.process_pending(state, str(logs), repo=str(tmp_path), runner=fake)
    assert [r["handoff"] for r in res] == ["ot_telemetry_handoff_2026-09-26.tar.gz", "ot_telemetry_handoff_2026-11-01.tar.gz"]


def test_failed_parser_stops_the_run_but_failed_ml_does_not(tmp_path):
    logs = _setup(tmp_path)
    p = _handoff(logs, "2026-11-01")
    r = rp.run_handoff(str(p), repo=str(tmp_path), runner=FakeRunner(fail={"log_parser"}))
    assert r["status"] == "PARSER_FAILED" and len(r["steps"]) == 1
    r = rp.run_handoff(str(p), repo=str(tmp_path), runner=FakeRunner(fail={"ml_detector"}))
    assert r["status"] == "COMPLETED_WITH_FAILURES" and [s["exit_code"] for s in r["steps"]] == [0, 0, 1, 0]


def test_parser_failure_is_retried_after_the_retry_interval(tmp_path):
    logs = _setup(tmp_path)
    _handoff(logs, "2026-11-01")
    state = {}
    rp.STATE = str(tmp_path / "state.json")
    rp.process_pending(state, str(logs), repo=str(tmp_path), runner=FakeRunner(fail={"log_parser"}))
    assert rp.process_pending(state, str(logs), repo=str(tmp_path), runner=FakeRunner()) == []   # too soon
    run_json = tmp_path / "data" / "runs" / "ot_telemetry_handoff_2026-11-01" / "run.json"
    old = run_json.stat().st_mtime - rp.RETRY_SECONDS - 1
    os.utime(run_json, (old, old))
    (r,) = rp.process_pending(state, str(logs), repo=str(tmp_path), runner=FakeRunner())
    assert r["status"] == "COMPLETED"
