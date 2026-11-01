"""Shared fixtures for the Docker deployment test suite (stdlib + PyYAML only;
PostgreSQL/FastAPI integration tests skip automatically when unavailable)."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEPLOY = os.path.join(REPO, "deploy")
sys.path.insert(0, DEPLOY)

from common.telemetry_schema import build_envelope  # noqa: E402
from edge import edge_database as db  # noqa: E402


class Clock:
    """Controllable UTC clock for time-travel tests (24 h outages etc.)."""

    def __init__(self, start=None):
        self.t = start or datetime(2026, 10, 2, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(db, "utcnow", c)
    return c


@pytest.fixture
def edge_db(tmp_path):
    p = str(tmp_path / "edge_queue.db")
    db.init_edge_db(p)
    return p


def make_env(i=0, fc=3, src="10.0.2.10", edge="edge-test-01", ts=None, event_type="MODBUS_DPI", severity=None):
    ts = ts or (datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=i))
    cat = "WRITE" if fc in (5, 6, 15, 16) else "READ"
    return build_envelope(
        edge_id=edge, event_type=event_type, timestamp_utc=ts,
        severity=severity or ("HIGH" if cat == "WRITE" else "INFO"),
        src_ip=src, src_port=40000 + (i % 20000), dest_ip="10.0.3.10", dest_port=502, protocol="TCP",
        modbus={"unit_id": 1, "function_code": fc, "function_name": f"FC{fc}", "category": cat,
                "transaction_id": i, "address": 1, "quantity": 1},
        raw={"seq": i, "fc": fc}, raw_ref={"file": "eve.json", "offset": i})


@pytest.fixture
def lab_files(tmp_path):
    sys.path.insert(0, os.path.join(DEPLOY, "testdata"))
    import make_testdata
    eve, fw = make_testdata.build()
    e, f = tmp_path / "eve.json", tmp_path / "filter.log"
    e.write_text("\n".join(eve) + "\n")
    f.write_text("\n".join(fw) + "\n")
    return str(e), str(f)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [json.loads(x) for x in fh if x.strip()]
