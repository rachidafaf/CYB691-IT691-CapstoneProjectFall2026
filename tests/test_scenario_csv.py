"""Generator scenario CSV -> ground-truth labels (src/scenario.py)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from scenario import explain_unmatched, join_labels, load_scenario  # noqa: E402

HEADER = "timestamp,scenario_id,network_mode,source_ip,function_code,authorized_yes_no\n"


def _csv(tmp_path, body, header=HEADER):
    p = tmp_path / "scenario_file.csv"
    p.write_text("﻿" + header + body, encoding="utf-8")
    return str(p)


def _ev(ts, src, fc, eid):
    return {"event_id": eid, "timestamp_iso": ts, "network": {"source_ip": src}, "modbus": {"function_code": fc}}


def test_csv_rows_become_labelled_actions(tmp_path):
    sc = load_scenario(_csv(tmp_path, "2026-11-02T00:30:00Z,C1,normal,10.0.1.10,03,1\n"
                                      "2026-11-02T00:30:10Z,C3,attack,10.0.1.20,06,0\n"))
    assert [(a["case_id"], a["function_code"], a["label"]) for a in sc["actions"]] == [("C1", 3, 0), ("C3", 6, 1)]


def test_runbook_column_names_are_accepted(tmp_path):
    sc = load_scenario(_csv(tmp_path, "2026-11-05T14:00:00.123Z,R01,baseline,C3,10.0.1.20,10.0.3.10,5,0\n",
                            header="timestamp_utc,run_id,topology,case_id,source_ip,dest_ip,function_code,authorized\n"))
    a = sc["actions"][0]
    assert (a["run"], a["network_mode"], a["target"], a["label"]) == ("R01", "baseline", "10.0.3.10", 1)


def test_timestamp_without_zone_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="no timezone"):
        load_scenario(_csv(tmp_path, "2026-11-02 00:30:00,C1,normal,10.0.1.10,3,1\n"))


def test_send_time_matches_sensor_event_within_tolerance(tmp_path):
    sc = load_scenario(_csv(tmp_path, "2026-11-02T00:30:10Z,C3,attack,10.0.1.20,06,0\n"))
    events = [_ev("2026-11-02T00:30:10.150+00:00", "10.0.1.20", 6, "E1"),
              _ev("2026-11-02T00:30:10.150+00:00", "10.0.1.20", 3, "E2")]    # same time, other FC
    labels, _, matched, _ = join_labels(events, sc)
    assert labels == [1, -1] and len(matched) == 1


def test_offset_mismatch_is_not_papered_over(tmp_path):
    """A 5-hour gap between the CSV clock and the sensor clock is reported, not matched."""
    sc = load_scenario(_csv(tmp_path, "2026-11-02T00:30:10Z,C3,attack,192.168.1.200,06,0\n"))
    events = [_ev("2026-11-02T00:30:10.1501-05:00", "192.168.1.200", 6, "E1")]
    labels, _, matched, _ = join_labels(events, sc)
    assert labels == [-1] and matched == []
    (row,) = explain_unmatched(events, sc)
    assert row["offset_s"] == pytest.approx(18000.15, abs=0.01)


def test_one_event_matches_at_most_one_action(tmp_path):
    sc = load_scenario(_csv(tmp_path, "2026-11-02T00:30:10Z,C3,attack,10.0.1.20,6,0\n"
                                      "2026-11-02T00:30:11Z,C3,attack,10.0.1.20,6,0\n"))
    labels, _, matched, _ = join_labels([_ev("2026-11-02T00:30:10.5+00:00", "10.0.1.20", 6, "E1")], sc)
    assert labels == [1] and len(matched) == 1
