"""Replay of handoff archives in both delivered layouts, and firewall-line parsing details."""

import hashlib
import io
import tarfile

import pytest

from common.normalizers import has_stable_timestamp, normalise_firewall_line
from edge.replay_handoff import HandoffError, unpack

EVE = b'{"timestamp":"2026-11-02T00:30:00.200000-0500","event_type":"modbus","src_ip":"192.168.1.50"}\n'
FW = (b"[2026-11-02T00:30:15.200Z] DROP TCP PACKET: IN=eth0 OUT= SRC=192.168.1.200 DST=192.168.1.100 "
      b"PROTO=TCP SPT=49153 DPT=502 SYN URGP=0 [RULE_ID: REJECT_UNAUTH_SCADA_FC16]\n")
CSV = b"timestamp,scenario_id,network_mode,source_ip,function_code,authorized_yes_no\n"


def _archive(tmp_path, members):
    path = tmp_path / "handoff.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return str(path), hashlib.sha256(path.read_bytes()).hexdigest()


def test_infrastructure_logs_layout_is_unpacked(tmp_path):
    arc, sha = _archive(tmp_path, {"infrastructure/logs/eve.json": EVE,
                                   "infrastructure/logs/iptables_drops.log": FW,
                                   "infrastructure/logs/scenario_file.csv": CSV})
    out = tmp_path / "replay"
    info = unpack(arc, sha, str(out))
    assert set(info["files"]) == {"eve.json", "iptables_drops.log", "scenario_file.csv"}
    assert (out / "eve.json").read_bytes() == EVE


def test_two_eve_files_in_one_archive_are_refused(tmp_path):
    arc, sha = _archive(tmp_path, {"var/log/suricata/eve.json": EVE, "infrastructure/logs/eve.json": EVE})
    with pytest.raises(HandoffError, match="more than one eve.json"):
        unpack(arc, sha, str(tmp_path / "replay"))


def test_wrong_hash_still_refused_for_new_layout(tmp_path):
    arc, _ = _archive(tmp_path, {"infrastructure/logs/eve.json": EVE})
    with pytest.raises(HandoffError, match="SHA-256 mismatch"):
        unpack(arc, "0" * 64, str(tmp_path / "replay"))


def test_bracketed_firewall_timestamp_and_rule_id_are_kept():
    env = normalise_firewall_line(FW.decode(), "e", {})
    assert env["timestamp_utc"].startswith("2026-11-02T00:30:15.2")
    assert env["raw"]["parsed"]["rule"] == "REJECT_UNAUTH_SCADA_FC16"
    assert env["raw"]["parsed"]["action_tag"] == "drop"
    assert env["raw"]["parsed"]["tcp_flags"] == ["SYN"]
    assert has_stable_timestamp(FW.decode())


def test_untagged_line_is_ingested_but_marked_and_accept_lines_are_skipped():
    untagged = ("﻿[2026-11-02T00:30:10.150Z] IN=eth0 OUT= SRC=192.168.1.200 DST=192.168.1.100 "
                "PROTO=TCP SPT=49152 DPT=502 ACK SYN URGP=0")
    env = normalise_firewall_line(untagged, "e", {})
    assert env["raw"]["parsed"]["action_tag"] == "untagged"
    accepted = "2026-11-02T00:30:10Z CYB691-ACCEPT IN=eth0 SRC=10.0.1.10 DST=10.0.3.10 PROTO=TCP DPT=502"
    assert normalise_firewall_line(accepted, "e", {}) is None


def test_bsd_syslog_line_gets_a_deterministic_utc_time():
    """No year or zone in the line: read as UTC (lab VMs run on UTC), so re-ingesting the same
    file yields the same event instead of a duplicate stamped with the processing time."""
    line = "Nov  3 09:00:01 vm-fwsensor kernel: CYB691-DROP SRC=10.0.1.20 DST=10.0.3.10 PROTO=TCP DPT=502"
    a, b = normalise_firewall_line(line, "e", {}), normalise_firewall_line(line, "e", {})
    assert a["idempotency_key"] == b["idempotency_key"]
    assert a["timestamp_utc"].endswith("-11-03T09:00:01+00:00")
    assert a["raw"]["parsed"]["timestamp_basis"] == "bsd_syslog_assumed_utc"
    assert has_stable_timestamp(line)


def test_files_at_archive_root_are_unpacked(tmp_path):
    """tar czf x.tar.gz -C dir eve.json iptables_drops.log scenario_file.csv versions.txt
    stores them at the root; all layouts are matched by basename now."""
    arc, sha = _archive(tmp_path, {"eve.json": EVE, "iptables_drops.log": FW,
                                   "scenario_file.csv": CSV, "versions.txt": b"Suricata: 7.0.3\n",
                                   "iptables-layered.rules": b"*filter\n"})   # rules file ignored
    out = tmp_path / "replay"
    info = unpack(arc, sha, str(out))
    assert set(info["files"]) == {"eve.json", "iptables_drops.log", "scenario_file.csv", "versions.txt"}
    assert (out / "eve.json").read_bytes() == EVE
    assert not (out / "iptables-layered.rules").exists()
