"""handoff_watcher: new ot_telemetry_handoff_*.tar.gz in the folder -> /replay/<name>/ + receipt."""

import hashlib
import io
import os
import tarfile

from edge import handoff_watcher as hw
from edge.edge_collector import sources

EVE = b'{"timestamp":"2026-11-02T00:30:00.200000+0000","event_type":"modbus","src_ip":"10.0.1.20"}\n'
FW = b"[2026-11-02T00:30:15.200Z] DROP IN=eth0 SRC=10.0.1.20 DST=10.0.3.10 PROTO=TCP SPT=1 DPT=502\n"


def _drop(folder, date, members=None):
    p = folder / f"ot_telemetry_handoff_{date}.tar.gz"
    with tarfile.open(p, "w:gz") as tar:
        for name, data in (members or {"infrastructure/logs/eve.json": EVE,
                                       "infrastructure/logs/iptables_drops.log": FW}).items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return p


def _dirs(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "replay").mkdir()
    return tmp_path / "logs", tmp_path / "replay"


def test_new_file_is_extracted_and_receipted_after_it_stops_changing(tmp_path):
    logs, replay = _dirs(tmp_path)
    arc = _drop(logs, "2026-11-01")
    w = hw.Watcher(str(logs), str(replay))
    assert w.poll_once() == []                      # first sighting: wait for a stable size
    (r,) = w.poll_once()
    assert (replay / "ot_telemetry_handoff_2026-11-01" / "eve.json").read_bytes() == EVE
    receipt = (logs / (arc.name + ".sha256")).read_text()
    assert receipt.startswith(hashlib.sha256(arc.read_bytes()).hexdigest() + "  " + arc.name)
    assert "processed_at_utc" in receipt
    assert arc.exists()                             # the data file itself is untouched
    assert w.poll_once() == [] and hw.pending(str(logs)) == []   # never ingested twice


def test_oldest_date_is_processed_first(tmp_path):
    logs, replay = _dirs(tmp_path)
    _drop(logs, "2026-11-01")
    _drop(logs, "2026-09-26")
    assert [os.path.basename(p) for p in hw.pending(str(logs))] == [
        "ot_telemetry_handoff_2026-09-26.tar.gz", "ot_telemetry_handoff_2026-11-01.tar.gz"]


def test_delivered_hash_is_enforced(tmp_path):
    logs, replay = _dirs(tmp_path)
    arc = _drop(logs, "2026-11-01")
    (logs / (arc.name + ".sha256")).write_text("0" * 64 + "  " + arc.name + "\n")   # capture-host hash
    w = hw.Watcher(str(logs), str(replay))
    w.poll_once(); assert w.poll_once() == []
    assert not (replay / "ot_telemetry_handoff_2026-11-01").exists()
    assert "processed_at_utc" not in (logs / (arc.name + ".sha256")).read_text()

    (logs / (arc.name + ".sha256")).write_text(hashlib.sha256(arc.read_bytes()).hexdigest() + "  x\n")
    w2 = hw.Watcher(str(logs), str(replay))
    w2.poll_once(); (r,) = w2.poll_once()
    assert "supplied_hash=verified" in (logs / (arc.name + ".sha256")).read_text()


def test_deleting_the_receipt_allows_reingest_without_duplicating_the_directory(tmp_path):
    logs, replay = _dirs(tmp_path)
    arc = _drop(logs, "2026-11-01")
    w = hw.Watcher(str(logs), str(replay))
    w.poll_once(); w.poll_once()
    os.remove(logs / (arc.name + ".sha256"))
    (r,) = w.poll_once() + w.poll_once()
    assert r["replay_dir"].endswith("ot_telemetry_handoff_2026-11-01")


def test_collector_tails_every_handoff_directory(tmp_path):
    logs, replay = _dirs(tmp_path)
    _drop(logs, "2026-09-26"); _drop(logs, "2026-11-01")
    w = hw.Watcher(str(logs), str(replay))
    w.poll_once(); w.poll_once()
    pairs = sources(str(replay / "ot_telemetry_handoff_*"))
    assert [os.path.basename(os.path.dirname(e)) for e, _ in pairs[1:]] == [
        "ot_telemetry_handoff_2026-09-26", "ot_telemetry_handoff_2026-11-01"]
    assert not any(".partial" in e for e, _ in pairs)


def test_underscore_dates_and_handoff_folder_layout_are_accepted(tmp_path):
    logs, replay = _dirs(tmp_path)
    p = logs / "ot_telemetry_handoff_2026-11-02.tar.gz"
    with tarfile.open(p, "w:gz") as tar:
        for name, data in {"handoff/eve.json": EVE, "handoff/iptables_drops.log": FW,
                           "handoff/versions.txt": b"Suricata: 7.0.3\n"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    _drop(logs, "2026-11-01")
    assert [os.path.basename(x) for x in hw.pending(str(logs))] == [
        "ot_telemetry_handoff_2026-11-01.tar.gz", "ot_telemetry_handoff_2026-11-02.tar.gz"]
    w = hw.Watcher(str(logs), str(replay))
    w.poll_once()
    assert len(w.poll_once()) == 2
    assert (replay / "ot_telemetry_handoff_2026-11-02" / "eve.json").read_bytes() == EVE
    assert (replay / "ot_telemetry_handoff_2026-11-02" / "versions.txt").exists()
