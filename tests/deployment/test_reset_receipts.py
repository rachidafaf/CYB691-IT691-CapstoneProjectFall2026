"""down -Purge clears processing receipts so every handoff is ingested into the new database."""

import os
import sys

from conftest import DEPLOY

sys.path.insert(0, os.path.join(DEPLOY, "docker"))
from reset_receipts import reset  # noqa: E402


def test_watcher_receipts_are_removed_and_delivered_hashes_restored(tmp_path):
    (tmp_path / "ot_telemetry_handoff_2026-11-01.tar.gz").write_bytes(b"a")
    (tmp_path / "ot_telemetry_handoff_2026-11-01.tar.gz.sha256").write_text(
        "a" * 64 + "  x\n# processed_at_utc=t\n# supplied_hash=none (hash recorded at processing)\n")
    (tmp_path / "ot_telemetry_handoff_2026-11-05.tar.gz.sha256").write_text(
        "b" * 64 + "  y\n# processed_at_utc=t\n# supplied_hash=verified\n")
    (tmp_path / "ot_telemetry_handoff_2026-11-09.tar.gz.sha256").write_text("c" * 64 + "  z\n")   # not processed yet
    assert reset(str(tmp_path)) == ["ot_telemetry_handoff_2026-11-01.tar.gz", "ot_telemetry_handoff_2026-11-05.tar.gz"]
    assert not (tmp_path / "ot_telemetry_handoff_2026-11-01.tar.gz.sha256").exists()
    assert (tmp_path / "ot_telemetry_handoff_2026-11-05.tar.gz.sha256").read_text() == "b" * 64 + "  y\n"
    assert (tmp_path / "ot_telemetry_handoff_2026-11-09.tar.gz.sha256").read_text() == "c" * 64 + "  z\n"
    assert (tmp_path / "ot_telemetry_handoff_2026-11-01.tar.gz").exists()
