#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Verified unpacking of a captured OT telemetry handoff archive for replay.

Library used by handoff_watcher.py (the `handoff-watcher` service) to verify and extract
each ot_telemetry_handoff_*.tar.gz dropped into infrastructure/logs; also usable on its own.

Accepted layouts: the 2026-09-26 handoff (var/log/suricata/eve.json, iptables_drops.log)
the 2026-11-01 handoff (infrastructure/logs/{eve.json,iptables_drops.log,
scenario_file.csv}), files under handoff/ (lab runbook packaging), and files at the archive root. The scenario file is copied next to the logs as evidence; the edge
collector does not read it.

Evidence-handling rules (same spirit as src/log_parser.py's Tar-Slip guard):
  * the archive's SHA-256 must equal the pinned value, or nothing is extracted
  * only allow-listed members are extracted, under fixed output names
  * absolute paths, '..' components, links and device files are rejected
  * per-member size limit

  python replay_handoff.py --archive handoff.tar.gz --sha256 <hex> --out /testdata
"""

import argparse
import hashlib
import os
import sys
import tarfile

# archive member -> output file name
# The files we take from a handoff, matched by BASENAME so any packaging layout works:
# at the archive root, or under handoff/, logs/, var/log/suricata/, infrastructure/logs/ ...
# Anything else in the archive (e.g. iptables-*.rules) is ignored.
ALLOWED_BASENAMES = {"eve.json", "iptables_drops.log", "scenario_file.csv", "versions.txt"}
MAX_MEMBER_BYTES = 512 * 1024 * 1024


class HandoffError(Exception):
    pass


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_name(name: str) -> str:
    norm = os.path.normpath(name).replace("\\", "/")
    if norm.startswith("/") or norm.startswith("../") or "/../" in norm or norm == "..":
        raise HandoffError(f"unsafe member path rejected: {name!r}")
    return norm.lstrip("./") if norm.startswith("./") else norm


def unpack(archive: str, expected_sha256: str, out_dir: str) -> dict:
    actual = sha256_of(archive)
    if actual != expected_sha256.lower():
        raise HandoffError(f"archive SHA-256 mismatch: expected {expected_sha256}, got {actual}")
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    with tarfile.open(archive, "r:*") as tar:
        for m in tar.getmembers():
            name = _safe_name(m.name)
            base = os.path.basename(name)
            if base not in ALLOWED_BASENAMES:
                continue
            if not m.isfile():
                raise HandoffError(f"member is not a regular file: {m.name!r}")
            if m.size > MAX_MEMBER_BYTES:
                raise HandoffError(f"member too large: {m.name!r} ({m.size} bytes)")
            if base in written:
                raise HandoffError(f"archive holds more than one {base}: "
                                   f"{written[base]['member']!r} and {m.name!r}")
            target = os.path.join(out_dir, base)
            src = tar.extractfile(m)
            h = hashlib.sha256()
            with open(target + ".partial", "wb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    h.update(chunk)
                    dst.write(chunk)
            os.replace(target + ".partial", target)
            written[base] = {"bytes": m.size, "sha256": h.hexdigest(), "member": m.name}
    if "eve.json" not in written:
        raise HandoffError("archive does not contain eve.json (any layout: root, handoff/, logs/, "
                           "var/log/suricata/, infrastructure/logs/)")
    return {"archive_sha256": actual, "files": written}


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify and unpack an OT telemetry handoff for replay")
    ap.add_argument("--archive", required=True)
    ap.add_argument("--sha256", required=True, help="pinned SHA-256 of the archive")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        info = unpack(a.archive, a.sha256, a.out)
    except HandoffError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(f"handoff verified (sha256 {info['archive_sha256']})")
    for name, meta in info["files"].items():
        print(f"  {meta['member']} -> {name}: {meta['bytes']} bytes, sha256 {meta['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
