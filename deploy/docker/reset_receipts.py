#!/usr/bin/env python3
"""
Clears handoff-watcher processing receipts after the database has been purged, so every
infrastructure/logs/ot_telemetry_handoff_*.tar.gz is ingested again into the new database.

A receipt that started as a hash delivered with the handoff (supplied_hash=verified) is put
back to that single hash line, so the capture-host hash is still enforced; a receipt the
watcher created on its own is deleted. The .tar.gz files are never touched.

  python deploy/docker/reset_receipts.py [--dir infrastructure/logs]
"""

import argparse
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def reset(folder):
    changed = []
    for r in sorted(glob.glob(os.path.join(folder, "ot_telemetry_handoff_*.tar.gz.sha256"))):
        text = open(r, encoding="utf-8-sig", errors="replace").read()
        if "processed_at_utc" not in text:
            continue                                   # a delivered hash, not yet processed
        if "supplied_hash=verified" in text:
            with open(r, "w", encoding="utf-8", newline="\n") as f:
                f.write(text.splitlines()[0] + "\n")
        else:
            os.remove(r)
        changed.append(os.path.basename(r)[: -len(".sha256")])
    return changed


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dir", default=os.environ.get("CYB691_HANDOFF_DIR") or os.path.join(HERE, "..", "..", "infrastructure", "logs"))
    a = ap.parse_args()
    folder = os.path.abspath(a.dir)
    if not os.path.isdir(folder):        # CYB691_HANDOFF_DIR in .env is relative to deploy/docker
        folder = os.path.normpath(os.path.join(HERE, a.dir))
    done = reset(folder)
    print(f"handoffs that will be ingested again on the next up: {', '.join(done) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
