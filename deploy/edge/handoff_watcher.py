#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Handoff watcher: ingests every new ot_telemetry_handoff_*.tar.gz dropped into the handoff folder.

Runs in the edge zone (no network). The host folder infrastructure/logs is mounted at
/handoffs. Every CYB691_HANDOFF_POLL_SECONDS (default 30) it:

  1. lists /handoffs/ot_telemetry_handoff_*.tar.gz, oldest date first;
  2. skips any file that already has a processing receipt (<name>.tar.gz.sha256 containing
     "processed_at_utc"), so nothing is ingested twice;
  3. waits until the file has stopped changing (same size and mtime on two polls), so a file
     still being copied is never read half-written;
  4. if the delivery came with its own <name>.tar.gz.sha256 (hash recorded on the capture host),
     refuses the file unless its SHA-256 matches;
  5. extracts the allow-listed members (eve.json, iptables_drops.log, scenario_file.csv) with the
     same Tar-Slip guards as replay_handoff.py into /replay/<name>/ (written under a hidden
     temporary name, then renamed, so the collector never sees a partial directory);
  6. writes the receipt <name>.tar.gz.sha256 next to the file: a `sha256sum`-compatible first
     line, then the processing time and the hash of every extracted member.

The .tar.gz itself is never modified, moved or deleted. The edge collector tails every
/replay/ot_telemetry_handoff_*/ directory, so each handoff flows edge -> landing -> PostgreSQL.
"""

import glob
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from edge.replay_handoff import HandoffError, sha256_of, unpack  # noqa: E402

WATCH_DIR = os.environ.get("CYB691_HANDOFF_WATCH_DIR", "/handoffs")
REPLAY_DIR = os.environ.get("CYB691_REPLAY_DIR", "/replay")
POLL_SECONDS = float(os.environ.get("CYB691_HANDOFF_POLL_SECONDS", "30"))
HEARTBEAT = os.environ.get("CYB691_WATCHER_HEARTBEAT", "/tmp/watcher.alive")
NAME = re.compile(r"^(ot_telemetry_handoff_(\d{4}[-_]\d{2}[-_]\d{2})[\w.-]*?)\.tar\.gz$")   # 2026-11-02 or 2026_11_02
HEX64 = re.compile(r"\b([0-9a-fA-F]{64})\b")
RECEIPT_MARK = "processed_at_utc"

logger = logging.getLogger("handoff_watcher")


def receipt_path(archive):
    return archive + ".sha256"


def read_receipt(archive):
    """(processed?, supplied_sha256) from <archive>.sha256, if present."""
    p = receipt_path(archive)
    if not os.path.exists(p):
        return False, None
    text = open(p, encoding="utf-8-sig", errors="replace").read()
    m = HEX64.search(text)
    return RECEIPT_MARK in text, (m.group(1).lower() if m else None)


def pending(watch_dir=WATCH_DIR):
    """Unprocessed handoff files, oldest date (then name) first."""
    out = []
    for p in glob.glob(os.path.join(watch_dir, "ot_telemetry_handoff_*.tar.gz")):
        m = NAME.match(os.path.basename(p))
        if m and os.path.isfile(p) and not read_receipt(p)[0]:
            out.append((m.group(2).replace("_", "-"), os.path.basename(p), p))
    return [p for _, _, p in sorted(out)]


def _write_atomic(path, text):
    tmp = os.path.join(os.path.dirname(path), f".{os.path.basename(path)}.tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def process(archive, replay_dir=REPLAY_DIR):
    """Verifies, extracts and receipts one handoff. Returns the receipt dict."""
    base = os.path.basename(archive)
    name = NAME.match(base).group(1)
    _, supplied = read_receipt(archive)
    actual = sha256_of(archive)
    if supplied and supplied != actual:
        raise HandoffError(f"{base}: SHA-256 is {actual}, but the delivered {base}.sha256 says {supplied}")
    final = os.path.join(replay_dir, name)
    marker = os.path.join(final, ".handoff.json")
    if os.path.exists(marker) and json.load(open(marker)).get("archive_sha256") == actual:
        info = json.load(open(marker))                 # extracted before a restart; only the receipt is missing
    else:
        if os.path.exists(final):
            raise HandoffError(f"{final} already holds a different handoff with the same name; rename the new file")
        partial = os.path.join(replay_dir, f".partial-{name}")
        if os.path.exists(partial):
            for f in os.listdir(partial):
                os.remove(os.path.join(partial, f))
        info = unpack(archive, actual, partial)
        info.update({"archive": base, "extracted_at_utc": datetime.now(timezone.utc).isoformat()})
        with open(os.path.join(partial, ".handoff.json"), "w", encoding="utf-8") as f:
            json.dump(info, f, indent=1, sort_keys=True)
        os.replace(partial, final)
    members = ", ".join(f"{k}={v['sha256']}" for k, v in sorted(info["files"].items()))
    _write_atomic(receipt_path(archive),
                  f"{actual}  {base}\n"
                  f"# {RECEIPT_MARK}={datetime.now(timezone.utc).isoformat()}\n"
                  f"# supplied_hash={'verified' if supplied else 'none (hash recorded at processing)'}\n"
                  f"# extracted_to=/replay/{name}\n"
                  f"# members: {members}\n")
    return {"archive": base, "sha256": actual, "replay_dir": final, "files": list(info["files"])}


class Watcher:
    def __init__(self, watch_dir=WATCH_DIR, replay_dir=REPLAY_DIR):
        self.watch_dir, self.replay_dir = watch_dir, replay_dir
        self._seen = {}            # path -> (size, mtime) from the previous poll
        self._refused = {}         # path -> (size, mtime) already reported, to log once
        self._stop = False

    def poll_once(self):
        done = []
        for p in pending(self.watch_dir):
            st = os.stat(p)
            sig = (st.st_size, st.st_mtime)
            if self._seen.get(p) != sig:   # new or still changing: look again next poll
                self._seen[p] = sig
                continue
            if self._refused.get(p) == sig:
                continue
            try:
                r = process(p, self.replay_dir)
                logger.info(json.dumps({"event": "handoff_ingested", **r}))
                done.append(r)
            except (HandoffError, OSError, ValueError) as exc:
                self._refused[p] = sig
                logger.error(json.dumps({"event": "handoff_refused", "archive": os.path.basename(p), "error": str(exc)}))
        return done

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "_stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "_stop", True))
        logger.info(json.dumps({"event": "watching", "dir": self.watch_dir, "every_s": POLL_SECONDS}))
        while not self._stop:
            self.poll_once()
            open(HEARTBEAT, "w").close()
            for _ in range(int(max(POLL_SECONDS, 1))):
                if self._stop:
                    break
                time.sleep(1)


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}')
    if not os.path.isdir(WATCH_DIR):
        logger.error(json.dumps({"event": "missing_watch_dir", "dir": WATCH_DIR}))
        return 2
    Watcher().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
