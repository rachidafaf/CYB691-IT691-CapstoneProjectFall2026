#!/usr/bin/env python3
"""Heartbeat file used by Docker HEALTH CHECKs for worker processes that have no
HTTP port.

  python -m common.health --max-age 180   -> exit 0 if heartbeat is fresh
"""
import argparse
import os
import sys
import time

HEARTBEAT = os.environ.get("CYB691_HEARTBEAT_FILE", "/tmp/heartbeat")


def touch(path: str = HEARTBEAT) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(time.time()))


def is_fresh(max_age: float, path: str = HEARTBEAT) -> bool:
    try:
        return time.time() - os.path.getmtime(path) <= max_age
    except OSError:
        return False


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-age", type=float, default=180)
    sys.exit(0 if is_fresh(ap.parse_args().max_age) else 1)
