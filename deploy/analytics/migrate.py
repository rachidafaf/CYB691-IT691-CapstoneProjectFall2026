#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Module: Repeatable, checksum-verified schema migrations (migrate.py)

  python -m analytics.migrate --dir analytics/migrations [--dry-run] [--verify-only]

* Applies V###__name.sql files in version order, each in its own transaction.
* Records (version, filename, sha256, applied_at, applied_by) in schema_migrations.
* Refuses to continue if an already-applied file's checksum changed (tamper /
  drift detection) – fix forward with a new V### file instead of editing.
* Uses a PostgreSQL advisory lock so two db-migrate runs can never overlap.
* Runs as the dedicated migration identity (schema owner); never as an app role.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import sys
from typing import List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

logger = logging.getLogger("migrate")
LOCK_ID = 691_004_001
_NAME = re.compile(r"^V(\d{3})__[a-z0-9_]+\.sql$")


def discover(directory: str) -> List[Tuple[int, str, str, str]]:
    out = []
    for fn in sorted(os.listdir(directory)):
        m = _NAME.match(fn)
        if not m:
            continue
        with open(os.path.join(directory, fn), "rb") as f:
            body = f.read()
        out.append((int(m.group(1)), fn, hashlib.sha256(body).hexdigest(), body.decode("utf-8")))
    versions = [v for v, *_ in out]
    if len(versions) != len(set(versions)):
        raise SystemExit("duplicate migration versions")
    return out


def run(directory: str, dry_run: bool = False, verify_only: bool = False) -> int:
    from analytics.pg_connection import connect
    files = discover(directory)
    conn = connect()
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
            cur.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                               version INTEGER PRIMARY KEY, filename TEXT NOT NULL,
                               sha256 CHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                               applied_by TEXT NOT NULL DEFAULT current_user)""")
            conn.commit()
            cur.execute("SELECT version, filename, sha256 FROM schema_migrations ORDER BY version")
            applied = {v: (fn, sha) for v, fn, sha in cur.fetchall()}
        for v, fn, sha, _ in files:
            if v in applied and applied[v][1] != sha:
                raise SystemExit(f"checksum drift: {fn} was modified after being applied")
        pending = [f for f in files if f[0] not in applied]
        logger.info("applied=%d pending=%d", len(applied), len(pending))
        if verify_only or dry_run:
            for v, fn, *_ in pending:
                print(f"PENDING {fn}")
            return len(pending)
        for v, fn, sha, body in pending:
            logger.info("applying %s", fn)
            with conn.cursor() as cur:
                cur.execute(body)
                cur.execute("INSERT INTO schema_migrations (version, filename, sha256) VALUES (%s,%s,%s)",
                            (v, fn, sha))
            conn.commit()
        return 0
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
            conn.commit()
        finally:
            conn.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(__file__), "migrations"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify-only", action="store_true", help="exit non-zero if migrations are pending")
    a = ap.parse_args()
    rc = run(a.dir, a.dry_run, a.verify_only)
    sys.exit(1 if (a.verify_only and rc) else 0)


if __name__ == "__main__":
    main()
