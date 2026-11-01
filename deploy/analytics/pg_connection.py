#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Module: PostgreSQL connection factory (pg_connection.py)

Authentication: password, read from a Docker secret file (PGPASSWORD_FILE,
e.g. /run/secrets/pg_ingestion_password). PGPASSWORD is accepted for ad-hoc
local runs but is never set by docker-compose.yml. Passwords are never logged.

TLS: PGSSLMODE defaults to `prefer`, which suits the Compose stack where
PostgreSQL is reachable only on the internal `analytics_net` network. Point
PGHOST at an external server and set PGSSLMODE=verify-full + PGSSLROOTCERT
for anything that crosses a host boundary. CYB691_ENVIRONMENT=production
refuses anything weaker than verify-full.

Configuration (environment, non-secret): PGHOST, PGPORT, PGDATABASE, PGUSER,
PGSSLMODE, PGSSLROOTCERT, PGPASSWORD_FILE.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_CONN_AGE_SECONDS = 45 * 60


class CredentialError(RuntimeError):
    """The password secret could not be read."""


def _settings() -> dict:
    env = os.environ.get("CYB691_ENVIRONMENT", "dev")
    sslmode = os.environ.get("PGSSLMODE", "prefer")
    if env == "production" and sslmode != "verify-full":
        raise SystemExit("PGSSLMODE must be verify-full when CYB691_ENVIRONMENT=production")
    host = os.environ.get("PGHOST")
    if not host:
        raise SystemExit("PGHOST is required")
    return {
        "env": env, "host": host,
        "port": int(os.environ.get("PGPORT", "5432")),
        "dbname": os.environ.get("PGDATABASE", "cyb691"),
        "user": os.environ.get("PGUSER", ""),
        "sslmode": sslmode,
        "sslrootcert": os.environ.get("PGSSLROOTCERT", "/etc/ssl/certs/ca-certificates.crt"),
        "app": os.environ.get("CYB691_WORKLOAD", "cyb691"),
    }


def read_password() -> str:
    path = os.environ.get("PGPASSWORD_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError as exc:
            raise CredentialError(f"cannot read PGPASSWORD_FILE: {exc.__class__.__name__}") from exc
    return os.environ.get("PGPASSWORD", "")


def connect():
    """Opens one connection. Never logs the password."""
    import psycopg2
    s = _settings()
    if not s["user"]:
        raise SystemExit("PGUSER is required")
    kwargs = dict(host=s["host"], port=s["port"], dbname=s["dbname"], user=s["user"],
                  password=read_password(), sslmode=s["sslmode"], application_name=s["app"],
                  connect_timeout=10, options="-c statement_timeout=60000")
    if s["sslmode"] in ("verify-ca", "verify-full"):
        kwargs["sslrootcert"] = s["sslrootcert"]
    return psycopg2.connect(**kwargs)


class ConnectionPool:
    """Tiny thread-safe pool that recycles long-lived connections."""

    def __init__(self, max_size: int = 5, max_age: int = MAX_CONN_AGE_SECONDS):
        self.max_size = max_size
        self.max_age = max_age
        self._idle: List[Tuple[Any, float]] = []
        self._lock = threading.Lock()

    @contextmanager
    def connection(self) -> Iterator[Any]:
        conn: Optional[Any] = None
        with self._lock:
            while self._idle:
                c, born = self._idle.pop()
                if time.time() - born < self.max_age and not c.closed:
                    conn, born_at = c, born
                    break
                c.close()
        if conn is None:
            conn, born_at = connect(), time.time()
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            conn.close()
            raise
        with self._lock:
            if len(self._idle) < self.max_size and not conn.closed:
                self._idle.append((conn, born_at))
            else:
                conn.close()

    def close(self) -> None:
        with self._lock:
            for c, _ in self._idle:
                c.close()
            self._idle.clear()
