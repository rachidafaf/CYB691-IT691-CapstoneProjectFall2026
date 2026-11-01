#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Module: File-system object store on a Docker volume (object_store.py)

Layout under CYB691_OBJECT_ROOT (default /objects):
    <area>/<object name>     e.g. landing/telemetry/edge=edge-01/yyyy=2026/.../<batch>.ndjson.gz

Areas: landing, quarantine, audit-manifests, normalized-exports, suricata-eve,
firewall-logs, raw-pcap, csv-telemetry, model-artifacts. (The API parameter is called
`container` because that is the column name in evidence_manifests.)

`landing` is mounted from its own Docker volume, shared with the edge-sync container: it is
the edge's only interface to the analytics tier. Every other area lives on the `objects`
volume, which only analytics containers mount.

Writes are create-only and atomic: data is written to a temporary file and hard-linked into
place, so an object either appears complete or not at all, and an existing object (evidence)
is never overwritten.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, Iterator, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.atomic_file import TMP_PREFIX as _TMP_PREFIX, create_only_write  # noqa: E402

DEFAULT_ROOT = os.environ.get("CYB691_OBJECT_ROOT", "/objects")
MAX_OBJECT_BYTES = int(os.environ.get("CYB691_MAX_OBJECT_BYTES", str(512 * 1024 * 1024)))


class ObjectTooLarge(Exception):
    pass


class FileObjectStore:
    def __init__(self, root: Optional[str] = None):
        self.root = os.path.realpath(root or DEFAULT_ROOT)

    def _path(self, container: str, name: str) -> str:
        p = os.path.realpath(os.path.join(self.root, container, name))
        if not p.startswith(self.root + os.sep):
            raise ValueError(f"path traversal rejected: {container}/{name}")
        return p

    def list(self, container: str, prefix: str = "") -> Iterator[str]:
        base = os.path.join(self.root, container)
        for r, _, files in os.walk(base):
            for f in sorted(files):
                if f.startswith(_TMP_PREFIX):
                    continue
                rel = os.path.relpath(os.path.join(r, f), base).replace(os.sep, "/")
                if rel.startswith(prefix):
                    yield rel

    def read(self, container: str, name: str, max_bytes: int = MAX_OBJECT_BYTES) -> bytes:
        p = self._path(container, name)
        if os.path.getsize(p) > max_bytes:
            raise ObjectTooLarge(f"{container}/{name}")
        with open(p, "rb") as f:
            return f.read()

    def write(self, container: str, name: str, data: bytes, metadata: Optional[Dict[str, str]] = None,
              content_type: str = "application/octet-stream") -> bool:
        return create_only_write(self._path(container, name), data)

    def delete(self, container: str, name: str) -> None:
        try:
            os.remove(self._path(container, name))
        except FileNotFoundError:
            pass

    def exists(self, container: str, name: str) -> bool:
        return os.path.exists(self._path(container, name))
