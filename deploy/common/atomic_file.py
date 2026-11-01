#!/usr/bin/env python3
"""
CYB691 Capstone - Team 4
Create-only, atomic file writes shared by the edge drop-zone transport and the
analytics object store.

Data goes to a temporary file in the target directory, is fsync'd, then
hard-linked into place. An object therefore appears complete or not at all,
and an existing file (evidence) is never overwritten.
"""

import os
import tempfile

TMP_PREFIX = ".tmp-"


def create_only_write(path: str, data: bytes) -> bool:
    """Atomically creates `path` with `data`. Returns False if it already exists."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    if os.path.exists(path):
        return False
    fd, tmp = tempfile.mkstemp(prefix=TMP_PREFIX, dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)            # atomic; fails if the target exists
        except FileExistsError:
            return False
        except OSError:                   # file systems without hard links (e.g. some bind mounts)
            if os.path.exists(path):
                return False
            os.replace(tmp, path)
            tmp = None
        return True
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
