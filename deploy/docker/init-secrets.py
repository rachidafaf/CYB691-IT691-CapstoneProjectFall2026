#!/usr/bin/env python3
"""
Generates the PostgreSQL passwords used as Docker secrets by docker-compose.yml.

  python deploy/docker/init-secrets.py            # create any missing secret, keep existing ones
  python deploy/docker/init-secrets.py --rotate   # replace all (then: docker compose down -v, see docs)

Files go to deploy/docker/secrets/ (git-ignored). Each holds one random password and
nothing else; nothing is printed. Existing secrets are never overwritten without --rotate,
because PostgreSQL only reads them when the pg_data volume is first initialised.
"""

import argparse
import os
import secrets
import stat

NAMES = ("pg_admin_password", "pg_migrate_password", "pg_ingestion_password",
         "pg_analytics_password", "pg_readonly_password")
DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rotate", action="store_true")
    rotate = ap.parse_args().rotate
    os.makedirs(DIR, exist_ok=True)
    try:
        os.chmod(DIR, stat.S_IRWXU)                     # 0700: other host users cannot list or read
    except OSError:
        pass
    created = 0
    for name in NAMES:
        path = os.path.join(DIR, name)
        if os.path.exists(path) and not rotate:
            continue
        with open(path, "w", encoding="ascii", newline="") as f:
            f.write(secrets.token_urlsafe(32))
        # 0644 so the non-root container users (UID 10001, postgres UID 999) can read the bind
        # mount on Linux hosts; the 0700 directory keeps other host users out.
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
        created += 1
    print(f"secrets ready in {DIR} ({created} created, {len(NAMES) - created} kept)")


if __name__ == "__main__":
    main()
