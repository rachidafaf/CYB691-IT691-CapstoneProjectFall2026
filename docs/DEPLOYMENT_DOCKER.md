# Docker Deployment — CYB691 OT Telemetry Defense Stack

This stack replays the team's captured testbed telemetry
(`infrastructure/ot_telemetry_handoff_2026-09-26.tar.gz`) through the same path a live
deployment would use: **edge collector → SQLite store-and-forward buffer → one-way drop
zone → verified ingestion into PostgreSQL → reconciliation, incidents and a read-only API.**
Everything runs under Docker Compose on one host. No cloud account is needed.

## 1. Quick start

Requirements: Docker Desktop (or Docker Engine + Compose v2) and Python 3.10+ on the host.

```powershell
# Windows (PowerShell), from the repository root
.\deploy\docker\up.ps1          # generates secrets, builds 3 images, starts the stack, runs the smoke test
.\deploy\docker\down.ps1        # stop (keeps data)      .\deploy\docker\down.ps1 -Purge   # stop and delete all volumes
```

```bash
# Linux / macOS
deploy/docker/up.sh             # deploy/docker/down.sh [--purge]
```

Manual equivalent:

```bash
python deploy/docker/init-secrets.py
docker compose -f deploy/docker/docker-compose.yml up -d --build
python deploy/docker/smoke-test.py
```

Reporting API (localhost only): <http://127.0.0.1:8080/docs> ·
`/api/v1/incidents` · `/api/v1/events/daily?days=90` · `/api/v1/runs` · `/healthz` · `/readyz`

## 2. Architecture

```
 EDGE ZONE  (network_mode: none — no network interface at all)
 ┌──────────────────────────────────────────────────────────────────────┐
 │ handoff-unpack ──► [replay] ──► edge-collector ──► [edge_data] ──► edge-sync │
 │  verifies SHA-256    eve.json     normalise, local     SQLite WAL     gzip+manifest │
 │  of the archive      iptables     alerting, dedup      buffer         create-only   │
 └───────────────────────────────────────────────────────────────┬──────┘
                                                   [landing] volume  (the ONLY crossing)
 ANALYTICS ZONE  (analytics_net: internal, no egress)            ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ telemetry-sync: verify hash → validate → insert → copy to evidence areas   │
 │ log-parser (5 min): re-parse raw evidence, backfill any gap                 │
 │ timeline-generator (5 min): incidents + forensic timeline report            │
 │ partitions (daily) · db-migrate (once) · ml-train / ml-detector (profile ml)│
 │ postgres 16 ◄── one login role per service, password from a Docker secret   │
 │ reporting-api (read-only role) ──► public_net ──► 127.0.0.1:8080 on the host │
 │ postgres ──► db_host_net ──► 127.0.0.1:5433 on the host (PyCharm / psql)     │
 └──────────────────────────────────────────────────────────────────────┘
```

| Service | Image | Network | Writes to | DB login (group role) |
|---|---|---|---|---|
| handoff-unpack | edge | none | `replay` | — |
| edge-collector | edge | none | `edge_data` | — |
| edge-sync | edge | none | `edge_data`, `landing` | — |
| postgres | postgres:16.6 | analytics_net | `pg_data` | `cyb691_admin` (bootstrap only) |
| db-migrate | analytics | analytics_net | schema | `svc_migrate` (schema owner, not superuser) |
| telemetry-sync | analytics | analytics_net | `objects`, `landing` | `svc_ingestion` (`cyb691_ingestion`) |
| log-parser | analytics | analytics_net | `objects` | `svc_ingestion` |
| partitions | analytics | analytics_net | — | `svc_ingestion` |
| timeline-generator | analytics | analytics_net | `objects` | `svc_analytics` (`cyb691_analytics`) |
| reporting-api | analytics | analytics_net + public_net | — | `svc_readonly` (`cyb691_readonly`) |
| ml-train / ml-detector | ml | analytics_net | `objects` | `svc_analytics` |

## 3. Security controls

| Control | How it is enforced | Verified by |
|---|---|---|
| Edge cannot be reached, and cannot reach anything | `network_mode: none` on all edge services | `test_edge_containers_have_no_network`, smoke test |
| One-way, create-only crossing | Only `edge-sync` and `telemetry-sync` mount `landing`; atomic hard-link writes never overwrite; manifest + SHA-256 verified before ingest | `test_landing_volume_is_the_only_edge_to_analytics_path`, `test_drop_zone_never_overwrites_different_content`, `test_hash_mismatch_is_quarantined_not_ingested` |
| No path to PLCs / TCP 502 | No container publishes or targets 502; no Modbus client or raw socket code anywhere in `deploy/` | `test_published_ports_are_loopback_only_and_never_modbus`, `test_no_code_can_send_modbus_or_open_raw_sockets` |
| Database reachable from the host only | Services reach it as `postgres:5432` on the internal `analytics_net`. For host tools it is published on `127.0.0.1:5433` (loopback only), through `db_host_net`, which no other service joins. Logins need SCRAM passwords from Docker secrets. | `test_postgres_host_port_is_loopback_only_and_isolated`, smoke test |
| API not exposed beyond the host | `127.0.0.1:8080` only; read-only DB role, `default_transaction_read_only` | smoke test |
| Container hardening | non-root UID 10001, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, PID limit, log rotation | `test_app_containers_are_hardened` |
| Secrets | Random passwords in git-ignored `deploy/docker/secrets/`, mounted as Docker secrets; each service sees only its own | `test_passwords_come_only_from_docker_secrets`, gitleaks in CI |
| Least-privilege SQL | insert-only telemetry, append-only audit trigger, no DELETE/TRUNCATE grants | `test_sql_roles_least_privilege`, RBAC probe below |
| Evidence integrity | archive SHA-256 pinned; per-object and per-event SHA-256; quarantine on mismatch; reconciliation backfill | `test_evidence_traceability`, `test_raw_evidence_file_path_and_reconciliation` |

**Limits to state honestly in the report.** Docker volumes are not WORM storage: anyone with
Docker access on the host can alter them, so tamper evidence comes from the hashes and the
append-only audit table, not from the storage layer. Running the edge and analytics zones
on one host is a lab simplification; in a plant they would be separate machines, with the
drop zone replaced by a data diode or an outbound-only file transfer.

## 4. Results on the captured handoff

Full Compose stack on Docker Desktop (Windows), 2026-11-01: `smoke-test.py` **21/21 checks passed**.
The same figures were reproduced against PostgreSQL 16 outside Docker:

| Stage | Result |
|---|---|
| Archive verification | SHA-256 `0e8bf4f5…447de6` matched; `eve.json` 33,621,005 bytes, SHA-256 `d8fda885…73750c` |
| Edge collection | 87 envelopes (20 Modbus records → **10 unique** after content-hash de-duplication, 67 Suricata alerts) |
| Local edge alerts | 6 `UNAUTHORISED_MODBUS_WRITE` (one per unique write: FC5 ×1, FC6 ×3, FC16 ×2), all from 10.0.1.4 |
| Ingestion | 83 events written (10 MODBUS_DPI, 67 SURICATA_ALERT, 6 LOCAL_ALERT), 0 failed, landing drained |
| Reconciliation (log-parser) | 87 raw records re-parsed, 0 missing, 1 line unverifiable (`-- No entries --` firewall marker) |
| Timeline | 8 incidents from 73 alert events |

**NUL bytes in the captured payloads.** Several Modbus write records carry
`"data": "\u0000\u0000"` (the actual register bytes). PostgreSQL cannot store U+0000 in
`jsonb` or `text`, so the database copy stores it as the literal six-character text `\u0000`
(`pg_writer.pg_safe`). The raw evidence objects and every SHA-256 / idempotency key are
computed before this step and are unchanged. Before this fix, every batch containing a write
was rolled back and retried, which is why the first smoke test showed 0 events.

`iptables_drops.log` holds only `-- No entries --`, so no firewall-drop events are ingested.
That matches the README finding that the capture contains no firewall-drop evidence.

## 5. Operations

### Browsing the database from PyCharm or psql
The Docker PostgreSQL 16.6 is published on **127.0.0.1:5433**, so it doesn't clash with a local PostgreSQL on 5432 (on Windows, 5433 can fall inside a Hyper-V/WinNAT excluded port range, which gives bind error 10013. List the ranges with `netsh interface ipv4 show excludedportrange protocol=tcp`; if 5433 is listed, reserve it once in an Administrator PowerShell: `net stop winnat`, `netsh int ipv4 add excludedportrange protocol=tcp startport=5433 numberofports=1`, `net start winnat`). Containers are unaffected and keep using `postgres:5432` inside the stack. Settings live in `deploy/docker/.env` (copy of `.env.example`, git-ignored, no passwords).

| PyCharm field | Value |
| :--- | :--- |
| Host / Port | `127.0.0.1` / `5433` |
| Database | `cyb691` |
| User (read-only) | `svc_readonly`. Password: contents of `deploy/docker/secrets/pg_readonly_password` |
| User (full access) | `cyb691_admin`. Password: contents of `deploy/docker/secrets/pg_admin_password` |

```powershell
Get-Content deploy\docker\secrets\pg_readonly_password      # copy into PyCharm's password field
psql -h 127.0.0.1 -p 5433 -U svc_readonly -d cyb691 -c "SELECT event_type, count(*) FROM telemetry_events GROUP BY event_type"
```

Tables are in schema `public` of database `cyb691`. Prefer `svc_readonly` for browsing: it cannot change the evidence tables.


```bash
C="docker compose -f deploy/docker/docker-compose.yml"
$C ps                                   # status and health
$C logs -f telemetry-sync               # structured JSON logs; "alert": true lines are detections
$C exec postgres psql -U cyb691_admin -d cyb691 -c "SELECT event_type, count(*) FROM telemetry_events GROUP BY 1"
$C run --rm db-migrate                  # re-apply migrations (checksum-verified, idempotent)
$C up -d --force-recreate handoff-unpack edge-collector    # replay again (events stay de-duplicated)
```

Configuration (environment or a git-ignored `deploy/docker/.env`):

| Variable | Default | Purpose |
|---|---|---|
| `CYB691_EDGE_ID` | `edge-lab-01` | Edge identifier stamped on every event |
| `CYB691_ALLOWED_WRITER_CIDRS` | *(empty: every write alerts)* | Authorised Modbus writers, e.g. `10.0.2.10/32` |
| `CYB691_HANDOFF_ARCHIVE` / `CYB691_HANDOFF_SHA256` | the 2026-09-26 handoff / its pinned hash | Replay a different capture |
| `CYB691_TIMELINE_HOURS` | `8760` | Incident look-back window |
| `CYB691_API_PORT` | `8080` | Host loopback port of the API |
| `CYB691_PG_HOST_PORT` | `5433` | Host loopback port of the Docker PostgreSQL (5432 is left to a local PostgreSQL) |

**Rotating passwords.** PostgreSQL reads the secrets only when `pg_data` is first created.
To rotate in the lab: `down -Purge`, `init-secrets.py --rotate`, `up`.

**ML (opt-in).** Export a labelled dataset into the `objects` volume under
`normalized-exports/`, then:

```bash
CYB691_MODEL_VERSION=v1 CYB691_TRAINING_OBJECT=training/normalized_telemetry.json \
CYB691_TRAINING_SHA256=<sha256> $C --profile ml run --rm ml-train
CYB691_MODEL_VERSION=v1 $C --profile ml up -d ml-detector
```

## 6. Tests and CI

```bash
pip install -r deploy/requirements/dev.txt
pytest -q tests/deployment tests/test_pipeline.py      # PostgreSQL tests run when CYB691_PG_TEST=1
```

`deploy/ci/docker-ci.yml` (copy it to `.github/workflows/` to enable) runs the tests against
a PostgreSQL 16 service container, gitleaks, `docker compose config`, image builds, a Trivy
scan that fails on HIGH/CRITICAL, and the end-to-end smoke test.
