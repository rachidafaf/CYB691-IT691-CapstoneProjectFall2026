#!/usr/bin/env python3
"""
End-to-end smoke test for the running Compose stack (standard library only).

  python deploy/docker/smoke-test.py [--timeout 600]

Checks container state, waits until the captured handoff has flowed
edge -> landing -> PostgreSQL, then checks incidents, the reporting API and
the isolation properties (edge containers have no network, nothing publishes 502).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = ["docker", "compose", "-f", os.path.join(HERE, "docker-compose.yml")]
API = f"http://127.0.0.1:{os.environ.get('CYB691_API_PORT', '8080')}"
results = []


def sh(args, check=False):
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(p.stderr.strip())
    return p.stdout.strip()


def record(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")


def psql(sql):
    return sh(COMPOSE + ["exec", "-T", "postgres", "psql", "-U", "cyb691_admin", "-d", "cyb691",
                         "-tA", "-c", sql])


def api(path):
    with urllib.request.urlopen(API + path, timeout=10) as r:
        return r.status, json.loads(r.read() or b"null")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=600)
    timeout = ap.parse_args().timeout

    ps = {}
    for line in sh(COMPOSE + ["ps", "-a", "--format", "json"]).splitlines():
        for row in (json.loads(line) if line.startswith("[") else [json.loads(line)]):
            ps[row["Service"]] = row
    for svc in ("db-migrate", "handoff-unpack"):
        row = ps.get(svc, {})
        record(f"{svc} completed", row.get("State") == "exited" and row.get("ExitCode") == 0,
               f"{row.get('State')} exit={row.get('ExitCode')}")
    for svc in ("postgres", "edge-collector", "edge-sync", "telemetry-sync", "log-parser",
                "timeline-generator", "partitions", "reporting-api"):
        record(f"{svc} running", ps.get(svc, {}).get("State") == "running", ps.get(svc, {}).get("Status", "missing"))

    deadline, events, last_note = time.time() + timeout, 0, 0.0
    print(f"waiting up to {timeout}s for ingestion and the first incidents (timeline runs every 5 min) ...")
    while time.time() < deadline:
        out = psql("SELECT count(*) FROM telemetry_events")
        events = int(out) if out.isdigit() else 0
        inc = psql("SELECT count(*) FROM incidents")
        if events > 0 and inc.isdigit() and int(inc) > 0:
            break
        if time.time() - last_note >= 60:
            print(f"       ... {events} events, {inc or 0} incidents so far", flush=True)
            last_note = time.time()
        time.sleep(10)
    record("telemetry ingested into PostgreSQL", events > 0, f"{events} events")
    # incidents appear on the timeline-generator's next 5-minute cycle after ingestion
    by_type = psql("SELECT event_type || '=' || count(*) FROM telemetry_events GROUP BY event_type ORDER BY event_type")
    print("       by type:", by_type.replace("\n", ", "))
    modbus = psql("SELECT count(*) FROM telemetry_events WHERE event_type='MODBUS_DPI'")
    record("unique Modbus transactions ingested", modbus == "10", f"{modbus} (expected 10 after de-duplication)")
    record("evidence manifests VERIFIED, none mismatched",
           psql("SELECT count(*) FROM evidence_manifests WHERE verification_status='HASH_MISMATCH'") == "0"
           and int(psql("SELECT count(*) FROM evidence_manifests WHERE verification_status='VERIFIED'") or 0) > 0)
    inc = psql("SELECT count(*) FROM incidents")
    record("timeline-generator produced incidents", inc.isdigit() and int(inc) > 0, f"{inc} incidents")

    try:
        st, body = api("/healthz")
        record("reporting-api /healthz", st == 200)
        st, body = api("/api/v1/incidents?limit=5")
        record("reporting-api /api/v1/incidents", st == 200 and isinstance(body, list), f"{len(body)} rows")
    except Exception as exc:
        record("reporting-api reachable on 127.0.0.1", False, str(exc))

    for svc in ("edge-collector", "edge-sync"):
        mode = sh(["docker", "inspect", "-f", "{{.HostConfig.NetworkMode}}", ps.get(svc, {}).get("Name", svc)])
        record(f"{svc} has no network", mode == "none", mode)
    ports = sh(["docker", "ps", "--filter", "label=com.docker.compose.project=cyb691", "--format", "{{.Ports}}"])
    # Only "host:port->container/proto" entries are published; bare "5432/tcp" is an image EXPOSE.
    published = [p.strip() for p in re.split(r"[,\n]", ports) if "->" in p]
    record("nothing publishes TCP/502", not any(re.search(r":502->", p) for p in published))
    record("published ports bind to 127.0.0.1 only", bool(published) and all(p.startswith("127.0.0.1:") for p in published),
           ", ".join(published) or "none")
    write = subprocess.run(COMPOSE + ["exec", "-T", "postgres", "psql", "-U", "svc_readonly", "-d", "cyb691",
                                      "-c", "DELETE FROM incidents"], capture_output=True, text=True)
    record("read-only role cannot modify data", write.returncode != 0 and
           ("permission denied" in write.stderr or "read-only transaction" in write.stderr), write.stderr.strip()[:80])

    if not all(results):
        print("\n--- diagnostics (last 25 log lines per service) ---")
        for svc in ("edge-collector", "edge-sync", "telemetry-sync", "timeline-generator"):
            print(f"\n## {svc}")
            print(sh(COMPOSE + ["logs", "--no-color", "--tail", "25", svc]))
        print("\n## landing drop zone (files waiting for telemetry-sync)")
        print(sh(COMPOSE + ["exec", "-T", "telemetry-sync", "python", "-c",
                            "import os;print(sum(len(f) for _,_,f in os.walk('/objects/landing')))"]))
        print("\n## processing runs")
        print(psql("SELECT workload, status, records_output, left(coalesce(error_summary,''),120) "
                   "FROM processing_runs ORDER BY started_at DESC LIMIT 8"))

    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
