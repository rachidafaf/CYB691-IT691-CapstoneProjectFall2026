"""Static security tests for the Docker Compose deployment (no Docker needed):
zone isolation, TCP/502 exposure, published ports, container hardening,
secrets handling, RBAC, dependency pinning, and code that could talk to a PLC."""

import glob
import os
import re

import pytest
import yaml

from conftest import DEPLOY, REPO

COMPOSE_PATH = os.path.join(DEPLOY, "docker", "docker-compose.yml")
EDGE = {"handoff-unpack", "edge-collector", "edge-sync"}
ANALYTICS = {"postgres", "db-migrate", "telemetry-sync", "log-parser", "timeline-generator", "partitions",
             "reporting-api", "ml-train", "ml-detector"}
APP_SERVICES = (EDGE | ANALYTICS) - {"postgres"}


@pytest.fixture(scope="module")
def compose():
    with open(COMPOSE_PATH) as f:
        return yaml.safe_load(f)


def _mount_sources(svc):
    return [str(v).split(":")[0] for v in svc.get("volumes", [])]


# ---------------------------------------------------------------- topology
def test_every_service_is_assigned_to_a_zone(compose):
    assert set(compose["services"]) == EDGE | ANALYTICS


def test_edge_containers_have_no_network(compose):
    for name in EDGE:
        svc = compose["services"][name]
        assert svc.get("network_mode") == "none", name
        assert "networks" not in svc and "ports" not in svc, name


def test_analytics_network_is_internal_and_only_api_is_published(compose):
    assert compose["networks"]["analytics_net"]["internal"] is True
    for name in ANALYTICS:
        svc = compose["services"][name]
        assert "network_mode" not in svc, name
        nets = set(svc.get("networks", []))
        if name == "reporting-api":
            assert nets == {"analytics_net", "public_net"}
        elif name == "postgres":
            assert nets == {"analytics_net", "db_host_net"}
        else:
            assert nets == {"analytics_net"}, f"{name} must not reach the host network"
            assert "ports" not in svc, name


def test_published_ports_are_loopback_only_and_never_modbus(compose):
    for name, svc in compose["services"].items():
        for p in svc.get("ports", []):
            p = str(p)
            assert p.startswith("127.0.0.1:"), f"{name} must bind to localhost only"
            assert p.split(":")[-1] != "502", name
        assert "expose" not in svc, name


def test_landing_volume_is_the_only_edge_to_analytics_path(compose):
    edge_vols = set().union(*(_mount_sources(compose["services"][n]) for n in EDGE))
    analytics_vols = set().union(*(_mount_sources(compose["services"][n]) for n in ANALYTICS))
    assert (edge_vols & analytics_vols & set(compose["volumes"])) == {"landing"}
    users_of_landing = {n for n, s in compose["services"].items() if "landing" in _mount_sources(s)}
    assert users_of_landing == {"edge-sync", "telemetry-sync"}


def test_host_bind_mounts_are_readonly_inputs_only(compose):
    for name, svc in compose["services"].items():
        for v in svc.get("volumes", []):
            src = str(v).split(":")[0]
            assert "docker.sock" not in str(v), name
            if src.startswith((".", "/", "$")):
                assert str(v).endswith(":ro"), f"{name}: host mount {v} must be read-only"


# ---------------------------------------------------------------- hardening
def test_app_containers_are_hardened(compose):
    for name in APP_SERVICES:
        svc = compose["services"][name]
        assert svc.get("read_only") is True, name
        assert svc.get("cap_drop") == ["ALL"] and "cap_add" not in svc, name
        assert "no-new-privileges:true" in svc.get("security_opt", []), name
        assert svc.get("user") == "10001:10001", name
        assert not svc.get("privileged") and "pid" not in svc and "ipc" not in svc, name
        assert ":latest" not in svc.get("image", ""), name


def test_postgres_has_minimal_capabilities(compose):
    pg = compose["services"]["postgres"]
    assert pg["cap_drop"] == ["ALL"]
    assert set(pg["cap_add"]) <= {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
    assert "no-new-privileges:true" in pg["security_opt"]
    assert re.match(r"^postgres:\d+\.\d+", pg["image"])


def test_postgres_host_port_is_loopback_only_and_isolated(compose):
    """The database is published for host tools on 127.0.0.1 only (default 5433, to avoid a
    local PostgreSQL on 5432), and db_host_net carries nothing but postgres."""
    ports = [str(p) for p in compose["services"]["postgres"].get("ports", [])]
    assert ports == ["127.0.0.1:${CYB691_PG_HOST_PORT:-5433}:5432"]
    users = {n for n, s in compose["services"].items() if "db_host_net" in s.get("networks", [])}
    assert users == {"postgres"}
    assert compose["services"]["reporting-api"]["environment"]["PGHOST"] == "postgres"
    assert compose["services"]["reporting-api"]["environment"]["PGPORT"] == "5432"


def test_only_api_and_database_publish_ports(compose):
    assert {n for n, s in compose["services"].items() if s.get("ports")} == {"reporting-api", "postgres"}


def test_long_running_services_have_healthchecks(compose):
    for name, svc in compose["services"].items():
        if svc.get("restart") == "no" or name in EDGE:   # edge image carries its own HEALTHCHECK
            continue
        assert "healthcheck" in svc, name


# ---------------------------------------------------------------- secrets
def test_passwords_come_only_from_docker_secrets(compose):
    for name, svc in compose["services"].items():
        env = svc.get("environment", {}) or {}
        assert "PGPASSWORD" not in env and "POSTGRES_PASSWORD" not in env, name
        if "PGUSER" in env:
            secret = env["PGPASSWORD_FILE"].rsplit("/", 1)[-1]
            assert svc["secrets"] == [secret], f"{name} should see only its own password"
    for s in compose["secrets"].values():
        assert s["file"].startswith("./secrets/")


def test_secrets_directory_is_gitignored():
    with open(os.path.join(DEPLOY, "docker", ".gitignore")) as f:
        assert "secrets/" in f.read()


SECRET_PATTERNS = [
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"(?i)password\s*=\s*['\"][^'\"$]{8,}['\"]",
    r"(?i)['\"]password['\"]\s*:\s*['\"][^'\"]{8,}['\"]",
    r"postgres(ql)?://[^:\s/]+:[^@\s]{4,}@",
    r"ghp_[A-Za-z0-9]{36}",
]


def test_no_secrets_committed_in_deploy_tree():
    for f in glob.glob(os.path.join(DEPLOY, "**", "*"), recursive=True):
        if os.path.isdir(f) or f.endswith((".db", ".gz", ".pyc")) or f"{os.sep}secrets{os.sep}" in f:
            continue
        body = open(f, errors="ignore").read()
        for p in SECRET_PATTERNS:
            assert not re.search(p, body), f"{f} matches {p}"


# ---------------------------------------------------------------- code paths
def test_no_code_can_send_modbus_or_open_raw_sockets():
    """The analytics tier must never send control commands to PLCs; the edge only reads logs."""
    for f in glob.glob(os.path.join(DEPLOY, "**", "*.py"), recursive=True):
        src = open(f).read()
        assert "pymodbus" not in src, f
        assert not re.search(r"\bimport socket\b|socket\.socket\(", src), f
        assert not re.search(r"ModbusTcpClient|write_register|write_coil", src), f


def test_edge_code_has_no_network_client_imports():
    for f in glob.glob(os.path.join(DEPLOY, "edge", "*.py")):
        src = open(f).read()
        assert not re.search(r"^\s*(import|from)\s+(requests|urllib|http\.client|httpx|psycopg2)\b", src, re.M), f


# ---------------------------------------------------------------- images & deps
def test_containerfiles_non_root_and_no_remote_add():
    files = glob.glob(os.path.join(DEPLOY, "docker", "Containerfile.*"))
    assert {os.path.basename(f) for f in files} == {"Containerfile.edge", "Containerfile.analytics",
                                                     "Containerfile.ml"}
    for f in files:
        body = open(f).read()
        assert re.search(r"^USER 10001:10001$", body, re.M), f
        assert not re.search(r"^ADD\s+https?://", body, re.M), f
        assert ":latest" not in body, f
        assert not re.search(r"^EXPOSE\s+502\b", body, re.M), f
    assert not re.search(r"^EXPOSE", open(os.path.join(DEPLOY, "docker", "Containerfile.edge")).read(), re.M)


def test_requirements_are_pinned():
    for f in glob.glob(os.path.join(DEPLOY, "requirements", "*.txt")):
        for line in open(f):
            line = line.split("#")[0].strip()
            if line and not line.startswith("-r"):
                assert re.match(r"^[A-Za-z0-9_.\-\[\]]+==[0-9][\w.]*$", line), f"{f}: {line}"


# ---------------------------------------------------------------- RBAC (SQL)
def test_sql_roles_least_privilege():
    sql = open(os.path.join(DEPLOY, "analytics", "migrations", "V002__roles_and_grants.sql")).read()
    grants = re.findall(r"GRANT ([^;]+?) ON ([^;]+?) TO ([^;]+);", sql, re.S)
    for privs, objs, roles in grants:
        if "cyb691_readonly" in roles:
            assert privs.strip() in ("SELECT", "USAGE"), privs
        for bad in ("DELETE", "TRUNCATE", "ALL"):
            assert bad not in privs.upper().split(), privs
        if re.search(r"\btelemetry_events\b", objs):
            assert "UPDATE" not in privs.upper(), "telemetry must be insert-only"
    assert "REVOKE CREATE ON SCHEMA public FROM PUBLIC" in sql


def test_service_logins_are_not_superusers():
    sh = open(os.path.join(DEPLOY, "docker", "postgres", "init", "10-service-roles.sh")).read()
    assert not re.search(r"^(?!\s*(--|#)).*\bSUPERUSER\b", sh, re.M | re.I), "no superuser grants"
    assert not re.search(r"PASSWORD '", sh), "passwords must come from psql variables (secrets)"
    for login, group in (("svc_ingestion", "cyb691_ingestion"), ("svc_analytics", "cyb691_analytics"),
                         ("svc_readonly", "cyb691_readonly")):
        assert re.search(rf"CREATE ROLE {login}\s+LOGIN PASSWORD :'\w+'\s+IN ROLE {group};", sh), login


def test_ci_gates_fail_on_vulnerabilities_and_secrets():
    wf = open(os.path.join(DEPLOY, "ci", "docker-ci.yml")).read()
    assert "gitleaks" in wf
    assert re.search(r"exit-code:\s*['\"]?1", wf) and "CRITICAL,HIGH" in wf
    assert "docker compose" in wf and " config" in wf
