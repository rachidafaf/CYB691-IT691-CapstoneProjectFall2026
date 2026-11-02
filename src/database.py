#!/usr/bin/env python3
"""
===============================================================================
CYB691 Cybersecurity Capstone - Team 4 (Cyber-Physical & Network Defense)
Module: Embedded SQLite Telemetry & Forensics Database Manager (database.py)
Author: Rachid Afaf (Security Architect / Lead Analyst)
===============================================================================
Description:
  Database interface with two interchangeable back ends:
    * SQLite  (default)  data/telemetry.db, zero configuration
    * PostgreSQL         selected by a postgresql:// URL, either via the environment
                         variable CYB691_DATABASE_URL or the --db argument of each script,
                         e.g. postgresql://postgres@localhost:5432/postgres
                         The password is never stored in the repo: libpq reads PGPASSWORD
                         or the pgpass file (%APPDATA%/postgresql/pgpass.conf on Windows).
                         Tables are created in schema CYB691_PG_SCHEMA (default "cyb691").
  It is used for:
    1. Storing normalized OT telemetry frames with high-speed indexes.
    2. Extracting observation-time ML feature vectors via optimized SQL queries.
    3. Logging incident triage metrics and forensic timeline summaries.
    4. Archiving model evaluation benchmark metrics (Random Forest, DT, SVM, IF).

  Schema:
    - telemetry_events: Individual normalized Modbus & Firewall records
    - incident_metrics: Aggregated triage metrics from timeline generator
    - ml_benchmarks: Layer 3 ML model performance metrics across CV folds
===============================================================================
"""

import os
import json
import sqlite3
import pandas as pd
from datetime import datetime, timezone

try:
    from src.scenario import load_scenario, action_index, _ts_key, UNLABELED
except ImportError:
    from scenario import load_scenario, action_index, _ts_key, UNLABELED

# Canonical project directories dynamically resolved relative to repo root
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(REPO_ROOT, "data")
SQLITE_DB_PATH = os.path.join(DEFAULT_DATA_DIR, "telemetry.db")
# A postgresql:// URL in CYB691_DATABASE_URL switches every script to PostgreSQL.
DEFAULT_DB_PATH = os.environ.get("CYB691_DATABASE_URL", "").strip() or SQLITE_DB_PATH
PG_SCHEMA = os.environ.get("CYB691_PG_SCHEMA", "cyb691")
NUL_TEXT = "\\u0000"      # PostgreSQL TEXT cannot hold U+0000; stored as this literal and restored on read


def is_postgres(target=None):
    return str(target or DEFAULT_DB_PATH).lower().startswith(("postgresql://", "postgres://"))


def describe_target(target=None):
    """Human-readable target without any password (for log lines)."""
    t = str(target or DEFAULT_DB_PATH)
    if not is_postgres(t):
        return f"SQLite {t}"
    from urllib.parse import urlsplit
    u = urlsplit(t)
    host = u.hostname or "localhost"
    return f"PostgreSQL {u.username or ''}@{host}:{u.port or 5432}{u.path or '/'} (schema {PG_SCHEMA})"


def database_available(target=None):
    """True if the SQLite file exists, or the PostgreSQL server accepts a connection."""
    t = target or DEFAULT_DB_PATH
    if not is_postgres(t):
        return os.path.exists(t)
    try:
        get_db_connection(t).close()
        return True
    except Exception:
        return False


def _pg_connect(url):
    """psycopg2 if installed, else psycopg 3. Both use %s placeholders."""
    if not str(PG_SCHEMA).replace("_", "").isalnum():
        raise ValueError(f"invalid CYB691_PG_SCHEMA {PG_SCHEMA!r}")
    try:
        import psycopg2
        conn = psycopg2.connect(url, connect_timeout=10, application_name="cyb691-pipeline")
    except ImportError:
        try:
            import psycopg
        except ImportError as exc:
            raise ImportError("PostgreSQL selected but no driver installed: pip install psycopg2-binary") from exc
        conn = psycopg.connect(url, connect_timeout=10, application_name="cyb691-pipeline")
    cur = conn.cursor()
    cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{PG_SCHEMA}"')
    cur.execute(f'SET search_path TO "{PG_SCHEMA}"')
    conn.commit()
    return conn


def get_db_connection(db_path=None):
    """
    SQLite: connection with write-ahead logging and foreign keys.
    PostgreSQL: connection with search_path set to the project schema.
    """
    target = db_path or DEFAULT_DB_PATH
    if is_postgres(target):
        return _pg_connect(target)
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    conn = sqlite3.connect(target)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


def _sql(sql, target):
    """Writes SQL with '?' placeholders; converts them for PostgreSQL drivers."""
    return sql.replace("?", "%s") if is_postgres(target) else sql


def _rows_as_dicts(cursor):
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def _pg_text(v):
    return v.replace("\x00", NUL_TEXT) if isinstance(v, str) and "\x00" in v else v


def init_db(db_path=None):
    """
    Initializes the database schema with appropriate tables and performance indexes.
    """
    target = db_path or DEFAULT_DB_PATH
    pg = is_postgres(target)
    conn = get_db_connection(target)
    cursor = conn.cursor()
    real = "DOUBLE PRECISION" if pg else "REAL"
    autoid = "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY" if pg else "INTEGER PRIMARY KEY AUTOINCREMENT"

    # 1. Normalized Telemetry Events Table
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS telemetry_events (
        event_id TEXT PRIMARY KEY,
        timestamp_iso TEXT NOT NULL,
        inter_arrival_ms {real} NOT NULL,
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        destination_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        unit_id INTEGER NOT NULL,
        function_code INTEGER NOT NULL,
        function_name TEXT NOT NULL,
        category TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        payload_raw TEXT,
        payload_parsed_json TEXT,
        exception_code TEXT,
        action_taken TEXT,
        is_state_altering INTEGER NOT NULL,
        has_protocol_exception INTEGER NOT NULL,
        threat_score INTEGER NOT NULL,
        ground_truth_label INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # Performance & Forensics Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events(timestamp_iso);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_fcode ON telemetry_events(function_code);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_ground_truth ON telemetry_events(ground_truth_label);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_ips ON telemetry_events(source_ip, dest_ip);")

    # 2. Incident Triage Summary Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incident_metrics (
        report_id TEXT PRIMARY KEY,
        generated_at TEXT NOT NULL,
        total_events INTEGER NOT NULL,
        read_operations INTEGER NOT NULL,
        write_operations INTEGER NOT NULL,
        protocol_exceptions INTEGER NOT NULL,
        high_threat_events INTEGER NOT NULL,
        metrics_json TEXT NOT NULL
    );
    """)

    # 3. ML Model Benchmarks Table
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS ml_benchmarks (
        benchmark_id {autoid},
        timestamp_iso TEXT NOT NULL,
        model_name TEXT NOT NULL,
        model_type TEXT NOT NULL,
        accuracy {real},
        recall {real},
        precision {real},
        false_positive_rate {real},
        training_time_ms {real},
        inference_latency_per_sample_ms {real},
        meets_recall_target INTEGER,
        meets_fpr_target INTEGER,
        metrics_json TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()


def insert_telemetry_records(records, db_path=None, replace=True, scenario_path=None):
    """
    Inserts normalized telemetry records (SQLite or PostgreSQL, see DEFAULT_DB_PATH).
    """
    target = db_path or DEFAULT_DB_PATH
    pg = is_postgres(target)
    init_db(target)
    conn = get_db_connection(target)
    cursor = conn.cursor()

    scenario = load_scenario(scenario_path)
    scenario_labels = {k: int(a["label"]) for k, a in action_index(scenario).items()}

    if pg:
        verb, conflict = "INSERT", ("" if replace else " ON CONFLICT (event_id) DO NOTHING")
    else:
        verb, conflict = ("INSERT OR REPLACE" if replace else "INSERT OR IGNORE"), ""
    now_iso = datetime.now(timezone.utc).isoformat()

    rows = []
    for r in records:
        net = r.get("network", {})
        mb = r.get("modbus", {})
        sec = r.get("security", {})
        fcode = int(mb.get("function_code", 0))

        # Ground truth comes from the scenario/action record (data/scenario_actions.json), joined by
        # timestamp - never from the function code or other features. -1 = no matching action.
        ground_truth = int(scenario_labels.get(_ts_key(r.get("timestamp_iso")), UNLABELED))

        rows.append((
            r.get("event_id"),
            r.get("timestamp_iso"),
            float(r.get("inter_arrival_ms", 0.0)),
            str(net.get("source_ip", "")),
            str(net.get("dest_ip", "")),
            int(net.get("destination_port", 502)),
            str(net.get("protocol", "Modbus_TCP")),
            int(mb.get("unit_id", 1)),
            fcode,
            str(mb.get("function_name", "")),
            str(mb.get("category", "")),
            str(mb.get("risk_level", "")),
            str(mb.get("payload_raw", "")),
            json.dumps(mb.get("payload_parsed", {})),
            str(mb.get("exception_code", "")),
            str(sec.get("action_taken", "")),
            1 if sec.get("is_state_altering", False) else 0,
            1 if sec.get("has_protocol_exception", False) else 0,
            int(sec.get("threat_score", 0)),
            ground_truth,
            now_iso
        ))

    if replace:
        # A parser run is a complete snapshot of the dataset. event_id is positional
        # (MODBUS-EVT-0001...), so INSERT OR REPLACE alone would leave rows from an
        # earlier, larger run in the table (e.g. 0011-0020 after a 10-event run) and the
        # ML stage would silently train on stale and repeated records. Replace the whole
        # table in the same transaction instead.
        cursor.execute("DELETE FROM telemetry_events;")

    if pg:
        rows = [tuple(_pg_text(v) for v in row) for row in rows]
    cursor.executemany(_sql(f"""
    {verb} INTO telemetry_events (
        event_id, timestamp_iso, inter_arrival_ms, source_ip, dest_ip,
        destination_port, protocol, unit_id, function_code, function_name,
        category, risk_level, payload_raw, payload_parsed_json, exception_code,
        action_taken, is_state_altering, has_protocol_exception, threat_score,
        ground_truth_label, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?){conflict};
    """, target), rows)

    conn.commit()
    conn.close()
    return len(rows)


def load_telemetry_records(db_path=None):
    """
    Retrieves all telemetry events from the database and reconstructs
    them into the canonical hierarchical JSON dictionary format.
    """
    target = db_path or DEFAULT_DB_PATH
    pg = is_postgres(target)
    conn = get_db_connection(target)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM telemetry_events ORDER BY timestamp_iso ASC;")
    rows = _rows_as_dicts(cursor)
    conn.close()
    if pg:   # restore NUL characters that PostgreSQL TEXT could not hold
        for row in rows:
            if isinstance(row.get("payload_raw"), str):
                row["payload_raw"] = row["payload_raw"].replace(NUL_TEXT, "\x00")

    records = []
    for row in rows:
        payload_parsed = {}
        try:
            if row["payload_parsed_json"]:
                payload_parsed = json.loads(row["payload_parsed_json"])
        except (json.JSONDecodeError, TypeError):
            pass

        records.append({
            "event_id": row["event_id"],
            "timestamp_iso": row["timestamp_iso"],
            "inter_arrival_ms": row["inter_arrival_ms"],
            "network": {
                "source_ip": row["source_ip"],
                "dest_ip": row["dest_ip"],
                "destination_port": row["destination_port"],
                "protocol": row["protocol"]
            },
            "modbus": {
                "unit_id": row["unit_id"],
                "function_code": row["function_code"],
                "function_name": row["function_name"],
                "category": row["category"],
                "risk_level": row["risk_level"],
                "payload_raw": row["payload_raw"],
                "payload_parsed": payload_parsed,
                "exception_code": row["exception_code"]
            },
            "security": {
                "action_taken": row["action_taken"],
                "is_state_altering": bool(row["is_state_altering"]),
                "has_protocol_exception": bool(row["has_protocol_exception"]),
                "threat_score": row["threat_score"]
            }
        })
    return records


def query_features_for_ml(db_path=None):
    """
    Queries observation-time features directly via SQL into a Pandas DataFrame.
    Excludes any derived threat scores to guarantee independent evaluation.
    """
    conn = get_db_connection(db_path)
    query = """
    SELECT 
        inter_arrival_ms,
        function_code,
        has_protocol_exception,
        destination_port,
        unit_id,
        LENGTH(payload_raw) AS payload_length,
        ground_truth_label
    FROM telemetry_events
    ORDER BY timestamp_iso ASC;
    """
    cursor = conn.cursor()
    cursor.execute(query)
    df = pd.DataFrame(_rows_as_dicts(cursor))
    conn.close()
    return df


def extract_features_from_db(db_path=None):
    """
    Queries features via SQL and returns (X, y, feature_names). Kept for compatibility only:
    ml_detector.py no longer uses it, because SQLite LENGTH() stops at the first NUL character
    (the captured FC16 payload contains NUL bytes) and y here is the stored scenario label.
    """
    df = query_features_for_ml(db_path)
    feature_names = [
        "inter_arrival_ms",
        "function_code",
        "has_protocol_exception",
        "destination_port",
        "unit_id",
        "payload_length"
    ]
    X = df[feature_names].to_numpy(dtype=float)
    y = df["ground_truth_label"].to_numpy(dtype=int)
    return X, y, feature_names


def save_incident_metrics_to_db(metrics, db_path=None):
    """Saves aggregated incident triage summary into incident_metrics table."""
    target = db_path or DEFAULT_DB_PATH
    init_db(target)
    conn = get_db_connection(target)
    cursor = conn.cursor()

    report_id = f"REPORT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    now_iso = datetime.now(timezone.utc).isoformat()

    upsert = ("INSERT INTO incident_metrics ({cols}) VALUES ({vals}) ON CONFLICT (report_id) DO UPDATE SET "
              "metrics_json = EXCLUDED.metrics_json" if is_postgres(target)
              else "INSERT OR REPLACE INTO incident_metrics ({cols}) VALUES ({vals})")
    cursor.execute(_sql(upsert.format(
        cols="report_id, generated_at, total_events, read_operations, write_operations, "
             "protocol_exceptions, high_threat_events, metrics_json",
        vals="?, ?, ?, ?, ?, ?, ?, ?"), target), (
        report_id,
        now_iso,
        metrics.get("total_telemetry_events", 0),
        metrics.get("traffic_distribution", {}).get("read_operations", 0),
        metrics.get("traffic_distribution", {}).get("write_operations", 0),
        metrics.get("security_flags", {}).get("protocol_exceptions", 0),
        metrics.get("security_flags", {}).get("high_threat_events", 0),
        json.dumps(metrics)
    ))

    conn.commit()
    conn.close()
    return report_id


def save_ml_benchmarks_to_db(ml_report, db_path=None):
    """Saves machine learning benchmark evaluation results into ml_benchmarks table."""
    target = db_path or DEFAULT_DB_PATH
    init_db(target)
    conn = get_db_connection(target)
    cursor = conn.cursor()

    now_iso = ml_report.get("timestamp", datetime.now(timezone.utc).isoformat())
    rows = []

    # Supervised Models
    for model_name, m in ml_report.get("supervised_models", {}).items():
        rows.append((
            now_iso,
            model_name,
            "SUPERVISED",
            float(m.get("accuracy", 0.0)),
            float(m.get("recall", 0.0)),
            float(m.get("precision", 0.0)),
            float(m.get("false_positive_rate", 0.0)),
            float(m.get("training_time_avg_ms", 0.0)),
            float(m.get("inference_latency_per_sample_ms", 0.0)),
            1 if m.get("meets_recall_target") else 0,
            1 if m.get("meets_fpr_target") else 0,
            json.dumps(m)
        ))

    # Unsupervised Model
    if "unsupervised_models" in ml_report:
        u = ml_report["unsupervised_models"]
        rows.append((
            now_iso,
            u.get("model_type", "IsolationForest"),
            "UNSUPERVISED_OUTLIER_SCREENING",
            float(u.get("accuracy", 0.0)),
            float(u.get("recall", 0.0)),
            float(u.get("precision", 0.0)),
            float(u.get("false_positive_rate", 0.0)),
            float(u.get("fit_time_total_ms", 0.0)),
            float(u.get("inference_latency_per_sample_ms", 0.0)),
            None,
            None,
            json.dumps(u)
        ))

    cursor.executemany(_sql("""
    INSERT INTO ml_benchmarks (
        timestamp_iso, model_name, model_type, accuracy, recall, precision,
        false_positive_rate, training_time_ms, inference_latency_per_sample_ms,
        meets_recall_target, meets_fpr_target, metrics_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, target), rows)

    conn.commit()
    conn.close()
    return len(rows)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Create the CYB691 tables (SQLite path or postgresql:// URL)")
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    a = ap.parse_args()
    print(f"[*] Initializing database: {describe_target(a.db)}")
    init_db(a.db)
    print("[+] Database initialized successfully.")
