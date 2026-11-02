-- =============================================================================
-- CYB691 Capstone – Team 4
-- Migration V001__initial_schema.sql  (PostgreSQL 16, `postgres` service in docker-compose.yml)
-- =============================================================================
-- Applied by deploy/analytics/migrate.py (the db-migrate service), which records a SHA-256 checksum per file in
-- schema_migrations and refuses to run if an applied file was edited later.
-- Every statement is idempotent (IF NOT EXISTS) so a re-run is harmless.
--
-- This file replaces the earlier draft, which could not run:
--   * COMMENT ON TABLE telemetry_events came before CREATE TABLE
--   * UNIQUE(idempotency_key) on a partitioned table must include the partition key
--   * GRANT referenced a non-existent table (upload_queue)
--   * PostgreSQL is reachable only on the internal Docker network analytics_net
--     (no published port); see deploy/docker/docker-compose.yml
--
-- Conventions: UUID keys, TIMESTAMPTZ in UTC, JSONB metadata, idempotency keys
-- (= SHA-256 of canonical event content, see deploy/common/telemetry_schema.py).
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()

-- ---------------------------------------------------------------------------
-- 1. telemetry_events – normalised edge telemetry (monthly range partitions)
--    Partitioning is justified: retention is enforced by detaching/dropping whole
--    months, and nearly every query is time-bounded.
--    PK = (idempotency_key, timestamp_utc). timestamp_utc is part of the hashed
--    content, so a given key always maps to one timestamp: the composite key is
--    therefore globally unique on idempotency_key.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS telemetry_events (
    idempotency_key     CHAR(64)     NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    timestamp_utc       TIMESTAMPTZ  NOT NULL,
    event_uuid          UUID         NOT NULL,
    schema_version      TEXT         NOT NULL,
    edge_id             TEXT         NOT NULL,
    event_type          TEXT         NOT NULL CHECK (event_type IN
                            ('MODBUS_DPI','SURICATA_ALERT','FIREWALL_DROP','LOCAL_ALERT')),
    severity            TEXT         NOT NULL CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    collected_at_utc    TIMESTAMPTZ  NOT NULL,
    ingested_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    src_ip              INET,
    src_port            INTEGER      CHECK (src_port BETWEEN 0 AND 65535),
    dest_ip             INET,
    dest_port           INTEGER      CHECK (dest_port BETWEEN 0 AND 65535),
    protocol            TEXT,
    unit_id             SMALLINT     CHECK (unit_id BETWEEN 0 AND 255),
    function_code       SMALLINT     CHECK (function_code BETWEEN 1 AND 255),
    function_category   TEXT,
    sha256_hash         CHAR(64)     NOT NULL,
    raw_ref             JSONB,
    raw                 JSONB,
    metadata            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    batch_id            UUID,
    evidence_manifest_id TEXT,
    run_id              UUID,
    PRIMARY KEY (idempotency_key, timestamp_utc),
    CHECK (sha256_hash = idempotency_key)
) PARTITION BY RANGE (timestamp_utc);

COMMENT ON TABLE telemetry_events IS
  'Normalised OT telemetry from edge gateways. Insert-only; de-duplicated by idempotency_key.';

-- Catches out-of-range timestamps instead of failing the whole batch.
CREATE TABLE IF NOT EXISTS telemetry_events_default PARTITION OF telemetry_events DEFAULT;

CREATE INDEX IF NOT EXISTS idx_te_ts            ON telemetry_events (timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_te_edge_ts       ON telemetry_events (edge_id, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_te_type_sev_ts   ON telemetry_events (event_type, severity, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_te_fc            ON telemetry_events (function_code) WHERE function_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_te_src           ON telemetry_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_te_manifest      ON telemetry_events (evidence_manifest_id);
CREATE INDEX IF NOT EXISTS idx_te_ingested      ON telemetry_events (ingested_at);

-- Partition helper. SECURITY DEFINER so the ingestion role can call it without
-- owning the table. search_path pinned to prevent hijacking.
CREATE OR REPLACE FUNCTION ensure_telemetry_partitions(months_ahead INTEGER DEFAULT 3)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    m DATE := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    i INTEGER;
    created INTEGER := 0;
    pname TEXT;
BEGIN
    IF months_ahead < 0 OR months_ahead > 24 THEN
        RAISE EXCEPTION 'months_ahead out of range';
    END IF;
    FOR i IN 0..months_ahead LOOP
        pname := format('telemetry_events_%s', to_char(m + make_interval(months => i), 'YYYY_MM'));
        IF to_regclass(pname) IS NULL THEN
            EXECUTE format(
              'CREATE TABLE %I PARTITION OF telemetry_events FOR VALUES FROM (%L) TO (%L)',
              pname, m + make_interval(months => i), m + make_interval(months => i + 1));
            created := created + 1;
        END IF;
    END LOOP;
    RETURN created;
END;
$$;

-- Create the lab period partitions explicitly (Sep 2026 onwards), then the rolling window.
DO $$
DECLARE d DATE := DATE '2026-09-01';
BEGIN
    WHILE d < date_trunc('month', now() AT TIME ZONE 'UTC')::date LOOP
        IF to_regclass(format('telemetry_events_%s', to_char(d, 'YYYY_MM'))) IS NULL THEN
            EXECUTE format('CREATE TABLE %I PARTITION OF telemetry_events FOR VALUES FROM (%L) TO (%L)',
                           format('telemetry_events_%s', to_char(d, 'YYYY_MM')), d, d + INTERVAL '1 month');
        END IF;
        d := d + INTERVAL '1 month';
    END LOOP;
END $$;
SELECT ensure_telemetry_partitions(3);

-- ---------------------------------------------------------------------------
-- 2. modbus_transactions – Modbus detail for MODBUS_DPI events (1:1, idempotent)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS modbus_transactions (
    idempotency_key     CHAR(64)     PRIMARY KEY,
    event_timestamp_utc TIMESTAMPTZ  NOT NULL,
    unit_id             SMALLINT,
    function_code       SMALLINT     NOT NULL CHECK (function_code BETWEEN 1 AND 255),
    function_name       TEXT,
    category            TEXT,
    transaction_id      INTEGER,
    address             INTEGER      CHECK (address BETWEEN 0 AND 65535),
    quantity            INTEGER      CHECK (quantity BETWEEN 0 AND 65535),
    is_write            BOOLEAN      NOT NULL DEFAULT FALSE,
    exception_code      TEXT,
    metadata            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    FOREIGN KEY (idempotency_key, event_timestamp_utc)
        REFERENCES telemetry_events (idempotency_key, timestamp_utc)
);
CREATE INDEX IF NOT EXISTS idx_mt_fc_ts ON modbus_transactions (function_code, event_timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_mt_write ON modbus_transactions (event_timestamp_utc) WHERE is_write;

-- ---------------------------------------------------------------------------
-- 3. suricata_alerts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suricata_alerts (
    idempotency_key     CHAR(64)     PRIMARY KEY,
    event_timestamp_utc TIMESTAMPTZ  NOT NULL,
    signature_id        BIGINT,
    signature           TEXT,
    rev                 INTEGER,
    alert_severity      SMALLINT,
    alert_category      TEXT,
    alert_action        TEXT,
    flow_id             BIGINT,
    raw_alert           JSONB,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    FOREIGN KEY (idempotency_key, event_timestamp_utc)
        REFERENCES telemetry_events (idempotency_key, timestamp_utc)
);
CREATE INDEX IF NOT EXISTS idx_sa_sig_ts ON suricata_alerts (signature_id, event_timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_sa_sev_ts ON suricata_alerts (alert_severity, event_timestamp_utc);

-- ---------------------------------------------------------------------------
-- 4. firewall_drops
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firewall_drops (
    idempotency_key     CHAR(64)     PRIMARY KEY,
    event_timestamp_utc TIMESTAMPTZ  NOT NULL,
    rule_id             TEXT,
    interface           TEXT,
    direction           TEXT,
    action              TEXT,
    src_ip              INET,
    dest_ip             INET,
    dest_port           INTEGER,
    protocol            TEXT,
    raw_line            TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    FOREIGN KEY (idempotency_key, event_timestamp_utc)
        REFERENCES telemetry_events (idempotency_key, timestamp_utc)
);
CREATE INDEX IF NOT EXISTS idx_fd_dst_ts ON firewall_drops (dest_ip, dest_port, event_timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_fd_src_ts ON firewall_drops (src_ip, event_timestamp_utc);

-- ---------------------------------------------------------------------------
-- 7. processing_runs (created before tables that reference it)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS processing_runs (
    run_id          UUID         PRIMARY KEY,
    workload        TEXT         NOT NULL,       -- telemetry-sync, log-parser, ...
    pipeline_stage  TEXT,
    status          TEXT         NOT NULL DEFAULT 'RUNNING'
                        CHECK (status IN ('RUNNING','COMPLETED','FAILED','PARTIAL')),
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    records_input   INTEGER      NOT NULL DEFAULT 0,
    records_output  INTEGER      NOT NULL DEFAULT 0,
    records_failed  INTEGER      NOT NULL DEFAULT 0,
    records_duplicate INTEGER    NOT NULL DEFAULT 0,
    error_summary   TEXT,
    image_ref       TEXT,                        -- image digest for traceability
    git_sha         TEXT,
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_pr_workload_ts ON processing_runs (workload, started_at);
CREATE INDEX IF NOT EXISTS idx_pr_status      ON processing_runs (status);

-- ---------------------------------------------------------------------------
-- 5. incidents – deterministic incident_id makes timeline re-runs idempotent
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT         PRIMARY KEY,
    severity        TEXT         NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    rule            TEXT         NOT NULL,
    title           TEXT         NOT NULL,
    description     TEXT,
    status          TEXT         NOT NULL DEFAULT 'OPEN'
                        CHECK (status IN ('OPEN','INVESTIGATING','MITIGATED','RESOLVED','FALSE_POSITIVE')),
    first_seen_utc  TIMESTAMPTZ  NOT NULL,
    last_seen_utc   TIMESTAMPTZ  NOT NULL,
    event_count     INTEGER      NOT NULL DEFAULT 0,
    event_keys      JSONB        NOT NULL DEFAULT '[]'::jsonb,
    src_ip          INET,
    dest_ip         INET,
    edge_id         TEXT,
    created_by_run  UUID         REFERENCES processing_runs (run_id),
    analyst_notes   TEXT,
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inc_status_sev ON incidents (status, severity);
CREATE INDEX IF NOT EXISTS idx_inc_last_seen  ON incidents (last_seen_utc);

-- ---------------------------------------------------------------------------
-- 6. ml_predictions – one prediction per (event, model, version)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_predictions (
    prediction_id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    event_idempotency_key CHAR(64)     NOT NULL,
    event_timestamp_utc   TIMESTAMPTZ  NOT NULL,
    model_name            TEXT         NOT NULL,
    model_version         TEXT         NOT NULL,
    model_sha256          CHAR(64)     NOT NULL,
    prediction_label      SMALLINT     NOT NULL,
    prediction_probability DOUBLE PRECISION CHECK (prediction_probability BETWEEN 0 AND 1),
    feature_vector        JSONB        NOT NULL,
    inference_latency_ms  DOUBLE PRECISION,
    run_id                UUID         REFERENCES processing_runs (run_id),
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (event_idempotency_key, model_name, model_version),
    FOREIGN KEY (event_idempotency_key, event_timestamp_utc)
        REFERENCES telemetry_events (idempotency_key, timestamp_utc)
);
CREATE INDEX IF NOT EXISTS idx_mlp_model_ts ON ml_predictions (model_name, model_version, event_timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_mlp_positive ON ml_predictions (event_timestamp_utc) WHERE prediction_label = 1;

-- ---------------------------------------------------------------------------
-- 8. evidence_manifests – one row per verified blob object (SHA-256 lineage)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence_manifests (
    manifest_id         TEXT         PRIMARY KEY,          -- '<kind>:<object_sha256>'
    kind                TEXT         NOT NULL,             -- TELEMETRY_BATCH, EVE_JSON, PCAP, ...
    edge_id             TEXT,
    batch_id            UUID,
    container           TEXT         NOT NULL,
    blob_name           TEXT         NOT NULL,
    sha256_hash         CHAR(64)     NOT NULL CHECK (sha256_hash ~ '^[0-9a-f]{64}$'),
    file_size_bytes     BIGINT       NOT NULL CHECK (file_size_bytes >= 0),
    content_type        TEXT,
    event_count         INTEGER,
    verification_status TEXT         NOT NULL CHECK (verification_status IN
                            ('VERIFIED','HASH_MISMATCH','INVALID_CONTENT','QUARANTINED')),
    verified_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    is_immutable        BOOLEAN      NOT NULL DEFAULT FALSE,
    retention_until     TIMESTAMPTZ,
    run_id              UUID         REFERENCES processing_runs (run_id),
    manifest            JSONB        NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (container, blob_name)
);
CREATE INDEX IF NOT EXISTS idx_em_sha    ON evidence_manifests (sha256_hash);
CREATE INDEX IF NOT EXISTS idx_em_run    ON evidence_manifests (run_id);
CREATE INDEX IF NOT EXISTS idx_em_kind_ts ON evidence_manifests (kind, verified_at);

-- ---------------------------------------------------------------------------
-- 9. audit_events – append-only audit trail (UPDATE/DELETE blocked by trigger)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    audit_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    actor           TEXT         NOT NULL,      -- workload identity / principal name
    actor_type      TEXT         NOT NULL DEFAULT 'WORKLOAD',
    action          TEXT         NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    outcome         TEXT         NOT NULL DEFAULT 'SUCCESS' CHECK (outcome IN ('SUCCESS','FAILURE','DENIED')),
    run_id          UUID,
    details         JSONB        NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_ae_ts     ON audit_events (occurred_at);
CREATE INDEX IF NOT EXISTS idx_ae_action ON audit_events (action, occurred_at);
CREATE INDEX IF NOT EXISTS idx_ae_target ON audit_events (target_type, target_id);

CREATE OR REPLACE FUNCTION audit_events_block_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;
CREATE TRIGGER trg_audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation();
