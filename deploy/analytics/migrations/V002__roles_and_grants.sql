-- =============================================================================
-- V002__roles_and_grants.sql – least-privilege group roles (NOLOGIN)
-- =============================================================================
-- Login roles are NOT created here. In the Docker deployment the postgres init
-- script deploy/docker/postgres/init/10-service-roles.sh creates one login role per
-- service (svc_ingestion, svc_analytics, svc_readonly), with passwords read from
-- Docker secrets, and grants each ONE of these group roles. Passwords never appear
-- in SQL files.
--
--   cyb691_ingestion  telemetry-sync, log-parser      insert telemetry/evidence
--   cyb691_analytics  ml-detector, timeline-generator read all, write results
--   cyb691_readonly   reporting-api, analysts          read only
--
-- Nobody but the schema owner (migration identity) may UPDATE/DELETE telemetry.
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cyb691_ingestion') THEN
        CREATE ROLE cyb691_ingestion NOLOGIN NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cyb691_analytics') THEN
        CREATE ROLE cyb691_analytics NOLOGIN NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cyb691_readonly') THEN
        CREATE ROLE cyb691_readonly NOLOGIN NOINHERIT;
    END IF;
END $$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO cyb691_ingestion, cyb691_analytics, cyb691_readonly;

-- Read access ---------------------------------------------------------------
GRANT SELECT ON ALL TABLES IN SCHEMA public TO cyb691_readonly, cyb691_analytics;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO cyb691_readonly, cyb691_analytics;
REVOKE SELECT ON schema_migrations FROM cyb691_readonly;

-- Ingestion: insert-only on telemetry + evidence; idempotency needs SELECT for ON CONFLICT checks
GRANT SELECT, INSERT ON telemetry_events, modbus_transactions, suricata_alerts, firewall_drops,
                        evidence_manifests TO cyb691_ingestion;
GRANT SELECT, INSERT, UPDATE ON processing_runs TO cyb691_ingestion, cyb691_analytics;
GRANT INSERT ON audit_events TO cyb691_ingestion, cyb691_analytics;
GRANT EXECUTE ON FUNCTION ensure_telemetry_partitions(INTEGER) TO cyb691_ingestion;
REVOKE EXECUTE ON FUNCTION ensure_telemetry_partitions(INTEGER) FROM PUBLIC;

-- Analytics: write derived results only
GRANT INSERT ON ml_predictions TO cyb691_analytics;
GRANT INSERT, UPDATE (severity, title, description, last_seen_utc, event_count, event_keys,
                      metadata, updated_at) ON incidents TO cyb691_analytics;
GRANT INSERT ON evidence_manifests TO cyb691_analytics;   -- model artifacts / exports

-- Explicitly no UPDATE/DELETE/TRUNCATE on raw telemetry for any application role
REVOKE UPDATE, DELETE, TRUNCATE ON telemetry_events, modbus_transactions, suricata_alerts,
                                   firewall_drops, evidence_manifests, audit_events
    FROM cyb691_ingestion, cyb691_analytics, cyb691_readonly;
