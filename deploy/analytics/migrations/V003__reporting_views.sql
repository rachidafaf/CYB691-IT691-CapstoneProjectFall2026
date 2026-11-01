-- =============================================================================
-- V003__reporting_views.sql – read-only views used by reporting-api
-- security_invoker so the caller's (readonly) privileges apply (PG15+).
-- =============================================================================

CREATE OR REPLACE VIEW v_daily_event_counts WITH (security_invoker = true) AS
SELECT date_trunc('day', timestamp_utc) AS day_utc,
       edge_id, event_type, severity,
       count(*)                          AS events
FROM telemetry_events
GROUP BY 1, 2, 3, 4;

CREATE OR REPLACE VIEW v_open_incidents WITH (security_invoker = true) AS
SELECT incident_id, severity, rule, title, status, first_seen_utc, last_seen_utc,
       event_count, src_ip, dest_ip, edge_id
FROM incidents
WHERE status IN ('OPEN', 'INVESTIGATING');

CREATE OR REPLACE VIEW v_evidence_lineage WITH (security_invoker = true) AS
SELECT em.manifest_id, em.kind, em.edge_id, em.container, em.blob_name, em.sha256_hash,
       em.verification_status, em.verified_at, em.event_count,
       pr.run_id, pr.workload, pr.image_ref, pr.git_sha
FROM evidence_manifests em
LEFT JOIN processing_runs pr ON pr.run_id = em.run_id;

GRANT SELECT ON v_daily_event_counts, v_open_incidents, v_evidence_lineage
    TO cyb691_readonly, cyb691_analytics;
