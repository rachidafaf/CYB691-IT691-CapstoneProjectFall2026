#!/bin/bash
# CYB691: runs once, on first start of an empty pg_data volume (official postgres image).
# Creates the group roles used by migrations V002 plus one LOGIN role per service, with
# passwords read from Docker secrets. No password is ever written to a file or a log.
set -euo pipefail

read_secret() { tr -d '\r\n' < "/run/secrets/$1"; }

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v migrate_pw="$(read_secret pg_migrate_password)" \
     -v ingestion_pw="$(read_secret pg_ingestion_password)" \
     -v analytics_pw="$(read_secret pg_analytics_password)" \
     -v readonly_pw="$(read_secret pg_readonly_password)" <<'SQL'
-- group roles (V002 creates them IF NOT EXISTS and grants table privileges)
CREATE ROLE cyb691_ingestion NOLOGIN NOINHERIT;
CREATE ROLE cyb691_analytics NOLOGIN NOINHERIT;
CREATE ROLE cyb691_readonly  NOLOGIN NOINHERIT;

-- schema owner used only by db-migrate (not a superuser)
CREATE ROLE svc_migrate LOGIN CREATEROLE PASSWORD :'migrate_pw';
ALTER DATABASE cyb691 OWNER TO svc_migrate;
ALTER SCHEMA public OWNER TO svc_migrate;
GRANT cyb691_ingestion, cyb691_analytics, cyb691_readonly TO svc_migrate WITH ADMIN OPTION;

-- one login per service, each a member of exactly one group role
CREATE ROLE svc_ingestion LOGIN PASSWORD :'ingestion_pw' IN ROLE cyb691_ingestion;
CREATE ROLE svc_analytics LOGIN PASSWORD :'analytics_pw' IN ROLE cyb691_analytics;
CREATE ROLE svc_readonly  LOGIN PASSWORD :'readonly_pw'  IN ROLE cyb691_readonly;

ALTER ROLE svc_readonly SET default_transaction_read_only = on;
REVOKE CONNECT ON DATABASE cyb691 FROM PUBLIC;
GRANT CONNECT ON DATABASE cyb691 TO svc_migrate, svc_ingestion, svc_analytics, svc_readonly;
SQL
echo "cyb691: service roles created"
