#!/bin/sh
# Runs once on first init of the data volume (after the Keycloak script).
#
#   casefile_migrator  owns the schema objects; used by migrations only, never by the running API
#   casefile_app       what the API connects as: not owner, not superuser, no BYPASSRLS, minimal grants (granted by migrations)
#
# Databases: $POSTGRES_DB (dev data) and ${POSTGRES_DB}_test (automated tests, wiped freely).
# Existing dev volumes do not re-run this: `docker compose down -v` to pick it up.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v mig_pass="$CASEFILE_MIGRATOR_PASSWORD" -v app_pass="$CASEFILE_APP_PASSWORD" \
  -v dev_db="$POSTGRES_DB" -v test_db="${POSTGRES_DB}_test" <<'SQL'
CREATE ROLE casefile_migrator LOGIN PASSWORD :'mig_pass' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE ROLE casefile_app LOGIN PASSWORD :'app_pass' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION CONNECTION LIMIT 25;

-- guard rails that apply to every connection of the app role, whatever the pool does
ALTER ROLE casefile_app SET statement_timeout = '5s';
ALTER ROLE casefile_app SET lock_timeout = '3s';
ALTER ROLE casefile_app SET idle_in_transaction_session_timeout = '15s';

CREATE DATABASE :"test_db" OWNER casefile_migrator;
ALTER DATABASE :"dev_db" OWNER TO casefile_migrator;
SQL

for db in "$POSTGRES_DB" "${POSTGRES_DB}_test"; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" -v db="$db" <<'SQL'
REVOKE CONNECT ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO casefile_migrator, casefile_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO casefile_app;
GRANT ALL ON SCHEMA public TO casefile_migrator;
SQL
done
