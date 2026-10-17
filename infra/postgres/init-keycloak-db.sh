#!/bin/sh
# Runs once on first init of the data volume. Keycloak gets its own role and database,
# so the app role can never read identity-provider tables and vice versa.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v kc_user="$KEYCLOAK_DB_USER" -v kc_pass="$KEYCLOAK_DB_PASSWORD" -v kc_db="$KEYCLOAK_DB_NAME" <<'SQL'
CREATE ROLE :"kc_user" LOGIN PASSWORD :'kc_pass';
CREATE DATABASE :"kc_db" OWNER :"kc_user";
REVOKE CONNECT ON DATABASE :"kc_db" FROM PUBLIC;
SQL
