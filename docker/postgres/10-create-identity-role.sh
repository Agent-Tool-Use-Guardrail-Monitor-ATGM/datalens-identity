#!/usr/bin/env bash
# Sourced by the official entrypoint only when the data directory is empty.
(
set -Eeuo pipefail

case "${POSTGRES_DB:-}:${IDENTITY_DB_USER:-}" in
  identity_db:identity_app|identity_test_db:identity_test) ;;
  *) echo 'Identity database initialization rejected an unexpected target.' >&2; exit 1 ;;
esac

if [ -z "${IDENTITY_DB_PASSWORD:-}" ]; then
  echo 'Identity database initialization requires an application password.' >&2
  exit 1
fi

# Read the password with psql getenv, not command arguments or interpolated SQL.
# Suppress secret-bearing SQL on errors; return a fixed diagnostic instead.
if ! psql -X --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set=ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL'
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
\getenv app_user IDENTITY_DB_USER
\getenv app_password IDENTITY_DB_PASSWORD
\getenv identity_database POSTGRES_DB
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';
ALTER DATABASE :"identity_database" OWNER TO :"app_user";
REVOKE ALL ON DATABASE :"identity_database" FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO :"app_user";
SQL
then
  echo 'Identity database initialization failed; inspect configuration without exposing secrets.' >&2
  exit 1
fi
)
