# Identity reproduction and recovery

Updated: 24 October 2026. Applies to the local single-node topology. Read the
[agent integration contract](identity_handoff.md) before wiring another service.
Commands run from this repository. Persistent storage is never a test fixture.

## Fresh local setup

1. Create `.venv`, install `requirements.txt`, and start Docker Desktop. Existing
   local environment/setup commands are in the repository README.
2. Run the secret generator once; if `.env.postgres` exists, keep it. The tool
   refuses to overwrite it. Never paste its contents into logs or tickets.
3. Start the database/runtime/capture stack and use bounded readiness, then run
   the explicit administrator bootstrap. Choose a named administrator and enter
   its password at the protected prompts.
4. Configure the client/roles and local email capture through the explicit tools.
   Invite synthetic local users through the console and confirm activation.

```powershell
.\.venv\Scripts\python.exe tools/init_local_database.py
docker compose --env-file .env.postgres -f compose.yaml -f compose.runtime.yaml up -d --build --wait --wait-timeout 180
.\.venv\Scripts\python.exe tools/bootstrap_identity.py --admin maxim-admin
.\.venv\Scripts\python.exe tools/configure_oidc.py --admin maxim-admin
.\.venv\Scripts\python.exe tools/configure_email.py --admin maxim-admin
```

`maxim-admin` is an example; substitute your named administrator. Do not run the
bootstrap again to reset an existing account. Existing legacy service containers
must be stopped before recreating renamed services; the bootstrap tool rejects
running legacy/additional identity nodes. Preserve the physical volume named
`datalens-identity-local_datalens-identity-postgres-data`.

## Existing storage and configuration changes

Ordinary start/restart uses the same `.env.postgres`, Compose project and volume.
PostgreSQL becomes ready before Keycloak; Keycloak updates its own schema; native
ready health must return success before accepting requests. Mailpit is independent
capture tooling. `down` removes containers/network; **never add `--volumes` to a
local-data cleanup command**. Do not change project/volume names to fix readiness.

On retained storage, do not rerun the secret generator or administrator bootstrap.
Sign in with the existing named administrator. Realm setup validates its owned
settings rather than overwriting accounts. The OIDC setup checks client drift,
preserves its generated secret and applies its owned role/scope/rotation settings.
Review intended changes before reapplying it. Local email setup deliberately
replaces SMTP settings with Mailpit; never run it against real SMTP configuration.

Realm import is initialization tooling, not reconciliation. Startup does not use
`--import-realm`. Do not replace live realms with exports to apply settings.
Changes belong through reviewed Admin API/console configuration. An export may
contain credentials and does not capture all operational state, including sessions;
it is not a substitute for a database backup.

## Administrator recovery

Try an existing working platform administrator first. For lost administrator
access, stop **every Keycloak node** using this database. Keep PostgreSQL available.
Use the pinned image with the same database settings and the supported offline
`bootstrap-admin user --optimized` command described in README. Supply a newly
generated temporary recovery password through an environment reference, never
literal command arguments. Use a new temporary username, not an existing user.
Start the server, verify a permanent administrator, remove temporary recovery
access and clear the terminal secret. For MFA-locked recovery, use the supported
service-account recovery procedure from the official guide; do not disable realm
security or delete its database. No recovery account/secret belongs in normal
runtime startup. Startup bootstrap variables do not reset existing administrators.

## Secret rotation and upgrades

| Material | Safe sequence |
|---|---|
| Client secret | Coordinate maintenance with the backend owner; regenerate through the protected console; replace the backend secret; reload and verify token exchange/refresh. Optional introspection remains a diagnostic. This baseline does not promise dual-secret overlap. Existing sessions may require login. Terminate sessions on compromise. |
| PostgreSQL application/bootstrap login | Change the actual database role password through protected administration, then update the matching ignored/deployment secret and restart affected connections. Startup environment variables and fresh-storage init scripts do not rotate existing SQL passwords. Do not delete storage. |
| Platform administrator password | Change through authenticated account/console recovery, confirm a working administrator and invalidate affected sessions as appropriate. Keep platform and application roles separate. |
| Signing keys | Back up first, use a reviewed Keycloak key-rotation procedure and retain verification keys for the supported transition. Plan 3 must refresh JWKS safely; no signing-key rotation was exercised here. |

Before Keycloak/PostgreSQL upgrades, take and protect a database backup, preserve
the matching image digests/configuration and test the candidate against an isolated
restore. Pin the reviewed target; exercise migration, login, claims, activation,
revocation/refresh and recovery before rollout. Restoring an older application
image does not reverse database-schema changes. A rollback may require restoring
the matching pre-upgrade database with the service stopped.

Backups contain personal data, password hashes, client secrets and signing keys.
Store them encrypted with restricted access outside Git/CI artifacts; protect
associated runtime secrets separately. A PostgreSQL custom-format dump or provider
backup must include the complete identity database. Preserve/recreate the required
database roles and ownership as well. When copying a binary dump on Windows, use
an in-container output file plus `docker cp`, not text redirection through
PowerShell. Validate backups by restoring into isolated storage with no route to
production SMTP. Restore/upgrade automation and production retention belong to
plan 10; this step does not claim an executed backup restore or image upgrade.

## Reproduction proof and CI boundary

`tests/test_handoff.py` derives the pinned runtime from the test Compose contract,
then runs under `datalens-identity-handoff-tests` with its own explicitly named
volume and loopback ports 28081/29001/28025. It starts fresh, creates a named
administrator and realm/client/SMTP setup, removes containers while retaining the
volume, starts again and verifies the same administrator password, IDs and client
secret. Reapplying managed settings must preserve accounts and secret. Cleanup
is guarded by that exact disposable project/volume; it cannot remove local data.

```powershell
$env:IDENTITY_RUNTIME_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/test_handoff.py
```

The existing required `tests` workflow collects this case with the other identity
tests. It uses disposable PostgreSQL/Keycloak/Mailpit, installs Chromium, enables
integration flags and always cleans its base fixture. Missing integration support
must fail CI rather than pass through skips. Local reproduction is evidence, not
proof of an unpublished PR's CI result. This step does not run plan 3 or modify
live local accounts/storage.

Sources: [realm import/export limits](https://www.keycloak.org/server/importExport),
[administrator recovery](https://www.keycloak.org/server/bootstrap-admin-recovery).


Authorization revision — 27 October 2026: ordinary agent requests will validate
JWTs locally using bounded cached keys. Identity disable/logout is not guaranteed
to reject an already issued token until expiry at an offline verifier. During
compromise response, invalidate local application sessions where possible and
account for cached signing-key trust separately. No new revocation service or
backchannel dependency was introduced; see the updated integration handoff.
