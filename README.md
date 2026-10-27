# DataLens identity

Keycloak configuration repository at `services/datalens-identity/`, remote
[DataLens identity](https://github.com/Agent-Tool-Use-Guardrail-Monitor-ATGM/datalens-identity).
Python is configuration/test tooling; there is no custom authentication API.

## Current progress

Step 2.1 is present on main at `e4a5a1e`; its required `tests` check succeeded.
The active rules require PRs, passing `tests`, up-to-date branches, and block
force pushes/deletions. The repository was initialized with its foundation;
no earlier merged feature PR was listed. All subsequent work uses the PR gate.

Step 2.2 was delivered through PR #1, merged at `9f6d675`, with required
`tests` successful. Step 2.3 was delivered through PR #2 (`50af5f5`); required tests passed on the PR.
Step 2.4 is locally verified on `feature/admin-realm-bootstrap`; its focused
acceptance test passed in 50.81 seconds. Full previous suites were not rerun.
Local account onboarding and new PR/CI delivery remain pending.
Steps 2.4вЂ“2.8 remain unimplemented.

## Tooling and configuration

Use Python 3.12 and this repository's own standard `.venv`. From the repository:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip check
python tools/check_config.py
```

Activation is optional: use `.\.venv\Scripts\python.exe` instead of `python`.
On this workstation the base is the ignored standalone CPython 3.12.15 runtime
at `../../.tools/python312/python/python.exe`; keep it while the environment uses
it. No Conda, uv or installable Python identity application is introduced.

`requirements.txt` is the only tooling dependency list. `pyproject.toml` configures
pytest/Ruff. [config/identity.toml](config/identity.toml) declares logical service
names, pinned images, local/test boundaries and future issuer/callback settings.
The checker rejects unknown/missing fields, unpinned images, noncanonical origins,
port collisions, shared storage targets and invalid secret references. Importing
it does no I/O; its CLI reads only an explicit/default contract, never dotenv.
The optional `--check-secrets` checks all declared process secrets, including the
future Keycloak administrator secret; it is not needed to start only PostgreSQL.

Playwright 1.64.1 pins Chromium revision 1248 for later browser tests. When needed,
use `python -m playwright install chromium` (Linux CI: add `--with-deps`). Browser
installation/login are not part of 2.2. The test gate currently needs Docker,
Python and the PostgreSQL image, without Azure, Keycloak, mail or LLM credentials.

## Start the local identity database

Docker Desktop's Linux engine must be running. Local credentials already exist
on this workstation in ignored `.env.postgres`; do not print or commit the file.
For a fresh checkout, create independent random bootstrap/application passwords:

```powershell
python tools/init_local_database.py
docker compose --env-file .env.postgres up -d --wait --wait-timeout 90
docker compose --env-file .env.postgres ps
```

The generator refuses to overwrite an existing file. Alternatively, fill the two
blank entries in [.env.postgres.example](.env.postgres.example) in an ignored
`.env.postgres`; keep distinct strong values. No Keycloak secret is generated.
Container initialization variables are not a password-rotation mechanism.

[compose.yaml](compose.yaml) starts only `identity-postgres`, scoped to
project/network `datalens-identity-local`. Its PostgreSQL 17 data uses named volume
`datalens-identity-local_identity-postgres-data`. There is **no published
host port**. A future Keycloak container on that network connects to
`identity-postgres:5432`, database `identity_db`, login `identity_app`.
It uses the application password, never bootstrap credentials. No service uses
agent database credentials, network attachments or storage mounts.

The bootstrap PostgreSQL login `identity_bootstrap` creates the database and
restricted `identity_app` login on fresh storage. The application owns its
identity database/schema and may perform the DDL needed by Keycloak. It has no
superuser, create-database, create-role, replication or bypass-RLS privileges and
no role memberships. PUBLIC database grants are removed; the application cannot
connect to the separate postgres/template1 databases. These are PostgreSQL roles,
not the future Keycloak application user/admin roles.

The [initialization script](docker/postgres/10-create-identity-role.sh) permits
only the local/test identity targets. It uses psql variable quoting/getenv for
passwords and fixed failure diagnostics. Git enforces LF endings for shell
scripts. The readiness probe authenticates the application login over TCP and
runs SELECT 1, so an available listener alone is insufficient. Host authentication
uses SCRAM; Linux/container TLS, production secret delivery and backup operations
remain deployment work. Docker administrators can access container environment.

A read-only smoke check confirmed `identity_db`/`identity_app`, no cluster-level
creation privileges and an empty public application schema. No mock business or
Keycloak tables were added to the local database.

## Restart, stop and credential changes

```powershell
docker compose --env-file .env.postgres restart
docker compose --env-file .env.postgres up -d --wait --wait-timeout 90
# To stop the development database while keeping its data:
docker compose --env-file .env.postgres down
```

Never add `--volumes`/`-v` to development cleanup. Changing image/container does
not require recreating the data volume. Initial scripts run only on empty
storage; later role/password changes need explicit supported administration and
matching client-secret updates. Do not delete a volume or assume editing dotenv
changes existing database credentials. Incomplete first-time initialization must
be diagnosed before retry; an existing data directory is not silently repaired.

## Run the database tests

[compose.test.yaml](compose.test.yaml) uses project `datalens-identity-tests`,
`identity_test_db`, runtime login `identity_test`, fixed synthetic passwords and
tmpfs. It publishes no ports and never mounts development data. From this repo:

```powershell
docker compose -p datalens-identity-tests -f compose.test.yaml up -d --wait --wait-timeout 90
$env:IDENTITY_DATABASE_TESTS = '1'
python -m pytest -q
Remove-Item Env:IDENTITY_DATABASE_TESTS
docker compose -p datalens-identity-tests -f compose.test.yaml down
python -m ruff check .
python -m ruff format --check tools tests
python -m pip check
```

Always remove the disposable fixture afterward, including when tests fail.
Missing opt-in skips marked database tests locally; CI must enable it and cannot
count skips as passes. Existing configuration tests still need no infrastructure.

Tests verify rendered configuration against the contract; real application
ownership, DDL and CRUD; denied database/role creation, role escalation and access
to other databases; rejected wrong passwords; and failure on missing bootstrap
configuration before any container is created. The persistence case uses the
actual development Compose file with a synthetic test override under a third
project, `datalens-identity-persistence-tests`. It creates a disposable named
volume, verifies a sentinel survives restart, and removes only that verified
project's volume. It never writes a sentinel into local identity_db.

The same required **`tests`** job now starts disposable PostgreSQL before pytest
and removes it with `if: always()`. Local results do not establish the new branch's
GitHub result; its PR still needs required checks on the latest revision.

## Workflow and boundary

Branch names use `<type>/<short-kebab-case-description>` and describe the task independently of the repository name. Do not automatically add a `datalens` or repository-name prefix. For example: `feature/postgres-foundation`, `fix/readiness-timeout`, `ci/run-tests`.

Every change uses a task branch and PR to main, with required tests passing and
an up-to-date branch. Never commit or push implementation directly to main. The
current feature branch is `feature/admin-realm-bootstrap`; nothing was staged,
committed, pushed or merged during this step. After its PR passes and merges,
request **2.3 РІР‚вЂќ Keycloak runtime, database connection and readiness** separately.
Parent workspace plans/index are outside this repository and its PR.

Sources: [official PostgreSQL image initialization](https://github.com/docker-library/docs/blob/master/postgres/README.md),
[PostgreSQL role attributes](https://www.postgresql.org/docs/17/role-attributes.html),
[psql variables/getenv](https://www.postgresql.org/docs/17/app-psql.html).


## Keycloak runtime вЂ” step 2.3

The runtime overlays preserve the database-only commands above. Include both
files whenever operating the full stack; the original database file alone does
not start Keycloak. From this repository:

```powershell
docker compose --env-file .env.postgres -f compose.yaml -f compose.runtime.yaml up -d --build --wait --wait-timeout 180
```

Open http://localhost:8081. Native readiness is at
http://localhost:9001/health/ready and liveness at `/health/live` on the same port.
Both published ports bind only to 127.0.0.1. Management health is not exposed on
the application port. This is local HTTP configuration, not cloud deployment.
The pinned derived image builds PostgreSQL, health and metrics support before
`start --optimized`. Its build context excludes credentials and source files.
`KC_CACHE=local` selects a single-node runtime; clustering is future deployment work.
A 768 MiB memory limit bounds this local container. Fresh initialization took
about 106 seconds on the development machine; readiness uses bounded polling.

Keycloak owns its generated tables in identity_db; existing storage is retained.
Its built-in master realm initializes automatically. No administrator, application
realm, user, OIDC client or email setup is provided by this step. The first-run
administrator prompt is expected; complete account bootstrap only in step 2.4.

To restart without deleting data:

```powershell
docker compose --env-file .env.postgres -f compose.yaml -f compose.runtime.yaml restart identity-keycloak
docker compose --env-file .env.postgres -f compose.yaml -f compose.runtime.yaml up -d --wait --wait-timeout 180
```

If PostgreSQL is unavailable, readiness must return 503. Restore the database,
then explicitly restart Keycloak and wait for readiness as above. Automatic
recovery without restart is not promised. Do not use `down --volumes` on local data.

Disposable verification (no local volume or real accounts):

```powershell
docker compose -p datalens-identity-tests -f compose.test.yaml -f compose.runtime.test.yaml up -d --build --wait --wait-timeout 180
$env:IDENTITY_DATABASE_TESTS = "1"
$env:IDENTITY_RUNTIME_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q
docker compose -p datalens-identity-tests -f compose.test.yaml -f compose.runtime.test.yaml down
```

Always perform test cleanup, including after failures. Runtime tests verify native
health and database checks, public issuer, management isolation, realm identity
across restart, failed startup with a wrong password, database-outage denial and
explicit restart recovery. The required CI job `tests` runs the complete stack.
Sources: [container build](https://www.keycloak.org/server/containers),
[native health and database metrics](https://www.keycloak.org/observability/health).


Internal service names are logical and omit the product prefix. Repository and
folder names retain `datalens-`; Compose projects retain environment scope.
Existing physical volume names are preserved to avoid replacing stored data.


Naming verification: identity passes all **88 tests without skips**, including
renamed runtime startup, restart, wrong-password and outage checks. Agent passes
all **154 tests without skips**. Ruff and diff whitespace checks pass. Disposable
test stacks were removed; persistent containers/data remain unchanged. Parent
plans remain outside service pull requests.


## Administrator and realm setup — step 2.4

Internal services are `identity-keycloak`, `identity-postgres` and
`identity-mailpit`. Repository names and upstream image/configuration keys retain
their existing names. The naming-only change did not trigger a full-suite rerun.

This step supplies an explicit one-time local setup tool, not another identity
API. After the new branch passes its PR/CI gate, run from this repository:

```powershell
.\.venv\Scripts\python.exe tools/bootstrap_identity.py --admin maxim-admin
```

Choose your own administrator name; `maxim-admin` is an example. The tool prompts
twice for a password of at least 16 characters. It never prints or saves that
password, a temporary password or tokens. It stops the single local identity
node, ensures PostgreSQL readiness, invokes Keycloak's supported offline
`bootstrap-admin user --optimized` with a randomly generated environment secret,
starts the runtime, creates the named master-realm administrator, verifies its
access, creates the application realm, and deletes the temporary administrator.
Bootstrap secrets are absent from normal runtime configuration. Admin API access
uses Keycloak's built-in master-realm admin-cli for this local administration
operation; this does not enable a password grant for the future application client.

If old containers still use previous service names, the tool refuses offline
bootstrap until they are stopped. Inspect this project's containers first:

```powershell
docker ps --filter label=com.docker.compose.project=datalens-identity-local
```

Stop only the displayed legacy identity runtime/database containers before
recreating the renamed services. Do not delete volumes. The explicit database
volume name preserves the existing identity data. Do not run this local tool
against a multi-node deployment or a database served by another Keycloak node.

Open http://localhost:8081/admin/ and choose the **master** realm to sign in with
the named platform administrator. This administrator can manage identity; future
application `admin` users do not automatically receive those permissions.

The new `datalens` realm disables public registration, requires verified email,
enables brute-force protection and a password policy (12 characters plus upper,
lower, digit and special character), and configures 5-minute access tokens,
30-minute idle sessions, 8-hour maximum sessions and 24-hour admin action links.
SMTP/activation and application roles/client remain future steps 2.5/2.6.
[config/realm.json](config/realm.json) contains only desired non-secret settings.
It is submitted through the Admin API, not imported on startup. Existing realms
are checked against these settings; mismatches require manual review. Existing
users/passwords are not overwritten. Ordinary startup never recreates accounts.

The tool is a one-time onboarding operation. If the named administrator already
exists, it refuses to reset that account. If setup partially fails, use the
console with an existing working administrator to inspect state. Do not blindly
rerun setup or delete the database. A failed handoff can leave temporary access;
remove it after verifying permanent access.

Recovery: stop **all** identity nodes, ensure the database remains available, and
use the same image/database configuration with Keycloak's supported command:

```powershell
# Set a fresh recovery secret in this terminal's environment without committing it.
# Choose a distinct temporary recovery username; never reuse a permanent username.
docker compose --env-file .env.postgres -f compose.yaml -f compose.runtime.yaml run --rm --no-deps -e KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD identity-keycloak bootstrap-admin user --optimized --username recovery-admin --password:env KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD --no-prompt
docker compose --env-file .env.postgres -f compose.yaml -f compose.runtime.yaml up -d --wait --wait-timeout 180
```

Obtain/set that secret through a protected local channel; do not paste passwords
into command arguments, chat or committed files. After recovery, verify a working
permanent administrator, remove the recovery administrator and clear the terminal
environment secret. Startup bootstrap variables cannot reset an existing master
administrator. No recovery secret belongs in the normal Compose environment.

Focused acceptance uses only disposable synthetic accounts:

```powershell
docker compose -p datalens-identity-tests -f compose.test.yaml -f compose.runtime.test.yaml up -d --build --wait --wait-timeout 180
$env:IDENTITY_RUNTIME_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/test_admin_bootstrap.py
docker compose -p datalens-identity-tests -f compose.test.yaml -f compose.runtime.test.yaml down
```

Run this acceptance case on fresh disposable storage, and always clean up after
failure. It is not a command to rerun against your real accounts. The existing
required `tests` CI job automatically collects the new acceptance test as well.
Sources: [offline bootstrap/recovery](https://www.keycloak.org/server/bootstrap-admin-recovery),
[administration](https://www.keycloak.org/docs/latest/server_admin/).

Focused verification: offline recovery, named-administrator access, temporary
account removal, realm defaults, repeated realm initialization, restart retention
and denied administration for an unrelated application-like role all passed.
Ruff/diff checks pass for the new files. Local real accounts were not created;
the operator must run the protected prompt-based setup command above.


## Application roles and OIDC client — step 2.5

Implemented on `feature/oidc-client`, based on merged administrator setup PR #3
(`c8f9e72`). Configure local identity after administrator onboarding:

```powershell
.\.venv\Scripts\python.exe tools/configure_oidc.py --admin maxim-admin
```

Use your actual administrator name. The password is prompted; no client secret,
password or token is printed/saved. The tool creates client `agent-api`, client
roles `user` and composite `admin` including `user`. These application roles grant
no Keycloak administration privileges. Assign roles to accounts through the
Keycloak console. Existing client configuration is checked for drift; existing
secrets are preserved. Repeated setup does not recreate accounts.

The confidential client requires a secret and authorization-code flow with S256
PKCE. Callback: `http://localhost:8000/auth/callback`; logout destination:
`http://localhost:8000/`. No wildcard redirect, browser CORS origin, password grant,
implicit grant, device/CIBA grant, service-account grant or offline scope is enabled.
Refresh rotation uses zero token reuse; concurrent refresh coordination and runtime
revocation verification belong to later steps. Basic/email scopes provide subject
and verified-email claims; custom mappers provide the intended `agent-api` audience
and `resource_access.agent-api.roles` in access tokens and introspection.

Retrieve the generated secret only through the protected Keycloak client
Credentials page; never commit or put it in frontend code. The agent backend's
secret storage, callback handler, session cookies, refresh and request authorization
are plan 3 work. No functional application callback endpoint exists yet. The test
callback server on port 18089 is isolated test tooling, not an agent API route.
Azure/Vercel callback origins are not registered until actual domains are known.

Current functionality: persistent independent PostgreSQL, Keycloak health and
recovery, one-time platform administrator/realm onboarding, and application
role/client configuration. The agent repository provides its existing FastAPI
foundation, settings, database/migrations and health checks. LLM statistics runs,
dataset tools, frontend UI, agent-side login enforcement and Kafka delivery are
not implemented. Email invitations/activation remain step 2.6.

Verification: the new focused acceptance uses real Chromium, synthetic accounts,
a loopback callback server and disposable identity storage. CI installs the pinned
browser before its existing required `tests` job. No live local users or clients
were changed by development/testing. Parent plans remain outside this repository.
Sources: [OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers),
[client administration](https://www.keycloak.org/docs/latest/server_admin/).


Step 2.5 verification — 23 October 2026: focused Chromium/real-Keycloak
acceptance passed in 32.60 seconds. Verified code/PKCE login with an exact loopback
callback, issuer/subject/audience/email claims, composite admin/user roles in
access tokens and introspection, denied Keycloak administration, rejected wrong
verifier/client secret/redirect, missing PKCE, implicit flow, password grants and
service-account grants. Repeated configuration preserves the client secret.
The test uses basic/email scopes, a real callback server and fresh administrator
authentication after realm initialization. Realm creation uses a bounded 60-second
test timeout. Ruff and whitespace checks pass. Full previous suites were not
rerun; required CI installs Chromium and runs all identity tests on the PR.
No local live users or clients were changed; operator application of the new
configuration remains explicit. No commit/push/PR was created. Stop before 2.6.
Parent plans are local workspace documents outside service repositories/PRs.


## Email capture and activation — step 2.6

Implemented on `feature/email-activation`, based on merged OIDC PR #4 (`57deb26`)
with successful required tests. Both runtime Compose files now include the pinned
`identity-mailpit` image. Its SMTP port 1025 is internal only; capture UI/API binds
to loopback at http://localhost:8025 (tests: http://localhost:18025). Capture storage
is ephemeral, with a 100-message limit. Mailpit does not deliver to real inboxes.

Start the existing complete local stack, then configure capture explicitly:

```powershell
docker compose --env-file .env.postgres -f compose.yaml -f compose.runtime.yaml up -d --build --wait --wait-timeout 180
.\.venv\Scripts\python.exe tools/configure_email.py --admin maxim-admin
```

Use your actual platform administrator name; the password is prompted. This sets
only local realm SMTP capture. It does not create users or send invitations.
No bootstrap secret enters normal runtime startup. All previous realm, role and
OIDC configuration remains owned by its existing setup steps.

To invite a teammate:

1. Sign in to the Keycloak console as a platform administrator; select `datalens`.
2. Create an enabled account with username, email, first/last name. Public signup
   stays disabled. Assign the intended `agent-api` client role, `user` or `admin`.
3. Require **Verify Email** and **Update Password**, then send an execute-actions
   email from that user's console page. The realm's admin-action lifetime is
   24 hours. Do not set/email a shared password or send tokens to the user.
4. Open the captured invitation in Mailpit; follow it to Keycloak and complete
   password setup. Check that required actions are cleared and email is verified.
5. The account can now complete the configured OIDC flow. Agent-side sessions and
   access enforcement still belong to plan 3; the callback is not implemented yet.

Pending activation is represented by required actions on an enabled account.
Disabling an account is an administrative denial, not an invitation state. Resend
an invitation when needed; do not assume resending invalidates every earlier link.
Never commit captured emails, invitation URLs, passwords or tokens. No browser
screenshots/traces or mail bodies are saved by the acceptance test.

For real delivery, configure the realm's SMTP settings with your selected
provider: verified sender/address/domain, SMTP host and port, required TLS mode,
authentication username and secret. Select STARTTLS or implicit TLS according to
that provider; never carry the local auth=false/TLS=false settings into a shared
production environment. Store/deploy secrets through the protected runtime/console
channel, never committed realm exports. Restrict console access and protect the
identity database/backups containing configuration. Verify actual inbox delivery,
spam handling and expiry before inviting real users. Provider/domain setup,
sending limits and real-inbox delivery remain unverified; no provider or paid
resource is provisioned by this step.

Focused synthetic acceptance:

```powershell
$env:IDENTITY_RUNTIME_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/test_email_activation.py
```

Start both test Compose files first, install the pinned Chromium browser as in CI,
and always remove the disposable test stack afterward. Never run this test
against local identity data. It captures synthetic invitations, completes browser
actions, then verifies OIDC/introspection email claims. Failure/expiry/reuse/resend
checks use only synthetic identities. Real live accounts were not modified.
Sources: [Mailpit API](https://mailpit.axllent.org/docs/api-v1/),
[Keycloak Admin API](https://www.keycloak.org/docs-api/latest/rest-api/index.html),
[account required actions](https://www.keycloak.org/docs/latest/server_admin/).


Step 2.6 evidence — 23 October 2026: implemented on `feature/email-activation`,
based on PR #4 (`57deb26`, required tests passed). Added pinned local/test Mailpit
with internal SMTP and loopback-only UI/API, ephemeral capture and a 100-message
limit; added explicit prompt-based local SMTP setup. Admin-created enabled users
receive VERIFY_EMAIL/UPDATE_PASSWORD action emails via the existing console.
No account-management API, automatic live invitations or real SMTP was added.

The new focused acceptance passed in **69.22 seconds** against real Keycloak,
Mailpit and Chromium. Synthetic tests cover invitation capture, expired links,
resend/new invitations, browser password setup, cleared required actions,
verified-email claims in access token/introspection, consumed-link reuse denial,
and SMTP failure without verification. Before activation the synthetic account
has required actions and no credential, so cannot complete password login.
Resend creates another invitation; no guarantee about invalidating earlier links
is inferred. No captured mail body, action URL or token was saved as an artifact.
Ruff/format/diff checks pass. Existing full suites were not rerun; the existing
required CI job collects the new acceptance test. Disposable test resources were
removed; live identity accounts/configuration/storage remain unchanged.

Local operator setup and console invitation steps are documented in the identity
README. Real SMTP requires provider-specific host/port/TLS/authentication,
verified sender/domain and secret injection; actual inbox delivery remains
unverified. No paid infrastructure or external messaging was used. Nothing was
staged, committed, pushed or merged. Parent plans remain outside service PRs.
Deliver this step through PR/required CI before requesting 2.7.


## Existing-token lifecycle contract — step 2.7

Implemented on `test/token-lifecycle`. Step 2.6 merge/check success and pull are
accepted from the user's confirmation; no GitHub checks or fetch were repeated.
This step adds focused integration tests, not agent authorization endpoints.

The pinned Keycloak 26.8.1 matrix keeps the original access token while changing
roles, group membership, composite roles, verified-email status and enabled state.
The initial matrix passed in 37.61 seconds. Introspection reconstructs current
roles/email status. Removing an extra direct user grant still allows that
permission through composite admin. Removing all grants removes that permission;
an active token by itself is insufficient to authorize an application request.

Disabling a user made the token inactive. Re-enabling that user made the original
token active again. To invalidate access permanently, disable the account and
terminate its identity sessions; re-enabling is not a substitute for logout.
Logout invalidated access and refresh. An expired access token was replaceable
while its identity session remained valid; reusing a rotated refresh token was
rejected. Wrong introspection credentials and unintended audiences were rejected.

**Policy revision — 27 October 2026:** plan 3 now validates JWTs locally with
trusted cached signing keys; no per-request introspection is required. The
provider matrix above is historical diagnostic evidence. Access-token claims
remain authoritative only until that token expires (maximum 300 seconds with
zero initial expiry leeway). Remote role/email/account/logout changes may lag
until then. Local application session logout remains immediate. Valid tokens
with still-trusted keys continue through identity outages; required refresh or
unknown/expired key trust fails safely if Keycloak is unavailable. No expired
or unverifiable token is accepted. The key trust lease is at most one hour, with
bounded/rate-limited refresh; signing-key compromise has a separate trust window.
See [the revised handoff](docs/identity_handoff.md).

Agent code still needs to implement this in plan 3. Cookies, encrypted server-side
tokens and coordinated refresh remain unchanged. Existing introspection tests
stay in CI as provider diagnostics; their passing results do not mean the agent
will make a network request on every authorization decision.

Focused synthetic run (start both test Compose files first):

```powershell
$env:IDENTITY_RUNTIME_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/test_token_lifecycle.py
```

Use disposable storage only. No tokens are saved, printed or added to artifacts.
No live identity accounts or agent access controls were changed by this step.
Source: [OIDC introspection](https://www.keycloak.org/securing-apps/oidc-layers),
[version-pinned introspection source](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java).


Step 2.7 verification — 24 October 2026: the extended focused acceptance passed
in **87.38 seconds** against pinned Keycloak 26.8.1, disposable PostgreSQL and real
Chromium. The same original access token was inspected after direct-role,
group-membership, composite-role, verified-email and enabled-state changes.
Removing an extra direct user grant retained permission through composite admin;
removing all remaining grants removed it. Logout invalidated access and renewal.
The wrong introspection client secret and unintended audience were rejected.

An access token with an observed three-second issued lifetime became inactive
under bounded polling, then its valid refresh credential produced a valid
replacement. Reusing the rotated refresh credential failed. A newly expired
identity session could not be renewed. Stopping the disposable identity service
produced an HTTP transport error with no claims; restart readiness succeeded.
Re-enabling a disabled user restored the original token's activity: terminate
identity sessions as well when permanent invalidation is intended.

An earlier fixed four-second expiry wait failed once; the final test verifies
issued lifetime and polls within a 15-second bound instead. Earlier repeated
fixture runs encountered setup timeouts and an administrator-token failure.
Their exact underlying resource/session cause was not established; no product
behavior was weakened to bypass them. Docker was stopped during investigation,
then restarted with permission for focused verification. Full previous suites
and GitHub merge/check verification were not repeated, as requested. Prior step
2.6 delivery is accepted from the user's confirmation.

Actual agent local-JWT authorization, bounded-delay behavior, malformed/missing-claim
fault injection, token storage and coordinated refresh remain plan 3 work. This
identity acceptance proves provider behavior; it does not implement the agent's
fail-closed authorization path. No live user data or production configuration
was modified. Ruff/format/diff checks passed; disposable test resources were
removed. Nothing was staged, committed, pushed or merged. Parent plans remain
outside service Git repositories and pull requests. Deliver this step through
PR/required CI, then request 2.8 separately.


## Plan 2 completion and integration handoff — step 2.8

Current branch: `docs/recovery-handoff`. Prior step 2.7 merge/check success and
pull are accepted from the user's confirmation; no remote checks were repeated.

- [Non-secret plan 3 contract](docs/identity_handoff.md): pinned images, endpoints,
  issuer/audience/roles, callbacks, lifetimes, secret transfer and access rules.
- [Reproduction/recovery runbook](docs/recovery.md): fresh/existing setup, reviewed
  configuration updates, recovery, rotation, backup/upgrade/rollback boundaries.

The new retained-storage acceptance passed in **98.70 seconds**. A fresh isolated
named-volume instance completed administrator/realm/client/SMTP setup; container
removal and recreation retained administrator login, realm/account IDs and the
client secret. Reapplying managed settings preserved them. Its guarded disposable
volume was removed; local data was not touched. Ruff/format/whitespace checks pass.
The existing required `tests` job automatically collects this test. Full previous
suites were not rerun, and new PR/CI delivery remains pending. No live local
onboarding, backup restore, image upgrade, production SMTP or cloud deployment was
performed. Actual agent-side login/access enforcement remains plan 3 work.

Identity configuration, activation and lifecycle behavior are now ready for that
integration after this documentation/test step passes its PR gate. Stop before
plan 3; create it only when requested. Nothing committed or pushed by this step.
Parent planning files remain outside service Git repositories/pull requests.


Documentation-only authorization revision — 27 October 2026: local token
validation replaces mandatory live introspection. No identity runtime, role
mapping, token lifetime or completed diagnostic test changed. Both public-key
caching and fresh token validation are required; login/refresh still depend on
Keycloak. Service docs use `docs/local-token-validation`; parent plans are outside Git.
