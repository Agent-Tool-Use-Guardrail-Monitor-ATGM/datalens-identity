# DataLens identity

Renamed from the original identity folder to `services/datalens-identity/` on
23 October 2026. The service-local environment and command launchers were repaired
at the new path. All owned service names now begin with `datalens-`; the
`[services]` section of the TOML contract enforces unique DNS-safe names.

Separate Keycloak configuration repository, intended GitHub name
`datalens-identity`, with source kept at `services/datalens-identity/` in the DataLens
workspace. Keycloak is the identity runtime; Python here is configuration/test
tooling only. There is no custom authentication API or password database code.

## Current scope — step 2.1

The foundation defines pinned image references, local/test isolation and required
secret names in [config/identity.toml](config/identity.toml). Its checker rejects
unknown fields, cross-service/shared database targets, persistent test storage,
noncanonical/non-loopback origins, overlapping/invalid ports and unpinned images.

This is a desired configuration contract, not Compose or a configured realm.
No container, PostgreSQL database, Keycloak account/realm, invitation, OAuth client
or cloud resource is created in 2.1. Database services start in 2.2; Keycloak starts
in 2.3. Later steps add native login, admin/user roles and email activation.

## Python environment and checks

Use Python 3.12 with a separate standard `.venv` in this repository. From its root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip check
python tools/check_config.py
python -m pytest -q
python -m ruff check .
python -m ruff format --check tools tests
```

If activation is unavailable, use `.\.venv\Scripts\python.exe` for `python`.
On the current workstation, the ignored standalone Python runtime is at
`../../.tools/python312/python/python.exe`; it created this service's environment
with `-m venv .venv`. Keep the base runtime while the environment uses it. The
agent's environment is independent and was not changed. No Conda or uv is used.

`requirements.txt` is the only dependency list. `pyproject.toml` configures tests
and Ruff; this repository is not an installable application package. The checker
uses Python's standard TOML parser and can also run before dependencies are
installed. Importing it does not read configuration or contact infrastructure.

Playwright 1.64.1 pins its browser revisions. For later real login tests, install
only Chromium with `python -m playwright install chromium`; Linux CI will use
`python -m playwright install --with-deps chromium` when those tests are added.
The initial configuration-only CI job does not need a browser or Docker. Browser
installation must remain aligned with the requirements version; do not reuse an
arbitrary system Chrome binary as the test browser.

Resolution check on 23 October 2026: Playwright selected Chromium
156.0.8078.4/revision 1248 (including its headless shell), FFmpeg revision 1013
and Winldd revision 1007 for Windows. Only the installation dry run was needed
for 2.1; no browser was downloaded or launched, and no login is claimed tested.

## Configuration and secrets

`python tools/check_config.py` validates the committed structural contract. Its
default path is relative to the script, not the terminal's working directory.
`--config <path>` selects an explicit alternative. It returns 0 for valid input
and 1 for configuration failure; diagnostics do not print supplied values,
connection strings, secrets or parser tracebacks.

`.env.example` declares three blank secret inputs: PostgreSQL bootstrap,
Keycloak database login and temporary Keycloak administrator passwords. Put real
values only in ignored local configuration or deployment secret injection. No
local secrets were generated, and the checker never loads dotenv automatically.
With those variables explicitly supplied in the process environment, use:

```powershell
python tools/check_config.py --check-secrets
```

The additional check requires distinct values of at least 16 non-padding
characters and rejects common placeholder prefixes. It does not prove password
strength or database/account connectivity. CI uses synthetic values in tests;
it needs no repository secrets. OIDC client and real-SMTP secrets will be added
with their owning implementation steps. Do not commit user/realm exports,
captured mail, invitation URLs, browser traces or token material.

## Intended container boundaries

| Contract | Development | Disposable tests |
|---|---|---|
| Compose project | `datalens-identity-local` | `datalens-identity-tests` |
| Realm | `datalens` | `datalens-test` |
| Database / runtime role | `identity_db` / `identity_app` | `identity_test_db` / `identity_test` |
| Storage | Own named PostgreSQL volume | Own tmpfs database; never development mounts |
| Public identity origin | `http://localhost:8081` | `http://localhost:18081` |
| Management host port | Loopback 9001 | Loopback 19001 |
| Mailpit UI/API host port | Loopback 8025 | Loopback 18025 |
| Future callback origin | `http://localhost:8000` | `http://localhost:18089` |

Later Compose files create independent networks per project. Keycloak reaches
its own `datalens-identity-postgres:5432` and `datalens-identity-mailpit:1025` on its network;
PostgreSQL/SMTP need no host port. Management maps internal 9000 only to loopback.
Browser-visible issuer origins remain canonical localhost addresses; an internal
Docker hostname must not replace the token issuer. Production HTTPS/DNS and
container access to the public issuer are later integration/deployment checks.

The agent database, volume and credentials are never identity inputs. Keycloak
will manage only its identity schema. Database initialization, least-privilege
roles, health checks and persistent restart behavior belong to 2.2/2.3.

## Verified image baselines

Manifest-index SHA-256 digests were resolved from the official registries on
23 October 2026 and are recorded with exact tags in the TOML contract:

- Keycloak **26.8.1**, the current official stable release at verification.
- PostgreSQL **17.11-bookworm**; PostgreSQL 17.x is in Keycloak's supported range.
- Mailpit **v1.32.0**, for future development/test email capture only.

The tags and manifest references were checked without pulling/running the images.
Recent public Keycloak advisories were reviewed alongside the stable release;
this is not a full container vulnerability scan or production security sign-off.
Recheck advisories and digest choices before runtime/cloud deployment. Do not
enable unneeded SAML, LDAP or dynamic client-registration features.

Sources: [Keycloak downloads](https://www.keycloak.org/downloads),
[supported databases](https://www.keycloak.org/server/supported-configurations),
[public advisories](https://github.com/keycloak/keycloak/security/advisories),
[Mailpit releases](https://github.com/axllent/mailpit/releases),
[Playwright releases](https://github.com/microsoft/playwright-python/releases).

## GitHub delivery and test gate

Every change uses a task branch and PR to `main`; never commit or push
implementation directly to main. Current local branch:
`feature/identity-foundation`. No implementation commit or push has been made.

The user confirmed that the remote has not been created yet. Create
`datalens-identity` in the team organization, initializing it with only a README
on main, then provide its URL. The local feature branch currently has no commits;
connect the initialized main as its base while preserving these files **before**
committing. Do not create an unrelated root implementation commit or discard local
files to resolve the initial README overlap. No remote URL is configured yet.

The tests-only [.github/workflows/ci.yml](.github/workflows/ci.yml) runs job
**`tests`** on all PRs to main and main pushes, using Python 3.12/Ubuntu 24.04,
read-only permissions and a ten-minute limit. It installs tooling and runs the
real configuration tests; no infrastructure/secrets or browser download is needed.
Later steps extend this same gate with disposable services and login tests.

After the first PR runs, configure main's rules to require PRs and the **`tests`**
status check, require an up-to-date branch, and restrict bypass/direct pushes.
Merge only after required checks pass for the latest revision. Local verification
does not prove GitHub CI execution or branch protection. Repository creation,
initial main attachment, first PR and required-check configuration remain delivery
items until verified. Parent workspace plans are not included in this repository.

## Local verification — 23 October 2026

Created a fresh service-local environment with Python 3.12.15 and installed the
four pinned tooling dependencies. After the folder/name update, **70 tests pass
without skips**, including prefix/syntax/uniqueness checks. Ruff lint
and formatting passed, and `pip check` reported no broken requirements.
The structural CLI passed without secrets or infrastructure. Explicit
secret-check failures and success were verified using synthetic inputs, without
logging their values. Image manifest references were resolved from registries;
the Playwright browser revision was resolved through its dry run.

No Compose service, database, identity server, real account, mail delivery or
browser-login behavior was tested at this stage. The repository remains on the
uncommitted `feature/identity-foundation` branch with no main implementation
commit. Finish remote/base/PR/required-CI setup before 2.2.
