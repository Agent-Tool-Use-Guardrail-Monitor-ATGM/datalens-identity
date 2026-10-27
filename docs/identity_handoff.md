# Identity integration handoff

Updated: 27 October 2026. Plan 2.8. No live secrets or tokens are included.

## Version and configuration authority

`config/identity.toml` records the exact upstream versions and SHA-256 manifests:

| Runtime | Pinned version |
|---|---|
| Keycloak | 26.8.1, built with PostgreSQL, health and metrics support |
| PostgreSQL | 17.11-bookworm |
| Mailpit | v1.32.0, local/test capture only |

Copy image digests from that tracked contract when building deployment assets;
do not replace them with floating tags. `config/realm.json` owns realm defaults;
`tools/configure_oidc.py` owns client/role configuration. Python tooling uses its
service-local `.venv` and pinned `requirements.txt`. The identity database is not
accessible to the agent database or agent migrations.

## Local protocol contract

| Setting | Value |
|---|---|
| Issuer | `http://localhost:8081/realms/datalens` |
| Discovery | `http://localhost:8081/realms/datalens/.well-known/openid-configuration` |
| Client ID / access-token audience | `agent-api` |
| Authorization | `http://localhost:8081/realms/datalens/protocol/openid-connect/auth` |
| Token / refresh | `http://localhost:8081/realms/datalens/protocol/openid-connect/token` |
| Optional diagnostic introspection | `http://localhost:8081/realms/datalens/protocol/openid-connect/token/introspect` |
| Logout | `http://localhost:8081/realms/datalens/protocol/openid-connect/logout` |
| JWKS | `http://localhost:8081/realms/datalens/protocol/openid-connect/certs` |
| Agent callback | `http://localhost:8000/auth/callback` |
| Post-logout destination | `http://localhost:8000/` |
| Access / idle / maximum session | 300 / 1800 / 28800 seconds |
| Administrator action-link lifetime | 86400 seconds |

Use discovery to obtain endpoints and verify its issuer against the configured
issuer. These HTTP addresses are a loopback development exception. Hostname,
scheme and port must agree through browser login, code exchange, discovery and
JWT checks. Containerized agent routing to this public issuer remains a plan 3/10
integration check; never fix connectivity by disabling issuer validation or
accepting a different internal issuer. No cloud/Vercel callbacks are registered.
The callback is currently a contract, not an implemented agent endpoint.

The client is confidential: authorization code plus S256 PKCE, exact callbacks,
no implicit/password/device/CIBA/service-account grants, no offline scope, and no
wildcard redirects or web origins. Request `openid email`; the client supplies
basic/email scopes. Refresh tokens rotate with maximum reuse zero. Serialize
refresh per session and save replacements atomically; do not retry an old token
blindly after a lost refresh response. Reauthentication may be required.

## Secrets and claims

Retrieve the client secret from the realm's `agent-api` client Credentials page
using a platform administrator. Transfer through a protected local/runtime secret
channel; never put it in browser code, Git, logs, exported fixtures or this file.
Plan 3 must define the backend secret reference and encrypted session storage.
Platform administrators are separate from application administrators.

## Planned authorization policy — revised 27 October 2026

Validate the access JWT locally using trusted cached keys, configured RS256,
exact issuer/audience/subject, iat/exp, maximum 300-second lifetime and strict
role/email claim types. Initial expiry leeway is zero. Do not introspect ordinary
protected requests. An ID token does not authorize API operations. These are
implementation requirements for plan 3, not completed agent functionality.

| Access-token claim | Required meaning |
|---|---|
| `iss` | Exact configured issuer |
| `aud` | Contains exact `agent-api` audience, not a substring |
| `sub` | Stable identifier for issuer/subject ownership |
| `iat`, `exp` | Valid issuance/expiry; lifetime at most 300 seconds |
| `email_verified` | Boolean true, not string truthiness |
| `resource_access["agent-api"]["roles"]` | Permissions from this validated token's signed snapshot |

The JWT need not contain `active`; that field belongs to optional introspection.
`admin` includes `user` but not identity administration. Role/email/account changes
and remote Keycloak logout may take until current token expiry to affect new
application decisions. Fresh token issuance/refresh must reflect provider changes
or be rejected (verify in plan 3 integration). Immediate remote revocation is no
longer required. Local application logout/revocation still ends its cookie session
immediately. Existing in-flight effects cannot be undone.

Cache trusted discovery/JWKS per API process, with a one-hour maximum trust lease.
Known keys within the lease allow valid-token requests without Keycloak calls.
Refresh on lease expiry/unknown kid with bounded, coalesced/rate-limited retrieval;
never fetch token-supplied URLs. Unknown keys or expired trust cannot authorize
when the provider is unavailable. A known still-trusted key remains usable during
an outage, but JWT/session expiry is never extended. Cold starts without trusted
keys, login and required refresh still need Keycloak. Compromised signing-key
removal is subject to this separate cache-trust window, not guaranteed five-minute
emergency invalidation. No new key-cache service or revocation broker is planned.

Refresh only when token expiry and the valid local session permit it. Validate
replacement claims locally before authorizing. Definitively rejected renewal
requires login; failed required refresh/key retrieval returns a safe unavailable
response rather than accepting expired/unverifiable tokens. A missing operation
role or unverified email denies access without a refresh loop. Keep encrypted
backend tokens, cookie/CSRF protection and atomic refresh coordination unchanged.

Existing identity introspection mappings/tests remain optional diagnostics.
Their observations are provider capabilities, not a mandatory request-time
service dependency. They do not demonstrate immediate invalidation of an offline
JWT verifier.

## Acceptance and ownership limits

Steps 2.4-2.7 exercised real Keycloak, synthetic accounts, Chromium and Mailpit:
administrator handoff, required-action activation, PKCE, role/group/composite
changes on the same token, email/account changes, audience checks, logout,
refresh rotation/expiry and service outage. See README evidence for measured
runs. Step 2.8 adds fresh and retained-storage reproduction in an isolated named
volume. CI's required `tests` job installs Chromium and collects all tests with
integration flags enabled; unavailable fixtures fail rather than count as passes.

Plan 3 still owns login/callback routes, browser cookies/CSRF, encrypted token
storage, refresh coordination, ownership and actual local-JWT authorization,
including bounded key caching, outage continuity and malformed-token/key tests. Plan 7 owns queued/running-job
checks and safe fallback. Plans 8/10 own frontend/public routing, DNS, TLS,
production SMTP, secret distribution, backups and cloud release automation.
Nothing in this handoff establishes production readiness or real inbox delivery.

[Recovery and reproduction](recovery.md).


Exact upstream image references from the tracked contract:

```text
quay.io/keycloak/keycloak:26.8.1@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b
postgres:17.11-bookworm@sha256:858bb5e98eed02eb8cafbcdc007f9a65d1b613972028944a8ec2133ccaf80d27
axllent/mailpit:v1.32.0@sha256:0790692be935ea4420d085694f7985b1f692ca6a8771ab0e0bd8ba75ac180498
```
