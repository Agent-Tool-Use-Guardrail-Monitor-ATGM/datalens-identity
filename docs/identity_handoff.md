# Identity integration handoff

Updated: 24 October 2026. Plan 2.8. No live secrets or tokens are included.

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
| Introspection | `http://localhost:8081/realms/datalens/protocol/openid-connect/token/introspect` |
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

Validate signature using discovered keys, allowed algorithms, issuer, audience,
expiry and subject. Then make a live authenticated introspection request for each
authorization decision. Reject missing/malformed claims, wrong issuer/audience,
inactive tokens and unavailable identity service. No cached positive decisions.
An ID token does not authorize agent API access.

| Claim | Required meaning |
|---|---|
| `active` | Boolean true in successful introspection; necessary but insufficient |
| `iss` | Exact configured issuer |
| `aud` | Contains exact `agent-api` audience, not a substring |
| `sub` | Stable user identifier used for ownership, not username/email |
| `email_verified` | Boolean true, not string truthiness |
| `resource_access["agent-api"]["roles"]` | Current effective client roles |

`admin` includes `user`; neither grants Keycloak administration. Deny operations
whose required role is absent even if active=true. Use current introspection
roles/email rather than stale embedded JWT values. A disabled account rejects
active use, but re-enabling can reactivate its existing token. For permanent
invalidation, terminate identity sessions as well. Session logout blocks renewal.
Expiry of an access token permits refresh only while the identity session remains
valid; expired/revoked sessions and rotated-token reuse require login.

## Acceptance and ownership limits

Steps 2.4-2.7 exercised real Keycloak, synthetic accounts, Chromium and Mailpit:
administrator handoff, required-action activation, PKCE, role/group/composite
changes on the same token, email/account changes, audience checks, logout,
refresh rotation/expiry and service outage. See README evidence for measured
runs. Step 2.8 adds fresh and retained-storage reproduction in an isolated named
volume. CI's required `tests` job installs Chromium and collects all tests with
integration flags enabled; unavailable fixtures fail rather than count as passes.

Plan 3 still owns login/callback routes, browser cookies/CSRF, encrypted token
storage, refresh coordination, ownership and actual fail-closed enforcement,
including malformed-response fault injection. Plan 7 owns queued/running-job
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
