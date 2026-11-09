# Public frontend OAuth and Account Console: step 3.8.3

Updated 9 November 2026. This is an additive identity configuration tool, not
the agent HTTP authentication cutover. The existing confidential `agent-api`
client and its secret are preserved. No development or cloud realm is changed
by importing the tool or starting containers.

## Explicit administrator setup

After the existing realm/API roles are configured, run from this repository:

```powershell
python tools/configure_frontend.py --admin YOUR_ADMIN --frontend-origin http://localhost:5173
```

The administrator password is prompted without echo. For hosted addresses,
replace these placeholders with your actual separately provisioned origins:

```powershell
python tools/configure_frontend.py --admin YOUR_ADMIN --hosted --identity-origin https://identity.example --frontend-origin https://web.example --realm datalens
```

`--hosted` requires HTTPS for both origins. Origins have no trailing slash, path,
query, fragment, wildcard, credentials or explicit default port. Loopback HTTP
is supported only without `--hosted`. The existing local deployment validators
are unchanged. DNS, TLS, proxy trust and Azure deployment are not provisioned here.

The tool creates `agent-web` only if absent, then checks its security settings.
An identical rerun succeeds; conflicting client configuration fails for manual
review instead of silently rewriting callbacks or grants. It allows only the
existing `agent-api` user/admin role scope, without assigning roles to users.
It also explicitly enables native username editing and realm-wide refresh-token
rotation with zero reuse. Review this realm-level change before applying to a
shared deployment; clients must serialize refreshes and retain each new token.

## Frontend contract

| Setting | Value |
|---|---|
| Client ID | `agent-web`, public, no client secret |
| Login | Authorization code with PKCE S256 |
| Callback | Exactly `FRONTEND_ORIGIN/auth/callback` |
| Post-logout redirect | Exactly `FRONTEND_ORIGIN/` |
| Allowed web origin | Exactly `FRONTEND_ORIGIN` |
| Scopes requested | `openid email profile` |
| Access-token audience | Includes `agent-api` |
| Authorized party | `agent-web` |
| Application role claim | `resource_access.agent-api.roles` |
| Disabled | Implicit/password/service-account/device/CIBA grants, optional scopes |

Use a maintained OIDC client library. Keep access and refresh tokens only in
browser memory; never localStorage, sessionStorage, URLs or application logs.
Validate OAuth state and OIDC nonce, exchange the code with its PKCE verifier,
and serialize refreshes. Page reload may redirect through Keycloak SSO again.
Handle expired/invalid refresh tokens by clearing memory and requiring login.
No identity administrator or broker credentials belong in frontend builds.

After the later HTTP cutover, send access tokens to the agent as Bearer headers.
The agent checks signature, issuer, audience, authorized party, verified email,
roles and expiry. Current agent cookie endpoints/workers remain unchanged in
this step; this configuration alone does not make them accept public-client tokens.

Native account management lives at:

```text
IDENTITY_ORIGIN/realms/REALM/account/
```

Link there for username/password/session actions. Application admin is not a
Keycloak administrator. No profile images/uploads are introduced. Username and
email are display data; stable identity is issuer plus subject. New token claims
reflect username edits. Updating the agent projection independently of a request
requires the future identity-event pipeline, not this client setup.

## Password changes and revocation: important boundary

On pinned Keycloak 26.8.1, the password form's **Sign out from other devices**
checkbox is initially unchecked. Checking it ends other identity sessions;
without it, changing a password does not guarantee their refresh tokens stop.
For this intermediate stage, explicitly check it when changing a password.
Administrator logout-all also ends refresh sessions. Already issued JWTs are
not erased from other services; they expire or require local revocation state.

Before production, step **3.8.4 must enforce password-change logout of other
sessions regardless of the checkbox**, and durably publish its revocation event.
RabbitMQ alone cannot invalidate a still-active Keycloak refresh session.
Use the canonical `UPDATE_CREDENTIAL` event with password credential detail;
the deprecated password event must not produce a second logical change. Verify
both checked and unchecked password flows with the implemented enforcement.
Do not claim automatic password revocation is delivered by step 3.8.3.

Later RabbitMQ consumers reject new requests quickly after consumed revocation;
300-second access-token expiry bounds delayed unknown revocations. Accepted
bounded jobs may finish under the agreed execution grant. Kafka remains agent
telemetry only. No messaging or revocation consumer is implemented here.

## CORS and verification

Client-bound token responses allow only the configured frontend origin. Generic
OPTIONS has no client identity and is not proof of client-specific policy.
CORS is a browser rule, not service authentication or a network firewall.
Agent exact-origin CORS and hosted TLS/network acceptance belong to later steps.

Tests use disposable identity PostgreSQL/Keycloak, synthetic accounts and a
loopback callback server, never team or cloud credentials. Acceptance covers
PKCE login, role/audience/profile claims, refresh rotation, native username and
password/session actions, denied grants/redirects, origin enforcement,
configuration drift and preservation of the confidential client/secret.
Final local gate: **109 passed in 377.38 seconds** on 9 November 2026, including
the existing confidential-client browser flow. Separate unit gate: 88 passed,
21 deselected. Ruff lint, changed-file formatting, dependency and Git whitespace
checks pass. Whole-tree formatting has an unrelated pre-existing issue in
`tools/check_config.py`. Seventeen affected documents have valid local links and
code fences. The earlier full-gate attempt while Docker was stopped is not a
passing result; the complete gate was rerun successfully once Docker returned.
No production/team realm was modified, and no commit or push was made. Required
GitHub `tests` and PR delivery remain pending. Stop before step 3.8.4.

## Primary references

- [Pinned password-action implementation](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/authentication/requiredactions/UpdatePassword.java)
- [Default sign-out checkbox change](https://www.keycloak.org/docs/26.3.5/upgrading/#signing-out-from-other-devices-now-disabled-by-default)
- [Pinned Account Console routes](https://github.com/keycloak/keycloak/blob/26.8.1/js/apps/account-ui/src/routes.tsx)
- [Pinned signing-in controls](https://github.com/keycloak/keycloak/blob/26.8.1/js/apps/account-ui/src/account-security/SigningIn.tsx)
