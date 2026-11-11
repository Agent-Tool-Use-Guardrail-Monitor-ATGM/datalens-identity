# Identity integration: plan 3.8.4

Updated 11 November 2026. Current branch: `test/identity-transport`.
Implement one slice, verify it and stop before the next.

**Broker ownership revision, 10 November 2026:** RabbitMQ deployment, persistent
storage, topology and permissions belong to separate repository
`datalens-messaging`. Identity retains its transactional source, outbox, schemas
and publisher; the agent retains its consumer/projection. The local broker foundation is merged. Internal broker service name is `rabbitmq`, superseding the
earlier `identity-rabbitmq` planning name. This changes repository ownership only.

## Sequence

1. **3.8.4.1 Contracts (delivered):** JSON Schema, synthetic examples, strict
   bounded decoding and tests. No runtime process invokes the decoder yet.
2. **3.8.4.2 Transactional source proof (delivered):** pinned Keycloak Event Listener SPI/JPA
   provider and disposable tests proving outbox intent commits/rolls back with
   administrative account mutations. Establish separate profile/security counter
   storage and prove concurrent profile allocation with database coordination.
   Security allocation is verified with the mappings in 3.8.4.3. Do not substitute
   in-memory or after-commit-only sending for atomic durable intent.
3. **3.8.4.3 Mappings/enforcement**, divided into these sequential slices:
   - **3.8.4.3.1 Profile mappings (merged, Linux verified):** canonical full snapshots for
     administrator creation/updates and native Account Console profile edits.
     Verify stable subject, consecutive revisions, explicit null clearing and
     account/outbox rollback with honest HTTP failure on validation/storage errors.
     Existing self-registration handling is not acceptance-tested; onboarding
     remains administrator-created accounts with public registration disabled.
   - **3.8.4.3.2 Security mappings (merged, Linux verified):** independent security revisions,
     session/user revocation, enable/disable, deletion and role changes, including
     administrative paths. Prove ordering, rollback and cutoff semantics.
   - **3.8.4.3.3 Password enforcement (PR gate pending):** invalidate other sessions
     even when the native checkbox is unchecked. Canonical password
     `UPDATE_CREDENTIAL` and its deprecated event must produce one logical change.
     Verify actual refresh invalidation for native changes and admin resets.
   Each slice requires the preceding slice's verified PR delivery. Stop before
   implementing the next slice.
4. **3.8.4.4 Publisher:** separate `identity-publisher`, integration-outbox-only
   access, persistent messages, confirms, stable retry IDs, outage recovery,
   bounded backlog alarms and published retention. No broker I/O while holding
   an account transaction. Configurable endpoints, hosted AMQPS and server-only
   least-privilege credentials are required.
   Split this stage into **3.8.4.4.1 broker foundation** in `datalens-messaging`
   and **3.8.4.4.2 publisher** in `datalens-identity`. The messaging repository
   provisions topology; identity connects through a configured endpoint with
   scoped credentials and validates the expected topology.
   The [publisher](identity-publisher.md) is implemented and locally verified.
   Linux CI passed and PR #16 merged.
5. **3.8.4.5 Transport acceptance (local checks passed, PR CI pending):** durable exchange `identity.events.v1`, queue
   `agent.identity.v1`, dead-letter queue `agent.identity.dead.v1`; disposable
   restart/outage/redelivery, permission and poison-message tests. Agent consumer
   remains 3.8.5; cloud infrastructure and availability guarantees remain Plan 10.

The transport check uses Keycloak's real profile and security events from
PostgreSQL. It restores RabbitMQ after an outage and verifies the publisher's
confirmed records. It recreates the broker before consumption, closes an
unacknowledged channel to prove redelivery, and compares the decoded messages
with their source events. A malformed delivery is rejected without requeue.
The test verifies the dead-letter queue through operator access and confirms
that the scoped consumer cannot read it.

This expands an existing stage into reviewable slices, not another top-level plan.

3.8.4.1 delivery is accepted from user confirmation. The
[3.8.4.2 proof](transactional-outbox-proof.md) demonstrates administrative creation/
profile writes, rollback and concurrent profile counters in the disposable image.
Security counters start at zero. The transactional source proof passed 156 tests
on 10 November 2026. The profile mapping then passed [171 Linux tests](https://github.com/Agent-Tool-Use-Guardrail-Monitor-ATGM/datalens-identity/actions/runs/42988281357)
and merged in [PR #12](https://github.com/Agent-Tool-Use-Guardrail-Monitor-ATGM/datalens-identity/pull/12).

## Security event sources

| Successful Keycloak action | Outbox event |
|---|---|
| OIDC logout or Account Console session removal with a user and session ID | `user.session.revoked`, reason `logout` |
| Administrator removes one session by ID | `user.session.revoked`, reason `admin_session_logout` |
| Administrator uses the per-user logout endpoint | `user.sessions.revoked`, reason `logout_all` |
| Administrator adds or removes a user's direct realm or client role mapping | `user.sessions.revoked`, reason `roles_changed` |
| Administrator changes the enabled state | `user.disabled` or `user.enabled`, alongside the existing profile snapshot |
| Administrator deletes the user | `user.deleted` |
| User successfully changes their password through Keycloak's required action | `user.sessions.revoked`, reason `password_changed` |
| Administrator successfully calls the user's `reset-password` endpoint | `user.sessions.revoked`, reason `admin_password_reset` |

Keycloak's administrator session-delete event carries the session ID after the
session is gone. A request filter captures its owner before removal. The
listener writes on Keycloak's matching success event. The target is the session
owner even when the administrator is a different user. An offline session with
a distinct linked online session ID produces a revocation for each ID.
Keycloak's enable-state details distinguish transitions from repeat writes.
Security revisions and outbox rows share the Keycloak transaction. The existing
per-subject row serializes revision allocation.

Cutoffs use the same clock as Keycloak token issuance, rounded down to Unix
seconds. Direct role mapping events request rejection of older access tokens by
the future agent consumer. Keycloak refresh sessions remain active on role
changes. Group membership changes, edits to composite role definitions and
realm-wide logout are outside these per-user mappings. The provider remains in
the disposable test image.

Pinned sources: [user operations](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/UserResource.java),
[admin session deletion](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java),
[Account Console sessions](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/account/SessionResource.java),
[realm role mappings](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/RoleMapperResource.java)
and [client role mappings](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/ClientRoleMappingsResource.java).

The runtime suite exercises OIDC logout, administrative logout and role mapping
through real Keycloak endpoints. PostgreSQL checks cover enable/disable,
deletion, repeat or rejected requests, concurrent security revision allocation
and rollback when the security event insert fails.

## Security-slice verification

The provider builds. All 149 unit tests passed. The two focused runtime tests
passed before the extra admin-session rollback assertion was added. In the
final full run, the browser test passed with that assertion. The full run
stopped at **165 passed and one failure** after the outbox test timed out on
realm teardown. Its event, rollback, concurrency and restart assertions
finished before teardown. Five later tests did not run. This matches the prior
local teardown symptom, with no JVM cause confirmed on that run. Disposable
test containers were removed.

The required [Linux job](https://github.com/Agent-Tool-Use-Guardrail-Monitor-ATGM/datalens-identity/actions/runs/43054685496)
passed all 171 tests and [PR #14](https://github.com/Agent-Tool-Use-Guardrail-Monitor-ATGM/datalens-identity/pull/14)
merged as `e97bbf9`.

## Password enforcement

The successful password `UPDATE_CREDENTIAL` event supplies the authentication
root ID that Keycloak uses for the current session. The listener keeps that
session and removes the user's other online and offline sessions through
Keycloak's session provider. The administrator reset endpoint removes all of
the target user's sessions. Both write one user-wide outbox event and reuse the
transactional security revision and cutoff. Keycloak can also emit individual
logout events when the checkbox is selected. The deprecated `UPDATE_PASSWORD`
event adds no second password revocation.

This covers Keycloak's password required action and dedicated admin reset
endpoint. Inline credential writes through generic user updates and third-party
credential providers are outside this mapping. For changes covered here, old
access tokens remain subject to the future agent consumer's inclusive cutoff.
The mandatory session removals do not invoke client back-channel callbacks.

The disposable provider built successfully. All 149 unit tests and both
focused browser/PostgreSQL tests passed. The focused cases verify both checkbox
settings, the existing browser session, rejected administrator resets, rollback
of the password and retained refresh session on write failure, refresh rejection
after success and consecutive outbox revisions. Offline token issuance and
revocation were outside this runtime check. Full Linux PR CI is pending.

## Wire contract

[Schema](../contracts/identity-events.v1.schema.json),
[synthetic examples](../contracts/identity-events.v1.examples.json), and
[decoder](../tools/identity_events.py) define identity integration only.
Kafka remains agent telemetry, separate from these seven identity event types.

Required envelope: `schema_version`, `event_id`, `event_type`, `issuer`, `subject`,
`occurred_at`, `data`. Version is 1; IDs are canonical UUIDv4; timestamps are UTC
`Z`. Subject is stable identity, not username/email. Issuer must exactly equal
trusted configuration, never configuration taken from the message. Matching an
issuer string does not authenticate the sender; transport must authorize it.

| Event | Required data |
|---|---|
| `user.created` | `profile_revision`, nullable `display_name`, `username`, `email` |
| `user.profile.updated` | Same full snapshot; null explicitly clears fields |
| `user.session.revoked` | `security_revision`, `session_id`, reason `logout` or `admin_session_logout` |
| `user.sessions.revoked` | `security_revision`, `tokens_issued_at_or_before`, reason `logout_all`, `password_changed`, `admin_password_reset` or `roles_changed` |
| `user.disabled` | `security_revision`, `tokens_issued_at_or_before` |
| `user.enabled` | `security_revision`; never clears prior revocations |
| `user.deleted` | `security_revision`, `tokens_issued_at_or_before`; no display PII |

Profile/security revisions are independent positive signed-64-bit source counters.
Both counters use atomic PostgreSQL upserts.
Retain each distinct session revocation even if a newer security event arrives
first. Deletion tombstones dominate stale profiles; reenabling cannot resurrect
old sessions. Event IDs remain stable on retry. Cutoffs are inclusive Unix seconds:
reject `iat <= tokens_issued_at_or_before`, including ambiguous same-second tokens.
A fresh login may need the next second. Consumer decisions remain future work.

`decode_event(body, expected_issuer=...)` accepts at most **16,384 UTF-8 bytes**,
including whitespace. Reject duplicate keys, non-finite numbers, invalid UTF-8,
unknown types, extra fields and invalid calendar dates. JSON Schema alone does
not enforce byte size or configured issuer; other implementations must also check
these. Diagnostics exclude payload values. Email is display PII, not verified
ownership authority. No passwords, JWTs, refresh tokens, authoritative roles,
login records or image attributes belong in events. Render display data as text.
Consumer receipt/state updates must commit together before acknowledgement in
3.8.5. These contracts do not cancel bounded jobs or change agent HTTP auth.

## Contract-stage verification (historical)

**46 contract tests passed; 134 identity unit tests passed, 21 runtime/PostgreSQL
tests deselected**, 0.52 seconds. Ruff lint, changed-file formatting, dependency
and whitespace checks pass. Existing required CI `tests` discovers these tests.
Browser/database suites were not rerun for pure contract code; previous evidence
is unchanged. Required PR delivery remains pending. No broker, live accounts,
database schema or cloud configuration changed. Stop before 3.8.4.2.

Validator: [jsonschema 4.26.0](https://pypi.org/project/jsonschema/4.26.0/).
Parent workspace plans are outside this service repository/PR.
## Existing-user backfill

On the pinned Keycloak 26.8.1 provider image, enable `identity-outbox-proof`
for the target realm and start the normal publisher and consumer. With a realm
administrator who can manage users, list accounts through Keycloak's paginated
`GET /admin/realms/{realm}/users` endpoint. For each known local user ID, send
`POST /admin/realms/{realm}/identity-backfill/users/{subject}` with no body.
Run one pass during a stable account inventory or repeat the listing if accounts
changed while paging. A `204` means both snapshots committed to the identity
outbox. Wait for the consumer backlog and dead-letter queue to be reconciled
before cutover.

The endpoint takes a lock on the local Keycloak account and writes a full
profile event and its current enabled/disabled status under the existing
source revisions. It leaves account fields and sessions intact. A second
successful request issues a newer snapshot. Transport retries reuse the
original event IDs. Missing accounts, federated users and service accounts
are outside this backfill. Accounts deleted before the listener was active
and historical session revocations cannot be reconstructed from the current
account inventory. Allow previously issued access tokens to expire before
switching to bearer admission.

The endpoint uses Keycloak's internal admin extension SPI and local JPA user
model. Re-run the runtime test before upgrading Keycloak. The hosted image and
rollout remain part of the deployment handoff.
See the [Keycloak custom REST resource guidance](https://www.keycloak.org/docs/latest/upgrading/index.html#upgrading-your-custom-jax-rs-resources).
