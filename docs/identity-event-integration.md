# Identity integration: plan 3.8.4

Updated 11 November 2026. Current branch: `fix/identity-profile-events`.
Implement one slice, verify it and stop before the next.

**Broker ownership revision, 10 November 2026:** RabbitMQ deployment, persistent
storage, topology and permissions belong to separate repository
`datalens-messaging`. Identity retains its transactional source, outbox, schemas
and publisher; the agent retains its consumer/projection. The broker is not
provisioned yet. Internal broker service name is `rabbitmq`, superseding the
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
   - **3.8.4.3.1 Profile mappings (blocked: runtime verification):** canonical full snapshots for
     administrator creation/updates and native Account Console profile edits.
     Verify stable subject, consecutive revisions, explicit null clearing and
     account/outbox rollback with honest HTTP failure on validation/storage errors.
     Existing self-registration handling is not acceptance-tested; onboarding
     remains administrator-created accounts with public registration disabled.
   - **3.8.4.3.2 Security mappings (not started):** independent security revisions,
     session/user revocation, enable/disable, deletion and role changes, including
     administrative paths. Prove ordering, rollback and cutoff semantics.
   - **3.8.4.3.3 Password enforcement (not started):** invalidate other sessions
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
5. **3.8.4.5 Transport acceptance:** durable exchange `identity.events.v1`, queue
   `agent.identity.v1`, dead-letter queue `agent.identity.dead.v1`; disposable
   restart/outage/redelivery, permission and poison-message tests. Agent consumer
   remains 3.8.5; cloud infrastructure and availability guarantees remain Plan 10.

This expands an existing stage into reviewable slices, not another top-level plan.

3.8.4.1 delivery is accepted from user confirmation. The
[3.8.4.2 proof](transactional-outbox-proof.md) demonstrates administrative creation/
profile writes, rollback and concurrent profile counters in the disposable image.
Security counters start at zero; complete security allocation/mappings are not
implemented. Focused real gate passed; final full regression passed (156 tests in 435.03 seconds, 10 November 2026). No broker
or production realm activation. Stop before 3.8.4.3. Verification below records
the earlier contract-only stage, not final source-proof regression.

## Current profile-slice verification

**Current, 11 November 2026: 3.8.4.3.1 native profile mappings.**
**Status: Blocked ? final runtime verification.** Identity branch:
`fix/identity-profile-events`. Administrator/native profile snapshots, null
clearing and transactional rollback protection are implemented in the disposable
test image. The configuration CLI also has bounded administrator-token renewal,
serialized rotation and an IPv4 transport for local Compose URLs; hosted URLs and
agent authentication are unchanged.

Final unit gate: **149 passed, 22 runtime/PostgreSQL tests deselected, 0.50 seconds**.
Fifteen new administration-client tests pass. Ruff lint, changed-file formatting,
dependency and whitespace checks pass. Latest fresh full gate after Docker reset:
**114 passed, 1 failed, 172.46 seconds**, stopping on realm cleanup after profile
assertions passed. This is not a successful full gate or merge sign-off.
Prior JVM samples found realm deletion/session cleanup spinning in Hibernate's
SimpleTimestamper; a timestamp-only probe observed guest-clock rollback. Increasing
cleanup timeouts and forcing IPv4 did not resolve that stall. Original cleanup
limits remain; no cache/JIT/transaction assertion is bypassed. Disposable test
containers are stopped and ignored reports retain the failed-run evidence.

Next action is stable-clock local verification or a draft PR's Linux `tests` gate;
do not merge or implement 3.8.4.3.2 security mappings until verification passes.
3.8.4.3.3 password enforcement and RabbitMQ publishing/consumption remain later.
The user authorized this fix branch's commit/push and a draft PR for Linux CI.
No merge, production activation or cloud deployment is authorized.
Parent plans are outside service Git repositories and their PRs. Older progress
snapshots below are historical.

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

Profile/security revisions are independent positive signed-64-bit source counters,
not timestamps or consumer order. Profile allocation uses the proven atomic
PostgreSQL upsert; security allocation remains 3.8.4.3.2 work.
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

## Verification

**46 contract tests passed; 134 identity unit tests passed, 21 runtime/PostgreSQL
tests deselected**, 0.52 seconds. Ruff lint, changed-file formatting, dependency
and whitespace checks pass. Existing required CI `tests` discovers these tests.
Browser/database suites were not rerun for pure contract code; previous evidence
is unchanged. Required PR delivery remains pending. No broker, live accounts,
database schema or cloud configuration changed. Stop before 3.8.4.2.

Validator: [jsonschema 4.26.0](https://pypi.org/project/jsonschema/4.26.0/).
Parent workspace plans are outside this service repository/PR.
