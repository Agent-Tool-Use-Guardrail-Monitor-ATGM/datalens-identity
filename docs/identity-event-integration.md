# Identity integration: plan 3.8.4

Updated 9 November 2026. Branch: `fix/identity-event-contracts`.
Implement one slice, verify it and stop before the next.

## Sequence

1. **3.8.4.1 Contracts (current):** JSON Schema, synthetic examples, strict
   bounded decoding and tests. No runtime process invokes the decoder yet.
2. **3.8.4.2 Transactional source proof:** pinned Keycloak Event Listener SPI/JPA
   provider and disposable tests proving outbox intent commits/rolls back with
   user/admin account mutations. Allocate independent profile/security counters
   with database coordination and consistent lock order. Do not substitute
   in-memory or after-commit-only sending for atomic durable intent.
3. **3.8.4.3 Mappings/enforcement:** canonical snapshots, session/user revocation,
   enable/disable and deletion, covering user/admin actions. Enforce password
   change logout of other sessions even when the native checkbox is unchecked.
   Canonical password `UPDATE_CREDENTIAL` and its deprecated event must produce
   one logical change. Verify actual refresh invalidation.
4. **3.8.4.4 Publisher:** separate `identity-publisher`, integration-outbox-only
   access, persistent messages, confirms, stable retry IDs, outage recovery,
   bounded backlog alarms and published retention. No broker I/O while holding
   an account transaction. Configurable endpoints, hosted AMQPS and server-only
   least-privilege credentials are required.
5. **3.8.4.5 Transport acceptance:** durable exchange `identity.events.v1`, queue
   `agent.identity.v1`, dead-letter queue `agent.identity.dead.v1`; disposable
   restart/outage/redelivery, permission and poison-message tests. Agent consumer
   remains 3.8.5; cloud infrastructure and availability guarantees remain Plan 10.

This expands an existing stage into reviewable slices, not another top-level plan.

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
not timestamps or consumer order. Actual allocation/locking is not implemented.
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
