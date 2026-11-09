"""Wire compatibility and rejection at the identity integration boundary."""

import copy
import json

import pytest
from identity_events import MAX_EVENT_BYTES, SCHEMA, SCHEMA_PATH, EventContractError, decode_event
from jsonschema import Draft202012Validator

EXAMPLES = json.loads(
    SCHEMA_PATH.with_name("identity-events.v1.examples.json").read_text(encoding="utf-8")
)
ISSUER = "http://localhost:8081/realms/datalens"


def encode(event):
    return json.dumps(event, ensure_ascii=False).encode("utf-8")


def test_schema_is_valid_and_examples_cover_every_event():
    Draft202012Validator.check_schema(SCHEMA)
    assert {e["event_type"] for e in EXAMPLES} == set(SCHEMA["properties"]["event_type"]["enum"])
    assert len(EXAMPLES) == 7


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda e: e["event_type"])
def test_wire_examples_round_trip_and_reject_missing_or_unknown_data(example):
    assert decode_event(encode(example), expected_issuer=ISSUER) == example
    for key in example["data"]:
        event = copy.deepcopy(example)
        del event["data"][key]
        with pytest.raises(EventContractError):
            decode_event(encode(event), expected_issuer=ISSUER)
    event = copy.deepcopy(example)
    event["data"]["refresh_token"] = "must-never-leak"
    with pytest.raises(EventContractError, match="^Invalid identity event contract.$") as error:
        decode_event(encode(event), expected_issuer=ISSUER)
    assert "must-never-leak" not in str(error.value)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("event_id", "not-a-uuid"),
        ("event_type", "session.started"),
        ("subject", ""),
        ("subject", "subject\nforged"),
        ("subject", "x" * 256),
        ("occurred_at", "2026-02-31T12:00:00Z"),
        ("occurred_at", "2026-11-09T12:00:00+01:00"),
        ("occurred_at", "2026-11-09T12:00:00"),
        ("issuer", "https://untrusted.example/realms/datalens"),
        ("data", {"profile_revision": 1}),
        ("password", "must-never-leak"),
    ],
)
def test_invalid_envelope_fields_are_rejected(key, value):
    event = copy.deepcopy(EXAMPLES[0])
    event[key] = value
    with pytest.raises(EventContractError):
        decode_event(encode(event), expected_issuer=ISSUER)


@pytest.mark.parametrize("revision", [0, -1, True, 1.5, "2", 2**63])
@pytest.mark.parametrize("index,key", [(0, "profile_revision"), (2, "security_revision")])
def test_revisions_are_positive_signed_64_bit_integers(index, key, revision):
    event = copy.deepcopy(EXAMPLES[index])
    event["data"][key] = revision
    with pytest.raises(EventContractError):
        decode_event(encode(event), expected_issuer=ISSUER)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"null",
        b"[]",
        b"\xff",
        b'{"x":NaN}',
        b'{"subject":"first","subject":"second"}',
        b'{"data":{"email":null,"email":"second"}}',
        b"[" * 2000 + b"]" * 2000,
        b" " * (MAX_EVENT_BYTES + 1),
        "not bytes",
    ],
)
def test_malformed_duplicate_nonfinite_deep_or_oversized_input_is_rejected(body):
    with pytest.raises(EventContractError):
        decode_event(body, expected_issuer=ISSUER)


def test_byte_limit_is_inclusive_and_not_a_character_limit():
    body = encode(EXAMPLES[0])
    padded = body + b" " * (MAX_EVENT_BYTES - len(body))
    assert decode_event(padded, expected_issuer=ISSUER) == EXAMPLES[0]
    with pytest.raises(EventContractError):
        decode_event(padded + b" ", expected_issuer=ISSUER)
    for issuer in ("", None):
        with pytest.raises(EventContractError, match="trusted issuer"):
            decode_event(body, expected_issuer=issuer)


def test_snapshots_allow_explicit_clears_and_security_payloads_are_separate():
    event = copy.deepcopy(EXAMPLES[1])
    event["data"].update(display_name="Analyst", username="analyst", email="a@example.invalid")
    assert decode_event(encode(event), expected_issuer=ISSUER) == event
    for index, key, value in (
        (1, "email", "x" * 321),
        (2, "session_id", ""),
        (2, "reason", "password_changed"),
        (3, "tokens_issued_at_or_before", -1),
        (3, "tokens_issued_at_or_before", True),
        (4, "email", "a@example.invalid"),
        (5, "tokens_issued_at_or_before", 1),
        (6, "username", "deleted-user"),
    ):
        event = copy.deepcopy(EXAMPLES[index])
        event["data"][key] = value
        with pytest.raises(EventContractError):
            decode_event(encode(event), expected_issuer=ISSUER)
