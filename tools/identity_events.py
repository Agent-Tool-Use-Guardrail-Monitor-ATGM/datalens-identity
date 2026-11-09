"""Identity wire contracts only; no broker connection or account mutation."""

import json
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

MAX_EVENT_BYTES = 16_384
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "contracts/identity-events.v1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


class EventContractError(ValueError):
    """Rejected payload; diagnostics deliberately exclude profile data and tokens."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-finite number")


def decode_event(body: bytes, *, expected_issuer: str) -> dict:
    """Check an authenticated transport payload against one configured issuer."""
    if not isinstance(expected_issuer, str) or not expected_issuer:
        raise EventContractError("A trusted issuer is required.")
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_EVENT_BYTES:
        raise EventContractError("Invalid identity event size or encoding.")
    try:
        event = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
        VALIDATOR.validate(event)
        # Validate calendar values without an optional JSON Schema format dependency.
        datetime.fromisoformat(event["occurred_at"])
        if event["issuer"] != expected_issuer:
            raise ValueError("Untrusted issuer")
    except (ValueError, ValidationError, RecursionError):
        raise EventContractError("Invalid identity event contract.") from None
    return event
