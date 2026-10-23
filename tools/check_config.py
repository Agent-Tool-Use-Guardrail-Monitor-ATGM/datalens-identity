"""Validate the identity foundation contract without contacting infrastructure."""

import argparse
import os
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "identity.toml"
SECRET_NAMES = frozenset(
    {
        "IDENTITY_DB_BOOTSTRAP_PASSWORD",
        "IDENTITY_DB_PASSWORD",
        "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD",
    }
)
IMAGE_PATTERNS = {
    "keycloak": r"quay\.io/keycloak/keycloak:\d+\.\d+\.\d+",
    "postgres": r"postgres:17\.\d+-bookworm",
    "mailpit": r"axllent/mailpit:v\d+\.\d+\.\d+",
}
PROFILE_KEYS = frozenset(
    {
        "project",
        "realm",
        "database",
        "database_user",
        "public_origin",
        "management_port",
        "mailpit_port",
        "callback_origin",
        "storage",
    }
)


class ConfigurationError(ValueError):
    """A trusted diagnostic that never includes submitted values or secret text."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigurationError(message)


def fields(value: object, expected: set | frozenset, location: str) -> None:
    require(
        isinstance(value, dict) and value.keys() == expected,
        f"Unexpected or missing fields in {location}.",
    )


def port(value: object) -> int:
    require(type(value) is int and 1024 <= value <= 65535, "Invalid local port.")
    return value


def origin_port(value: object) -> int:
    require(isinstance(value, str), "Invalid local origin.")
    try:
        parsed = urlsplit(value)
        number = parsed.port
        valid = (
            parsed.scheme == "http"
            and parsed.hostname == "localhost"
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and value == f"http://localhost:{number}"
        )
    except ValueError:
        raise ConfigurationError("Invalid local origin.") from None
    require(valid, "Invalid local origin.")
    return port(number)


def validate_config(config: object) -> dict:
    fields(config, {"schema_version", "services", "images", "secrets", "profiles"}, "configuration")
    require(
        type(config["schema_version"]) is int and config["schema_version"] == 1,
        "Unsupported configuration version.",
    )
    fields(config["services"], {"keycloak", "postgres", "mailpit"}, "services")
    service_names = list(config["services"].values())
    require(
        all(
            isinstance(name, str)
            and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is not None
            for name in service_names
        )
        and len(set(service_names)) == len(service_names),
        "Service names must be unique and use lowercase DNS-safe logical names.",
    )
    fields(config["images"], set(IMAGE_PATTERNS), "images")
    for name, pattern in IMAGE_PATTERNS.items():
        image = config["images"][name]
        require(
            isinstance(image, str)
            and re.fullmatch(pattern + r"@sha256:[0-9a-f]{64}", image) is not None,
            "Images require approved repositories, exact release tags and SHA-256 digests.",
        )
    fields(config["secrets"], {"required_env"}, "secrets")
    names = config["secrets"]["required_env"]
    require(
        isinstance(names, list)
        and all(isinstance(name, str) for name in names)
        and len(names) == len(SECRET_NAMES)
        and set(names) == SECRET_NAMES,
        "Invalid secret environment references.",
    )
    fields(config["profiles"], {"local", "test"}, "profiles")
    used_ports = []
    for name, database, user, realm, project, storage in (
        (
            "local",
            "identity_db",
            "identity_app",
            "datalens",
            "datalens-identity-local",
            "named-volume",
        ),
        (
            "test",
            "identity_test_db",
            "identity_test",
            "datalens-test",
            "datalens-identity-tests",
            "tmpfs",
        ),
    ):
        profile = config["profiles"][name]
        fields(profile, PROFILE_KEYS, f"profiles.{name}")
        require(
            (
                profile["database"],
                profile["database_user"],
                profile["realm"],
                profile["project"],
                profile["storage"],
            )
            == (database, user, realm, project, storage),
            "Profiles must use separate identity-owned databases, roles, realms and storage.",
        )
        used_ports.extend(
            [
                origin_port(profile["public_origin"]),
                origin_port(profile["callback_origin"]),
                port(profile["management_port"]),
                port(profile["mailpit_port"]),
            ]
        )
    require(len(used_ports) == len(set(used_ports)), "Local/test ports must not overlap.")
    return config


def read_config(path: Path = DEFAULT_CONFIG) -> dict:
    try:
        with path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, ValueError):
        raise ConfigurationError("Unable to read identity configuration.") from None
    return validate_config(config)


def check_secrets(environment: Mapping[str, str], *, names: frozenset[str] = SECRET_NAMES) -> None:
    values = []
    for name in sorted(names):
        value = environment.get(name, "")
        require(
            isinstance(value, str)
            and len(value.strip()) >= 16
            and not re.match(r"(?i)^(replace|change.?me|example|placeholder|<)", value.strip()),
            f"Missing or placeholder secret: {name}.",
        )
        values.append(value)
    require(len(set(values)) == len(values), "Identity secrets must use separate values.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--check-secrets", action="store_true", help="Check process environment too"
    )
    args = parser.parse_args(argv)
    try:
        read_config(args.config)
        if args.check_secrets:
            check_secrets(os.environ)
    except ConfigurationError as error:
        print(f"Identity configuration failed: {error}")
        return 1
    print("Identity configuration is valid; no infrastructure was contacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
