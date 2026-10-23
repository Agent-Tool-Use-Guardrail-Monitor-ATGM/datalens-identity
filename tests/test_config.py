"""Prove configuration isolation and safe diagnostics before services exist."""

import copy
import os
import socket
import subprocess
import sys

import pytest
from check_config import (
    DEFAULT_CONFIG,
    SECRET_NAMES,
    ConfigurationError,
    check_secrets,
    main,
    read_config,
    validate_config,
)


@pytest.fixture
def config():
    return copy.deepcopy(read_config())


def test_committed_contract_and_cli_work_without_network_or_secrets(monkeypatch, capsys):
    def deny(*args, **kwargs):
        raise AssertionError("Network access is forbidden")

    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    for name in SECRET_NAMES:
        monkeypatch.delenv(name, raising=False)
    assert read_config()["schema_version"] == 1
    assert main([]) == 0
    assert "no infrastructure was contacted" in capsys.readouterr().out


@pytest.mark.parametrize("version", [0, 2, True, "1"])
def test_rejects_unknown_or_non_integer_schema_version(config, version):
    config["schema_version"] = version
    with pytest.raises(ConfigurationError, match="version"):
        validate_config(config)


@pytest.mark.parametrize("section", [None, "services", "images", "secrets", "profiles"])
def test_unknown_fields_are_rejected_without_echoing_their_name(config, section):
    target = config if section is None else config[section]
    target["private-submitted-value"] = "private-submitted-value"
    with pytest.raises(ConfigurationError) as caught:
        validate_config(config)
    assert "private-submitted-value" not in str(caught.value)


@pytest.mark.parametrize("section", ["services", "images", "secrets", "profiles"])
def test_missing_sections_are_rejected(config, section):
    del config[section]
    with pytest.raises(ConfigurationError, match="fields"):
        validate_config(config)


@pytest.mark.parametrize("image", ["keycloak", "postgres", "mailpit"])
@pytest.mark.parametrize("bad_reference", ["untrusted/image:1.2.3", "latest", "missing-digest"])
def test_rejects_unpinned_or_unapproved_images(config, image, bad_reference):
    if bad_reference == "missing-digest":
        config["images"][image] = config["images"][image].split("@", 1)[0]
    else:
        config["images"][image] = bad_reference
    with pytest.raises(ConfigurationError, match="Images require"):
        validate_config(config)


@pytest.mark.parametrize("name", ["identity", "Identity-Postgres", "datalens-invalid_name", 1])
def test_service_names_require_the_shared_prefix_and_dns_safe_syntax(config, name):
    config["services"]["keycloak"] = name
    with pytest.raises(ConfigurationError, match="Service names"):
        validate_config(config)


def test_services_cannot_share_a_name(config):
    config["services"]["postgres"] = config["services"]["keycloak"]
    with pytest.raises(ConfigurationError, match="unique"):
        validate_config(config)


@pytest.mark.parametrize(
    "profile,field,value",
    [
        ("local", "database", "agent_db"),
        ("test", "database", "identity_db"),
        ("test", "database_user", "identity_app"),
        ("local", "database_user", "postgres"),
        ("test", "realm", "datalens"),
        ("test", "project", "datalens-identity-local"),
        ("test", "storage", "named-volume"),
        ("local", "storage", "tmpfs"),
    ],
)
def test_profiles_cannot_share_or_cross_service_storage(config, profile, field, value):
    config["profiles"][profile][field] = value
    with pytest.raises(ConfigurationError, match="identity-owned"):
        validate_config(config)


@pytest.mark.parametrize(
    "origin",
    [
        "http://0.0.0.0:8081",
        "http://example.com:8081",
        "http://127.0.0.1:8081",
        "http://secret:private-value@localhost:8081",
        "http://localhost:8081/path",
        "http://localhost:8081?secret=private-value",
        "http://localhost:8081#private-value",
        "http://localhost:invalid",
        "http://localhost",
        "http://[invalid",
        8081,
    ],
)
def test_local_origins_are_canonical_loopback_without_credentials_or_paths(config, origin):
    config["profiles"]["local"]["public_origin"] = origin
    with pytest.raises(ConfigurationError) as caught:
        validate_config(config)
    assert "private-value" not in str(caught.value)


@pytest.mark.parametrize("number", [0, 80, 65536, True, "9001"])
def test_port_bounds_and_types_are_enforced(config, number):
    config["profiles"]["local"]["management_port"] = number
    with pytest.raises(ConfigurationError, match="port"):
        validate_config(config)


def test_cross_profile_port_collision_is_rejected(config):
    config["profiles"]["test"]["management_port"] = config["profiles"]["local"]["mailpit_port"]
    with pytest.raises(ConfigurationError, match="overlap"):
        validate_config(config)


def test_unused_loopback_port_can_be_selected_without_changing_validation(config):
    config["profiles"]["local"]["public_origin"] = "http://localhost:28081"
    assert validate_config(config) is config


@pytest.mark.parametrize("references", [[], ["DATABASE_URL"], ["private-value"], [True]])
def test_only_expected_secret_names_are_accepted(config, references):
    config["secrets"]["required_env"] = references
    with pytest.raises(ConfigurationError, match="references") as caught:
        validate_config(config)
    assert "private-value" not in str(caught.value)


@pytest.fixture
def secrets():
    return {
        name: f"synthetic-private-value-{index}" for index, name in enumerate(sorted(SECRET_NAMES))
    }


def test_explicit_secret_check_accepts_distinct_test_values(secrets):
    check_secrets(secrets)


@pytest.mark.parametrize(
    "value", ["", "short", "replace-with-real-secret", "<private-placeholder>"]
)
def test_missing_short_placeholder_secrets_fail_without_disclosing_values(secrets, value):
    secrets["IDENTITY_DB_PASSWORD"] = value
    with pytest.raises(ConfigurationError) as caught:
        check_secrets(secrets)
    assert "IDENTITY_DB_PASSWORD" in str(caught.value)
    if value:
        assert value not in str(caught.value)


def test_missing_environment_and_secret_reuse_fail(secrets):
    with pytest.raises(ConfigurationError, match="Missing"):
        check_secrets({})
    for name in SECRET_NAMES:
        secrets[name] = "same-synthetic-private-secret"
    with pytest.raises(ConfigurationError, match="separate values") as caught:
        check_secrets(secrets)
    assert "same-synthetic-private-secret" not in str(caught.value)


def test_secret_cli_reports_safe_failure_then_success(monkeypatch, capsys, secrets):
    for name in SECRET_NAMES:
        monkeypatch.delenv(name, raising=False)
    assert main(["--check-secrets"]) == 1
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)
    assert main(["--check-secrets"]) == 0
    output = capsys.readouterr().out
    assert not any(value in output for value in secrets.values())
    assert "Traceback" not in output


@pytest.mark.parametrize("content", [b'password = "private-value', b"\xff\xfe"])
def test_malformed_files_have_safe_diagnostics(tmp_path, capsys, content):
    path = tmp_path / "invalid.toml"
    path.write_bytes(content)
    assert main(["--config", str(path)]) == 1
    output = capsys.readouterr().out
    assert "Unable to read" in output
    assert "private-value" not in output
    assert "Traceback" not in output


def test_unreadable_config_has_safe_diagnostic(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "missing.toml")]) == 1
    assert "Unable to read" in capsys.readouterr().out


def test_cli_default_path_is_independent_of_working_directory(tmp_path):
    script = DEFAULT_CONFIG.parents[1] / "tools" / "check_config.py"
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    assert "no infrastructure was contacted" in result.stdout


def test_example_defines_only_blank_expected_secret_inputs():
    example = DEFAULT_CONFIG.parents[1] / ".env.example"
    assignments = dict(
        line.split("=", 1)
        for line in example.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert assignments.keys() == SECRET_NAMES
    assert not any(assignments.values())
