"""Real native readiness, database failure and restart checks on disposable storage."""

import json
import os
import time
from pathlib import Path

import httpx
import pytest
from check_config import read_config
from test_database import FixtureDatabase

ROOT = Path(__file__).resolve().parents[1]
SERVICE = "identity-keycloak"
MANAGEMENT = "http://localhost:19001"


def wait_for_status(path, expected, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = httpx.get(MANAGEMENT + path, timeout=2, trust_env=False)
            if response.status_code == expected:
                return response
        except httpx.HTTPError:
            pass
        time.sleep(1)
    pytest.fail(f"Native {path} did not return {expected} within {timeout}s.")


@pytest.fixture
def runtime():
    if os.environ.get("IDENTITY_RUNTIME_TESTS") != "1":
        if os.environ.get("CI"):
            pytest.fail("CI must enable IDENTITY_RUNTIME_TESTS.")
        pytest.skip("Start both test Compose files and set IDENTITY_RUNTIME_TESTS=1.")
    fixture = FixtureDatabase(
        [
            "-p",
            "datalens-identity-tests",
            "-f",
            str(ROOT / "compose.test.yaml"),
            "-f",
            str(ROOT / "compose.runtime.test.yaml"),
        ]
    )
    fixture.check_target()
    wait_for_status("/health/ready", 200)
    return fixture


@pytest.mark.runtime
def test_runtime_contract_and_database_aware_native_health(runtime):
    result = runtime.command("config", "--format", "json")
    assert result.returncode == 0
    model = json.loads(result.stdout)
    service = model["services"][SERVICE]
    assert service["command"] == ["start", "--optimized"]
    assert all(port["host_ip"] == "127.0.0.1" for port in service["ports"])
    assert not any("BOOTSTRAP" in key for key in service["environment"])
    assert not model.get("volumes")
    assert read_config()["images"]["keycloak"] in (ROOT / "docker/keycloak/Dockerfile").read_text()
    for path in ("/health/live", "/health/ready"):
        body = wait_for_status(path, 200).json()
        assert body["status"] == "UP"
    checks = wait_for_status("/health/ready", 200).json()["checks"]
    assert any("database" in check["name"].lower() for check in checks)
    discovery = httpx.get(
        "http://localhost:18081/realms/master/.well-known/openid-configuration",
        timeout=5,
        trust_env=False,
    )
    assert discovery.status_code == 200
    assert discovery.json()["issuer"] == "http://localhost:18081/realms/master"
    assert (
        httpx.get("http://localhost:18081/health/ready", timeout=5, trust_env=False).status_code
        == 404
    )


@pytest.mark.runtime
def test_keycloak_restart_retains_schema_and_master_realm(runtime):
    realm_id = runtime.value("SELECT id FROM realm WHERE name = 'master';")
    assert realm_id
    assert runtime.command("restart", "--no-deps", SERVICE).returncode == 0
    assert runtime.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
    wait_for_status("/health/ready", 200)
    assert runtime.value("SELECT id FROM realm WHERE name = 'master';") == realm_id


@pytest.mark.runtime
def test_wrong_database_password_cannot_start_runtime(runtime):
    result = runtime.command(
        "run",
        "--rm",
        "--no-deps",
        "-e",
        "KC_DB_PASSWORD=wrong-test-only-password",
        SERVICE,
        timeout=120,
    )
    assert result.returncode != 0
    # The healthy fixture must remain unaffected by the failed one-off container.
    wait_for_status("/health/ready", 200)


@pytest.mark.runtime
def test_database_outage_removes_readiness_and_restart_recovers(runtime):
    try:
        assert runtime.command("stop", "identity-postgres").returncode == 0
        assert wait_for_status("/health/ready", 503).json()["status"] == "DOWN"
    finally:
        assert (
            runtime.command(
                "up", "-d", "--wait", "--wait-timeout", "90", "identity-postgres"
            ).returncode
            == 0
        )
        # Explicit restart is the supported recovery path; no automatic guarantee.
        assert runtime.command("restart", "--no-deps", SERVICE).returncode == 0
        assert runtime.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
    wait_for_status("/health/ready", 200)
