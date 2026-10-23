"""Focused 2.4 acceptance against disposable Keycloak, never local accounts."""

import os
import secrets

import pytest
from bootstrap_identity import TEMP_USER, Admin, SetupError, create_realm, establish_admin
from test_database import FixtureDatabase
from test_runtime import ROOT, wait_for_status


@pytest.mark.runtime
def test_administrator_handoff_realm_defaults_restart_and_no_role_escalation(monkeypatch):
    if os.environ.get("IDENTITY_RUNTIME_TESTS") != "1":
        if os.environ.get("CI"):
            pytest.fail("CI must enable IDENTITY_RUNTIME_TESTS.")
        pytest.skip("Enable the disposable runtime fixture.")
    stack = FixtureDatabase(
        [
            "-p",
            "datalens-identity-tests",
            "-f",
            str(ROOT / "compose.test.yaml"),
            "-f",
            str(ROOT / "compose.runtime.test.yaml"),
        ]
    )
    stack.check_target()
    password = "Test-Only!" + secrets.token_urlsafe(24)
    permanent_password = "Permanent-Test!" + secrets.token_urlsafe(24)
    monkeypatch.setenv("KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD", password)
    assert stack.command("stop", "identity-keycloak").returncode == 0
    try:
        result = stack.command(
            "run",
            "--rm",
            "--no-deps",
            "-e",
            "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD",
            "identity-keycloak",
            "bootstrap-admin",
            "user",
            "--optimized",
            "--username",
            TEMP_USER,
            "--password:env",
            "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD",
            "--no-prompt",
            timeout=180,
        )
        assert result.returncode == 0, "Disposable offline administrator bootstrap failed."
    finally:
        assert stack.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
    origin = "http://localhost:18081"
    admin = Admin(origin, TEMP_USER, password)
    try:
        establish_admin(admin, origin, "platform-test-admin", permanent_password, "datalens-test")
    finally:
        admin.close()
    with pytest.raises(SetupError, match="authentication failed"):
        Admin(origin, TEMP_USER, password)
    permanent = Admin(origin, "platform-test-admin", permanent_password)
    try:
        realm = permanent.request("GET", "datalens-test").json()
        assert realm["registrationAllowed"] is False
        assert realm["verifyEmail"] is True
        assert realm["bruteForceProtected"] is True
        assert realm["accessTokenLifespan"] == 300
        assert realm["ssoSessionMaxLifespan"] == 28800
        assert realm["actionTokenGeneratedByAdminLifespan"] == 86400
        create_realm(permanent, "datalens-test")
        assert permanent.request("GET", "datalens-test").json()["id"] == realm["id"]
        # A normal identity with an application-like role cannot manage Keycloak.
        permanent.request("POST", "master/roles", {"name": "application-admin-test"})
        permanent.request(
            "POST",
            "master/users",
            {
                "username": "ordinary-test",
                "enabled": True,
                "credentials": [
                    {"type": "password", "value": permanent_password, "temporary": False}
                ],
            },
        )
        user_id = permanent.request("GET", "master/users?username=ordinary-test&exact=true").json()[
            0
        ]["id"]
        role = permanent.request("GET", "master/roles/application-admin-test").json()
        permanent.request("POST", f"master/users/{user_id}/role-mappings/realm", [role])
        ordinary = Admin(origin, "ordinary-test", permanent_password)
        try:
            with pytest.raises(SetupError, match="HTTP 403"):
                ordinary.request("GET", "master")
        finally:
            ordinary.close()
        permanent.request("DELETE", "master/users/" + user_id)
        permanent.request("DELETE", "master/roles/application-admin-test")
    finally:
        permanent.close()
    assert stack.command("restart", "--no-deps", "identity-keycloak").returncode == 0
    assert stack.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
    wait_for_status("/health/ready", 200)
    permanent = Admin(origin, "platform-test-admin", permanent_password)
    try:
        assert permanent.request("GET", "datalens-test").json()["id"] == realm["id"]
        assert (
            permanent.request("GET", "master/users?username=identity-bootstrap&exact=true").json()
            == []
        )
    finally:
        permanent.close()
