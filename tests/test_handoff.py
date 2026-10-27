"""Fresh and retained-storage identity reproduction in an isolated named-volume project."""

import json
import os
import secrets

import httpx
import pytest
from bootstrap_identity import TEMP_USER, Admin, create_realm, establish_admin
from configure_email import configure_capture
from configure_oidc import configure
from test_database import FixtureDatabase
from test_runtime import ROOT

PROJECT = "datalens-identity-handoff-tests"
VOLUME = PROJECT + "_postgres-data"


@pytest.mark.runtime
def test_fresh_setup_and_retained_storage_preserve_accounts_and_secret(tmp_path, monkeypatch):
    if os.environ.get("IDENTITY_RUNTIME_TESTS") != "1":
        if os.environ.get("CI"):
            pytest.fail("CI must enable runtime acceptance.")
        pytest.skip("Enable disposable runtime acceptance.")
    source = FixtureDatabase(
        [
            "-p",
            PROJECT,
            "-f",
            str(ROOT / "compose.test.yaml"),
            "-f",
            str(ROOT / "compose.runtime.test.yaml"),
        ]
    )
    rendered = source.command("config", "--format", "json")
    assert rendered.returncode == 0
    model = json.loads(rendered.stdout)
    assert model["name"] == PROJECT
    database = model["services"]["identity-postgres"]
    assert database["environment"]["POSTGRES_DB"] == "identity_test_db"
    assert not database.get("ports")
    database.pop("tmpfs")
    database["volumes"].append(
        {
            "type": "volume",
            "source": "postgres-data",
            "target": "/var/lib/postgresql/data",
        }
    )
    model["volumes"] = {"postgres-data": {"name": VOLUME}}
    model["services"]["identity-keycloak"]["environment"]["KC_HOSTNAME"] = "http://localhost:28081"
    for service in model["services"].values():
        for port in service.get("ports", []):
            port["published"] = str(int(port["published"]) + 10000)
            assert port["host_ip"] == "127.0.0.1"
    fixture_file = tmp_path / "handoff.json"
    fixture_file.write_text(json.dumps(model), encoding="utf-8")
    fixture = FixtureDatabase(["-p", PROJECT, "-f", str(fixture_file)])
    # Guard every destructive cleanup against a local/external storage target.
    assert set(model["volumes"]) == {"postgres-data"}
    assert model["volumes"]["postgres-data"] == {"name": VOLUME}
    assert VOLUME.startswith(PROJECT + "_")
    bootstrap_password = "Bootstrap-Test!" + secrets.token_urlsafe(24)
    permanent_password = "Permanent-Test!" + secrets.token_urlsafe(24)
    monkeypatch.setenv("KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD", bootstrap_password)
    origin = "http://localhost:28081"
    realm = "handoff-test"
    try:
        assert (
            fixture.command(
                "up", "-d", "--build", "--wait", "--wait-timeout", "180", timeout=240
            ).returncode
            == 0
        )
        fixture.check_target()
        assert fixture.command("stop", "identity-keycloak").returncode == 0
        try:
            assert (
                fixture.command(
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
                ).returncode
                == 0
            )
        finally:
            assert (
                fixture.command(
                    "up", "-d", "--wait", "--wait-timeout", "180", timeout=200
                ).returncode
                == 0
            )
        temporary = Admin(origin, TEMP_USER, bootstrap_password)
        try:
            temporary.client.timeout = httpx.Timeout(60)
            create_realm(temporary, realm)
            establish_admin(temporary, origin, "handoff-admin", permanent_password, realm)
        finally:
            temporary.close()
        admin = Admin(origin, "handoff-admin", permanent_password)
        try:
            client_id = configure(admin, realm, "http://localhost:28089")
            configure_capture(admin, realm)
            realm_id = admin.request("GET", realm).json()["id"]
            user_id = admin.request("GET", "master/users?username=handoff-admin&exact=true").json()[
                0
            ]["id"]
            secret = admin.request("GET", f"{realm}/clients/{client_id}/client-secret").json()[
                "value"
            ]
        finally:
            admin.close()
        # Remove containers/network only; the named test volume is deliberately retained.
        assert fixture.command("down").returncode == 0
        assert (
            fixture.command("up", "-d", "--wait", "--wait-timeout", "180", timeout=200).returncode
            == 0
        )
        fixture.check_target()
        admin = Admin(origin, "handoff-admin", permanent_password)
        try:
            create_realm(admin, realm)
            assert configure(admin, realm, "http://localhost:28089") == client_id
            configure_capture(admin, realm)
            assert admin.request("GET", realm).json()["id"] == realm_id
            assert (
                admin.request("GET", "master/users?username=handoff-admin&exact=true").json()[0][
                    "id"
                ]
                == user_id
            )
            assert (
                admin.request("GET", f"{realm}/clients/{client_id}/client-secret").json()["value"]
                == secret
            )
            assert (
                admin.request("GET", "master/users?username=identity-bootstrap&exact=true").json()
                == []
            )
        finally:
            admin.close()
    finally:
        assert fixture.command("down", "--volumes").returncode == 0
