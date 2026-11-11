"""Real Keycloak/JPA commit, rollback and concurrent revision proof."""

import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import httpx
import pytest
from bootstrap_identity import Admin, create_realm
from identity_events import decode_event
from test_runtime import runtime as runtime


@pytest.mark.runtime
def test_account_and_outbox_share_commit_rollback_and_revision_lock(runtime, monkeypatch):
    admin_name = "outbox-test-" + secrets.token_hex(4)
    password = "Outbox-Test!29" + secrets.token_urlsafe(24)
    monkeypatch.setenv("KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD", password)
    assert runtime.command("stop", "identity-keycloak").returncode == 0
    try:
        assert (
            runtime.command(
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
                admin_name,
                "--password:env",
                "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD",
                "--no-prompt",
                timeout=180,
            ).returncode
            == 0
        )
    finally:
        assert runtime.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
    origin = "http://localhost:18081"
    realm = "outbox-test-" + secrets.token_hex(4)
    issuer = origin + "/realms/" + realm
    admin = Admin(origin, admin_name, password)
    admin.client.timeout = httpx.Timeout(60)
    try:
        # Exercise real provider renewal after authentication rejects the access token.
        admin.client.headers["Authorization"] = "Bearer invalid-test-access-token"
        assert admin.request("GET", "master").status_code == 200
        assert admin.client.headers["Authorization"] != "Bearer invalid-test-access-token"
        create_realm(admin, realm)
        realm_id = str(UUID(admin.request("GET", realm).json()["id"]))
        admin.request("PUT", realm, {"eventsListeners": ["identity-outbox-proof"]})

        def events():
            rows = runtime.value(
                f"SELECT payload FROM dl_identity_outbox WHERE realm_id = '{realm_id}';"
            )
            return [decode_event(row.encode(), expected_issuer=issuer) for row in rows.splitlines()]

        admin.request("POST", realm + "/users", {"username": "proof-user", "enabled": True})
        user = admin.request("GET", realm + "/users?username=proof-user&exact=true").json()[0]
        subject = str(UUID(user["id"]))
        first = events()
        assert len(first) == 1 and first[0]["event_type"] == "user.created"
        assert first[0]["subject"] == subject
        assert first[0]["data"] == {
            "profile_revision": 1,
            "display_name": None,
            "username": "proof-user",
            "email": None,
        }

        def update(index):
            return admin.request(
                "PUT",
                f"{realm}/users/{subject}",
                {"firstName": f"Name-{index}"},
                expected=(204,),
            ).status_code

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert list(pool.map(update, range(4))) == [204] * 4
        snapshots = events()
        assert sorted(e["data"]["profile_revision"] for e in snapshots) == [1, 2, 3, 4, 5]
        assert len({e["event_id"] for e in snapshots}) == 5
        assert (
            runtime.value(
                f"SELECT profile_revision, security_revision FROM dl_identity_revision "
                f"WHERE realm_id = '{realm_id}' AND subject = '{subject}';"
            )
            == "5|0"
        )
        before = admin.request("GET", f"{realm}/users/{subject}").json()["firstName"]

        # Valid individual name lengths can still exceed the combined display contract.
        assert admin.request(
            "PUT",
            f"{realm}/users/{subject}",
            {"firstName": "a" * 200, "lastName": "b" * 200},
            expected=(400, 500),
        ).status_code in (400, 500)
        assert admin.request("GET", f"{realm}/users/{subject}").json()["firstName"] == before
        assert len(events()) == 5

        # Immediate storage failure must not be swallowed into an account-only commit.
        assert (
            runtime.sql(
                "ALTER TABLE dl_identity_outbox ADD CONSTRAINT dl_proof_reject "
                "CHECK(false) NOT VALID;"
            ).returncode
            == 0
        )
        try:
            failed = admin.request(
                "PUT",
                f"{realm}/users/{subject}",
                {"firstName": "must-rollback"},
                expected=(400, 500),
            )
            assert failed.status_code in (400, 500)
        finally:
            assert (
                runtime.sql(
                    "ALTER TABLE dl_identity_outbox DROP CONSTRAINT dl_proof_reject;"
                ).returncode
                == 0
            )
        assert admin.request("GET", f"{realm}/users/{subject}").json()["firstName"] == before
        assert len(events()) == 5

        # This trigger fails only at commit, after listener persist/flush succeeded.
        assert (
            runtime.sql("""
            CREATE FUNCTION dl_identity_proof_fail() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Disposable commit failure'; END $$;
            CREATE CONSTRAINT TRIGGER dl_identity_proof_fail AFTER INSERT ON dl_identity_outbox
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dl_identity_proof_fail();
        """).returncode
            == 0
        )
        try:
            assert (
                admin.request(
                    "POST",
                    realm + "/users",
                    {"username": "must-not-exist", "enabled": True},
                    expected=(500,),
                ).status_code
                == 500
            )
        finally:
            assert (
                runtime.sql("""
                DROP TRIGGER dl_identity_proof_fail ON dl_identity_outbox;
                DROP FUNCTION dl_identity_proof_fail();
            """).returncode
                == 0
            )
        assert (
            admin.request("GET", realm + "/users?username=must-not-exist&exact=true").json() == []
        )
        assert len(events()) == 5
        assert (
            runtime.value(
                f"SELECT count(*) FROM dl_identity_revision WHERE realm_id = '{realm_id}';"
            )
            == "1"
        )

        update(5)
        assert sorted(e["data"]["profile_revision"] for e in events()) == [1, 2, 3, 4, 5, 6]
        saved = {e["event_id"]: e for e in events()}
        admin.request("DELETE", f"{realm}/users/{subject}")
        assert {e["event_id"]: e for e in events()} == saved
        assert runtime.command("restart", "--no-deps", "identity-keycloak").returncode == 0
        assert runtime.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
        assert {e["event_id"]: e for e in events()} == saved
        assert all(len(json.dumps(e).encode()) <= 16384 for e in saved.values())
    finally:
        admin.close()
        cleanup = Admin(origin, admin_name, password)
        try:
            cleanup.request("DELETE", realm, expected=(204, 404))
        finally:
            cleanup.close()
