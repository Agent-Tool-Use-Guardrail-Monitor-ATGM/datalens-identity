"""Native public PKCE and Account Console acceptance on disposable Keycloak."""

import base64
import hashlib
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import UUID

import httpx
import pytest
from bootstrap_identity import Admin, SetupError, create_realm
from configure_frontend import CLIENT, configure
from configure_oidc import configure as configure_api
from identity_events import decode_event
from playwright.sync_api import expect, sync_playwright
from test_runtime import runtime as runtime


def payload(value):
    # Inspection is paired with provider introspection; this is not JWT verification.
    return json.loads(base64.urlsafe_b64decode(value.split(".")[1] + "=="))


@pytest.mark.runtime
def test_public_pkce_roles_account_edits_password_sessions_and_legacy_preservation(
    runtime, monkeypatch
):
    admin_name = "frontend-test-" + secrets.token_hex(4)
    password = "Frontend-Test!29" + secrets.token_urlsafe(24)
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
    origin, frontend = "http://localhost:18081", "http://localhost:18089"
    realm = "frontend-test-" + secrets.token_hex(4)
    admin = Admin(origin, admin_name, password)
    admin.client.timeout = httpx.Timeout(60)
    try:
        create_realm(admin, realm)
        realm_id = str(UUID(admin.request("GET", realm).json()["id"]))
        admin.request("PUT", realm, {"eventsListeners": ["identity-outbox-proof"]})

        def outbox_events():
            rows = runtime.value(
                f"SELECT payload FROM dl_identity_outbox WHERE realm_id = '{realm_id}';"
            )
            return [
                decode_event(row.encode(), expected_issuer=origin + "/realms/" + realm)
                for row in rows.splitlines()
            ]

        def profiles():
            return sorted(
                (e for e in outbox_events() if "profile_revision" in e["data"]),
                key=lambda e: e["data"]["profile_revision"],
            )

        def security_events():
            return sorted(
                (e for e in outbox_events() if "security_revision" in e["data"]),
                key=lambda e: e["data"]["security_revision"],
            )

        api_id = configure_api(admin, realm, frontend)
        legacy = admin.request("GET", f"{realm}/clients/{api_id}").json()
        secret = admin.request("GET", f"{realm}/clients/{api_id}/client-secret").json()["value"]
        web_id = configure(admin, realm, frontend)
        assert configure(admin, realm, frontend) == web_id
        assert admin.request("GET", f"{realm}/clients/{api_id}").json() == legacy
        assert (
            admin.request("GET", f"{realm}/clients/{api_id}/client-secret").json()["value"]
            == secret
        )
        admin.request(
            "POST",
            realm + "/users",
            {
                "username": "analyst",
                "email": "analyst@example.invalid",
                "emailVerified": True,
                "firstName": "Test",
                "lastName": "Analyst",
                "enabled": True,
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
        user_id = admin.request("GET", realm + "/users?username=analyst&exact=true").json()[0]["id"]
        role = admin.request("GET", f"{realm}/clients/{api_id}/roles/admin").json()
        role_path = f"{realm}/users/{user_id}/role-mappings/clients/{api_id}"
        admin.request("POST", role_path, [role])
        assert security_events()[0]["data"]["reason"] == "roles_changed"
        assert len(profiles()) == 1
        assert profiles()[0]["event_type"] == "user.created"
        assert profiles()[0]["data"]["profile_revision"] == 1
        issuer = origin + "/realms/" + realm
        endpoint, callback = issuer + "/protocol/openid-connect", frontend + "/auth/callback"
        proof = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(proof.encode()).digest()).decode().rstrip("=")
        )
        parameters = {
            "client_id": CLIENT,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": callback,
            "state": secrets.token_urlsafe(24),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        with sync_playwright() as playwright, httpx.Client(trust_env=False, timeout=30) as http:

            class Callback(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Complete")

                def log_message(self, *args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 18089), Callback)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            browser = playwright.chromium.launch(args=["--no-proxy-server"])

            def login(context, username="analyst", current_password=password):
                page = context.new_page()
                page.goto(endpoint + "/auth?" + urlencode(parameters))
                page.locator("#username").fill(username)
                page.locator("#password").fill(current_password)
                page.locator("#kc-login").click()
                page.wait_for_url(lambda url: url.startswith(callback + "?"))
                query = parse_qs(urlparse(page.url).query)
                assert query["state"] == [parameters["state"]]
                return page, query["code"][0]

            def exchange(code, verifier=proof):
                return http.post(
                    endpoint + "/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": CLIENT,
                        "code": code,
                        "redirect_uri": callback,
                        "code_verifier": verifier,
                    },
                )

            def refresh(value):
                return http.post(
                    endpoint + "/token",
                    data={
                        "grant_type": "refresh_token",
                        "client_id": CLIENT,
                        "refresh_token": value,
                    },
                )

            first, second, profile_context = (browser.new_context() for _ in range(3))
            try:
                page, code = login(first)
                response = exchange(code)
                assert response.status_code == 200
                first_tokens = response.json()
                claims = payload(first_tokens["access_token"])
                audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
                assert "agent-api" in audience and claims["azp"] == CLIENT
                assert claims["sub"] == user_id and claims["email_verified"] is True
                assert (
                    claims["name"] == "Test Analyst" and claims["preferred_username"] == "analyst"
                )
                assert claims["email"] == "analyst@example.invalid" and claims.get("sid")
                assert set(claims["resource_access"]["agent-api"]["roles"]) == {"user", "admin"}
                introspection = http.post(
                    endpoint + "/token/introspect",
                    data={
                        "client_id": "agent-api",
                        "client_secret": secret,
                        "token": first_tokens["access_token"],
                    },
                ).json()
                assert introspection["active"] is True and introspection["sub"] == user_id
                assert (
                    http.get(
                        origin + "/admin/realms/master",
                        headers={"Authorization": "Bearer " + first_tokens["access_token"]},
                    ).status_code
                    == 403
                )
                _, other_code = login(second)
                second_tokens = exchange(other_code).json()
                assert payload(second_tokens["access_token"])["sid"] != claims["sid"]
                page.goto(issuer + "/account/")
                page.locator("#username").fill("renamed-analyst")
                with page.expect_response(
                    lambda r: r.request.method == "POST" and "/account/" in r.url
                ) as saved:
                    page.get_by_test_id("save").click()
                assert saved.value.status in (200, 204)
                assert (
                    admin.request("GET", f"{realm}/users/{user_id}").json()["username"]
                    == "renamed-analyst"
                )
                assert page.locator('input[type="file"], input[name="picture"]').count() == 0
                snapshots = profiles()
                assert len(snapshots) == 2 and snapshots[-1]["subject"] == user_id
                assert snapshots[-1]["event_type"] == "user.profile.updated"
                assert snapshots[-1]["data"] == {
                    "profile_revision": 2,
                    "display_name": "Test Analyst",
                    "username": "renamed-analyst",
                    "email": "analyst@example.invalid",
                }
                page.locator("#firstName").fill("a" * 200)
                page.locator("#lastName").fill("b" * 200)
                with page.expect_response(
                    lambda r: r.request.method == "POST" and "/account/" in r.url
                ) as rejected:
                    page.get_by_test_id("save").click()
                assert rejected.value.status == 500
                assert rejected.value.json() == {"error": "identity_event_persistence_failed"}
                assert "no-store" in rejected.value.headers.get("cache-control", "")
                assert len(profiles()) == 2
                unchanged = admin.request("GET", f"{realm}/users/{user_id}").json()
                assert unchanged["firstName"] == "Test" and unchanged["lastName"] == "Analyst"
                page.reload()
                page.locator("#firstName").fill("Updated")
                page.locator("#lastName").fill("Analyst")
                with page.expect_response(
                    lambda r: r.request.method == "POST" and "/account/" in r.url
                ) as renamed:
                    page.get_by_test_id("save").click()
                assert renamed.value.status in (200, 204)
                assert profiles()[-1]["data"]["display_name"] == "Updated Analyst"
                assert len(profiles()) == 3
                updated = refresh(first_tokens["refresh_token"])
                assert updated.status_code == 200
                assert (
                    payload(updated.json()["access_token"])["preferred_username"]
                    == "renamed-analyst"
                )
                assert refresh(first_tokens["refresh_token"]).status_code == 400
                # Start a fresh token chain after the deliberate replay, using the same SSO session.
                page.goto(endpoint + "/auth?" + urlencode(parameters | {"prompt": "none"}))
                page.wait_for_url(lambda url: url.startswith(callback + "?"))
                sso_code = parse_qs(urlparse(page.url).query)["code"][0]
                first_tokens = exchange(sso_code).json()
                assert payload(first_tokens["access_token"])["sid"] == claims["sid"]
                for index, checked in enumerate((False, True), start=1):
                    current_password = f"Updated-{index}!29" + password
                    before_change = security_events()[-1]["data"]["security_revision"]
                    page.goto(issuer + "/account/account-security/signing-in")
                    page.locator('[data-testrole="update"]').click()
                    page.locator("#password-new").fill(current_password)
                    page.locator("#password-confirm").fill(current_password)
                    checkbox = page.locator('input[name="logout-sessions"]')
                    expect(checkbox).not_to_be_checked()
                    if checked:
                        checkbox.check()
                    page.locator("#kc-submit").click()
                    page.wait_for_url(lambda url: "/account/" in url)
                    assert refresh(second_tokens["refresh_token"]).status_code == 400
                    current_refresh = refresh(first_tokens["refresh_token"])
                    assert current_refresh.status_code == 200, current_refresh.json().get(
                        "error_description"
                    )
                    first_tokens = current_refresh.json()
                    assert payload(first_tokens["access_token"])["sid"] == claims["sid"]
                    changes = [
                        event
                        for event in security_events()
                        if event["data"]["security_revision"] > before_change
                        and event["event_type"] == "user.sessions.revoked"
                    ]
                    assert len(changes) == 1
                    assert changes[0]["subject"] == user_id
                    assert changes[0]["data"]["reason"] == "password_changed"
                    assert (
                        changes[0]["data"]["tokens_issued_at_or_before"]
                        >= payload(second_tokens["access_token"])["iat"]
                    )
                    if not checked:
                        _, code = login(second, "renamed-analyst", current_password)
                        second_tokens = exchange(code).json()

                admin.request("POST", f"{realm}/users/{user_id}/logout")
                assert refresh(first_tokens["refresh_token"]).status_code == 400
                logout_all = security_events()[-1]
                assert logout_all["event_type"] == "user.sessions.revoked"
                assert logout_all["data"]["reason"] == "logout_all"
                assert logout_all["data"]["tokens_issued_at_or_before"] >= claims["iat"]

                _, bad_code = login(second, "renamed-analyst", current_password)
                assert exchange(bad_code, verifier="wrong" * 12).status_code == 400

                logout_context = browser.new_context()
                try:
                    logout_page, logout_code = login(
                        logout_context, "renamed-analyst", current_password
                    )
                    logout_response = exchange(logout_code)
                    assert logout_response.status_code == 200
                    logout_tokens = logout_response.json()
                    logout_state = secrets.token_urlsafe(24)
                    logout_page.goto(
                        endpoint
                        + "/logout?"
                        + urlencode(
                            {
                                "id_token_hint": logout_tokens["id_token"],
                                "post_logout_redirect_uri": frontend + "/",
                                "state": logout_state,
                            }
                        )
                    )
                    logout_page.wait_for_url(lambda url: url.startswith(frontend + "/?"))
                    assert parse_qs(urlparse(logout_page.url).query)["state"] == [logout_state]
                    assert refresh(logout_tokens["refresh_token"]).status_code == 400
                    native = security_events()[-1]
                    assert native["event_type"] == "user.session.revoked"
                    assert native["subject"] == user_id
                    assert native["data"]["reason"] == "logout"
                    assert (
                        native["data"]["session_id"]
                        == payload(logout_tokens["access_token"])["sid"]
                    )
                finally:
                    logout_context.close()

                admin_logout_context = browser.new_context()
                try:
                    _, code = login(admin_logout_context, "renamed-analyst", current_password)
                    admin_logout_tokens = exchange(code).json()
                    sid = payload(admin_logout_tokens["access_token"])["sid"]
                    session_path = f"{realm}/sessions/{sid}"
                    assert (
                        http.delete(
                            origin + "/admin/realms/" + session_path,
                            headers={
                                "Authorization": "Bearer " + admin_logout_tokens["access_token"]
                            },
                        ).status_code
                        == 403
                    )
                    assert security_events()[-1] == native
                    assert (
                        runtime.sql("""
                        ALTER TABLE dl_identity_outbox ADD CONSTRAINT dl_logout_reject
                        CHECK ((payload::jsonb -> 'data' ->> 'reason') <> 'admin_session_logout')
                        NOT VALID;
                        """).returncode
                        == 0
                    )
                    try:
                        failed_logout = admin.request("DELETE", session_path, expected=(500,))
                        assert failed_logout.json() == {
                            "error": "identity_event_persistence_failed"
                        }
                        assert security_events()[-1] == native
                        still_active = refresh(admin_logout_tokens["refresh_token"])
                        assert still_active.status_code == 200
                    finally:
                        assert (
                            runtime.sql(
                                "ALTER TABLE dl_identity_outbox DROP CONSTRAINT dl_logout_reject;"
                            ).returncode
                            == 0
                        )
                    admin.request("DELETE", session_path)
                    assert refresh(still_active.json()["refresh_token"]).status_code == 400
                    revoked = security_events()[-1]
                    assert revoked["event_type"] == "user.session.revoked"
                    assert revoked["subject"] == user_id
                    assert revoked["data"] == {
                        "security_revision": native["data"]["security_revision"] + 1,
                        "session_id": sid,
                        "reason": "admin_session_logout",
                    }
                    admin.request("DELETE", session_path, expected=(404,))
                    assert security_events()[-1] == revoked
                finally:
                    admin_logout_context.close()

                for changed in (
                    {"redirect_uri": frontend + "/evil"},
                    {"code_challenge": "", "code_challenge_method": ""},
                    {"response_type": "token"},
                ):
                    denied = http.get(endpoint + "/auth", params=parameters | changed)
                    if denied.status_code == 302:
                        target = urlparse(denied.headers["location"])
                        assert target._replace(query="", fragment="").geturl() == callback
                        error = parse_qs(target.query) | parse_qs(target.fragment)
                        assert error.get("error") and not error.get("code")
                        assert not error.get("access_token") and not error.get("id_token")
                    else:
                        assert denied.status_code == 400
                for grant in ("password", "client_credentials"):
                    assert http.post(
                        endpoint + "/token",
                        data={
                            "client_id": CLIENT,
                            "grant_type": grant,
                            "username": "renamed-analyst",
                            "password": current_password,
                        },
                    ).status_code in (400, 401)
                # Client-bound token responses enforce origins; preflight has no client identity.
                preflight = http.post(
                    endpoint + "/token",
                    data={
                        "client_id": CLIENT,
                        "grant_type": "refresh_token",
                        "refresh_token": "invalid-test-only",
                    },
                    headers={
                        "Origin": frontend,
                    },
                )
                assert preflight.headers.get("access-control-allow-origin") == frontend
                bad = http.post(
                    endpoint + "/token",
                    data={
                        "client_id": CLIENT,
                        "grant_type": "refresh_token",
                        "refresh_token": "invalid-test-only",
                    },
                    headers={
                        "Origin": "https://untrusted.example",
                    },
                )
                assert bad.headers.get("access-control-allow-origin") is None
                # Credential/login/token/client operations must not fabricate profile updates.
                assert len(profiles()) == 3
                _, profile_code = login(profile_context, "renamed-analyst", current_password)
                profile_tokens = exchange(profile_code).json()
                reset_path = f"{realm}/users/{user_id}/reset-password"
                reset_password = "Admin-Reset!29" + password
                reset_body = {"type": "password", "value": reset_password, "temporary": False}
                admin.request("PUT", reset_path, reset_body | {"value": ""}, expected=(400,))
                assert security_events()[-1] == revoked
                assert (
                    runtime.sql("""
                    ALTER TABLE dl_identity_outbox ADD CONSTRAINT dl_password_reject
                    CHECK ((payload::jsonb -> 'data' ->> 'reason') <> 'admin_password_reset')
                    NOT VALID;
                    """).returncode
                    == 0
                )
                other_context = browser.new_context()
                try:
                    try:
                        failed_reset = admin.request("PUT", reset_path, reset_body, expected=(500,))
                        assert failed_reset.json() == {"error": "identity_event_persistence_failed"}
                        assert security_events()[-1] == revoked
                        active = refresh(profile_tokens["refresh_token"])
                        assert active.status_code == 200
                        _, code = login(other_context, "renamed-analyst", current_password)
                        other_tokens = exchange(code).json()
                    finally:
                        assert (
                            runtime.sql(
                                "ALTER TABLE dl_identity_outbox DROP CONSTRAINT dl_password_reject;"
                            ).returncode
                            == 0
                        )
                    admin.request("PUT", reset_path, reset_body)
                    assert refresh(active.json()["refresh_token"]).status_code == 400
                    assert refresh(other_tokens["refresh_token"]).status_code == 400
                    assert admin.request("GET", f"{realm}/users/{user_id}/sessions").json() == []
                    reset_event = security_events()[-1]
                    assert reset_event["event_type"] == "user.sessions.revoked"
                    assert reset_event["subject"] == user_id
                    assert reset_event["data"]["reason"] == "admin_password_reset"
                    assert (
                        reset_event["data"]["security_revision"]
                        == revoked["data"]["security_revision"] + 1
                    )
                    assert (
                        reset_event["data"]["tokens_issued_at_or_before"]
                        >= payload(other_tokens["access_token"])["iat"]
                    )
                finally:
                    other_context.close()
                email_page, profile_code = login(profile_context, "renamed-analyst", reset_password)
                assert exchange(profile_code).status_code == 200
                email_page.goto(issuer + "/account/")
                email_page.locator("#email").fill("changed@example.invalid")
                assert (
                    runtime.sql(
                        "ALTER TABLE dl_identity_outbox ADD CONSTRAINT dl_native_reject "
                        "CHECK(false) NOT VALID;"
                    ).returncode
                    == 0
                )
                try:
                    with email_page.expect_response(
                        lambda r: r.request.method == "POST" and "/account/" in r.url
                    ) as unavailable:
                        email_page.get_by_test_id("save").click()
                    assert unavailable.value.status == 500
                    assert unavailable.value.json() == {
                        "error": "identity_event_persistence_failed"
                    }
                finally:
                    assert (
                        runtime.sql(
                            "ALTER TABLE dl_identity_outbox DROP CONSTRAINT dl_native_reject;"
                        ).returncode
                        == 0
                    )
                assert len(profiles()) == 3
                assert admin.request("GET", f"{realm}/users/{user_id}").json()["email"] == (
                    "analyst@example.invalid"
                )
                email_page.reload()
                email_page.locator("#email").fill("changed@example.invalid")
                with email_page.expect_response(
                    lambda r: r.request.method == "POST" and "/account/" in r.url
                ) as email_saved:
                    email_page.get_by_test_id("save").click()
                assert email_saved.value.status in (200, 204)
                assert profiles()[-1]["data"] == {
                    "profile_revision": 4,
                    "display_name": "Updated Analyst",
                    "username": "renamed-analyst",
                    "email": "changed@example.invalid",
                }
                assert len(profiles()) == 4
                admin.request(
                    "PUT",
                    f"{realm}/users/{user_id}",
                    {
                        "firstName": "",
                        "lastName": "",
                        "email": "",
                    },
                )
                assert profiles()[-1]["data"] == {
                    "profile_revision": 5,
                    "display_name": None,
                    "username": "renamed-analyst",
                    "email": None,
                }
                assert len(profiles()) == 5
                admin.request("DELETE", role_path, [role])
                changed_roles = security_events()[-1]
                assert changed_roles["event_type"] == "user.sessions.revoked"
                assert changed_roles["subject"] == user_id
                assert changed_roles["data"]["reason"] == "roles_changed"
                assert (
                    changed_roles["data"]["security_revision"]
                    == reset_event["data"]["security_revision"] + 1
                )
                admin.request(
                    "PUT", f"{realm}/clients/{web_id}", {"redirectUris": [frontend + "/drift"]}
                )
                with pytest.raises(SetupError, match="differs"):
                    configure(admin, realm, frontend)
            finally:
                first.close()
                second.close()
                profile_context.close()
                browser.close()
                server.shutdown()
                server.server_close()
                thread.join()
    finally:
        original = sys.exception()
        admin.close()
        cleanup = Admin(origin, admin_name, password)
        try:
            cleanup.request("DELETE", realm, expected=(204, 404))
        except Exception as cleanup_failure:
            if original is not None:
                raise original from cleanup_failure
            raise
        finally:
            cleanup.close()
