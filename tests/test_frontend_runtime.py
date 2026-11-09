"""Native public PKCE and Account Console acceptance on disposable Keycloak."""

import base64
import hashlib
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
from bootstrap_identity import Admin, SetupError, create_realm
from configure_frontend import CLIENT, configure
from configure_oidc import configure as configure_api
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
        admin.request("POST", f"{realm}/users/{user_id}/role-mappings/clients/{api_id}", [role])
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

            first, second = browser.new_context(), browser.new_context()
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
                updated = refresh(first_tokens["refresh_token"])
                assert updated.status_code == 200
                assert (
                    payload(updated.json()["access_token"])["preferred_username"]
                    == "renamed-analyst"
                )
                assert refresh(first_tokens["refresh_token"]).status_code == 400
                first_tokens = updated.json()
                page.goto(issuer + "/account/account-security/signing-in")
                page.locator('[data-testrole="update"]').click()
                page.locator("#password-new").fill("Updated-Test!29" + password)
                page.locator("#password-confirm").fill("Updated-Test!29" + password)
                checkbox = page.locator('input[name="logout-sessions"]')
                expect(checkbox).not_to_be_checked()
                checkbox.check()
                page.locator("#kc-submit").click()
                page.wait_for_url(lambda url: "/account/" in url)
                assert refresh(second_tokens["refresh_token"]).status_code == 400
                admin.request("POST", f"{realm}/users/{user_id}/logout")
                assert refresh(first_tokens["refresh_token"]).status_code == 400

                _, bad_code = login(second, "renamed-analyst", "Updated-Test!29" + password)
                assert exchange(bad_code, verifier="wrong" * 12).status_code == 400

                logout_context = browser.new_context()
                try:
                    logout_page, logout_code = login(
                        logout_context, "renamed-analyst", "Updated-Test!29" + password
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
                finally:
                    logout_context.close()

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
                            "password": "Updated-Test!29" + password,
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
                admin.request(
                    "PUT", f"{realm}/clients/{web_id}", {"redirectUris": [frontend + "/drift"]}
                )
                with pytest.raises(SetupError, match="differs"):
                    configure(admin, realm, frontend)
            finally:
                first.close()
                second.close()
                browser.close()
                server.shutdown()
                server.server_close()
                thread.join()
    finally:
        admin.close()
        cleanup = Admin(origin, admin_name, password)
        try:
            cleanup.request("DELETE", realm, expected=(204, 404))
        finally:
            cleanup.close()
