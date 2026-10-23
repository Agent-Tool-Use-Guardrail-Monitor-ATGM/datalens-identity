"""Real browser PKCE acceptance, with synthetic identities and intercepted callbacks."""

import base64
import hashlib
import json
import os
import re
import secrets
import time
from html import unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Queue
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
from bootstrap_identity import Admin, create_realm
from configure_email import configure_capture
from configure_oidc import CLIENT, configure
from playwright.sync_api import sync_playwright
from test_database import FixtureDatabase
from test_runtime import ROOT


@pytest.mark.runtime
def test_invitation_activation_expiry_reuse_resend_and_smtp_failure(monkeypatch):
    if os.environ.get("IDENTITY_RUNTIME_TESTS") != "1":
        if os.environ.get("CI"):
            pytest.fail("CI must enable runtime acceptance.")
        pytest.skip("Enable disposable runtime acceptance.")
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
    admin_name = "email-test-" + secrets.token_hex(4)
    password = "Oidc-Test!" + secrets.token_urlsafe(24)
    monkeypatch.setenv("KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD", password)
    assert stack.command("stop", "identity-keycloak").returncode == 0
    try:
        assert (
            stack.command(
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
        assert stack.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
    origin = "http://localhost:18081"
    realm = "email-test-" + secrets.token_hex(4)
    callback = "http://localhost:18089/auth/callback"
    admin = Admin(origin, admin_name, password)
    try:
        admin.client.timeout = httpx.Timeout(60)
        create_realm(admin, realm)
        admin.close()
        admin = Admin(origin, admin_name, password)
        client_id = configure(admin, realm, "http://localhost:18089")
        client_secret = admin.request("GET", f"{realm}/clients/{client_id}/client-secret").json()[
            "value"
        ]
        assert configure(admin, realm, "http://localhost:18089") == client_id
        assert (
            admin.request("GET", f"{realm}/clients/{client_id}/client-secret").json()["value"]
            == client_secret
        )
        admin.request(
            "POST",
            realm + "/users",
            {
                "username": "analyst",
                "firstName": "Test",
                "lastName": "Analyst",
                "email": "analyst@example.invalid",
                "enabled": True,
                "requiredActions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
                "emailVerified": False,
            },
        )
        user_id = admin.request("GET", realm + "/users?username=analyst&exact=true").json()[0]["id"]
        role = admin.request("GET", f"{realm}/clients/{client_id}/roles/admin").json()
        admin.request("POST", f"{realm}/users/{user_id}/role-mappings/clients/{client_id}", [role])
        configure_capture(admin, realm)
        user_path = f"{realm}/users/{user_id}"
        assert admin.request("GET", user_path).json()["requiredActions"]
        assert admin.request("GET", user_path + "/credentials").json() == []
        mail = httpx.Client(base_url="http://localhost:18025", trust_env=False, timeout=10)

        def invite(path, lifetime=86400):
            before = {m["ID"] for m in mail.get("/api/v1/messages").json()["messages"]}
            admin.request(
                "PUT",
                path + f"/execute-actions-email?lifespan={lifetime}",
                ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
            )
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                for message in mail.get("/api/v1/messages").json()["messages"]:
                    if message["ID"] not in before:
                        body = mail.get("/api/v1/message/" + message["ID"]).json()
                        links = re.findall(r'href="([^"]+)"', body["HTML"])
                        return next(unescape(url) for url in links if "login-actions" in url)
                time.sleep(0.2)
            pytest.fail("Synthetic invitation was not captured.")

        expired = invite(user_path, 1)
        time.sleep(2)
        with sync_playwright() as driver:
            browser = driver.chromium.launch(args=["--no-proxy-server"])
            page = browser.new_page()
            page.goto(expired)
            assert page.locator("#password-new").count() == 0
            assert admin.request("GET", user_path).json()["emailVerified"] is False
            first = invite(user_path)
            second = invite(user_path)
            assert first != second
            assert admin.request("GET", user_path).json()["emailVerified"] is False
            page.goto(second)
            confirm = page.get_by_role("link", name="Click here to proceed")
            if confirm.count():
                confirm.click()
            page.locator("#password-new").fill(password)
            page.locator("#password-confirm").fill(password)
            page.locator('button[type="submit"], input[type="submit"]').click()
            page.wait_for_load_state()
            assert admin.request("GET", user_path).json()["emailVerified"] is True
            assert admin.request("GET", user_path).json()["requiredActions"] == []
            # A consumed invitation must not expose another password-reset form.
            page = browser.new_page()
            page.goto(second)
            assert page.locator("#password-new").count() == 0
            browser.close()
        # A delivery failure must leave an unverified account unverified.
        admin.request(
            "POST",
            realm + "/users",
            {
                "username": "delivery-failure",
                "enabled": True,
                "email": "failure@example.invalid",
                "emailVerified": False,
            },
        )
        failed_id = admin.request(
            "GET", realm + "/users?username=delivery-failure&exact=true"
        ).json()[0]["id"]
        admin.request(
            "PUT",
            realm,
            {
                "smtpServer": {
                    "host": "identity-mailpit",
                    "port": "1",
                    "from": "identity@example.invalid",
                }
            },
        )
        admin.request(
            "PUT",
            f"{realm}/users/{failed_id}/execute-actions-email",
            ["VERIFY_EMAIL"],
            expected=(500,),
        )
        assert admin.request("GET", f"{realm}/users/{failed_id}").json()["emailVerified"] is False
        configure_capture(admin, realm)
        mail.close()
        endpoint = origin + f"/realms/{realm}/protocol/openid-connect"
        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        parameters = {
            "client_id": CLIENT,
            "response_type": "code",
            "scope": "openid email",
            "redirect_uri": callback,
            "state": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        with sync_playwright() as playwright, httpx.Client(trust_env=False, timeout=15) as http:
            received = Queue()

            class Callback(BaseHTTPRequestHandler):
                def do_GET(self):
                    received.put("http://localhost:18089" + self.path)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Login complete")

                def log_message(self, *args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 18089), Callback)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            browser = playwright.chromium.launch(args=["--no-proxy-server"])

            def get_code():
                context = browser.new_context()
                try:
                    page = context.new_page()
                    page.goto(endpoint + "/auth?" + urlencode(parameters))
                    page.locator("#username").fill("analyst")
                    page.locator("#password").fill(password)
                    page.locator("#kc-login").click()
                    page.wait_for_url(lambda url: url.startswith(callback + "?"))
                    query = parse_qs(urlparse(received.get(timeout=5)).query)
                    assert query["state"] == [parameters["state"]]
                    return query["code"][0]
                finally:
                    context.close()

            def exchange(code, secret=client_secret, proof=verifier):
                return http.post(
                    endpoint + "/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": CLIENT,
                        "client_secret": secret,
                        "redirect_uri": callback,
                        "code": code,
                        "code_verifier": proof,
                    },
                )

            try:
                response = exchange(get_code())
                assert response.status_code == 200
                tokens = response.json()
                claims = json.loads(
                    base64.urlsafe_b64decode(tokens["access_token"].split(".")[1] + "==")
                )
                assert claims["iss"] == origin + "/realms/" + realm
                assert CLIENT in claims["aud"]
                assert claims["sub"] == user_id
                assert claims["email_verified"] is True
                assert set(claims["resource_access"][CLIENT]["roles"]) == {"admin", "user"}
                introspection = http.post(
                    endpoint + "/token/introspect",
                    data={
                        "client_id": CLIENT,
                        "client_secret": client_secret,
                        "token": tokens["access_token"],
                    },
                ).json()
                assert introspection["active"] is True
                assert introspection["email_verified"] is True
                assert set(introspection["resource_access"][CLIENT]["roles"]) == {"admin", "user"}
                assert (
                    http.get(
                        origin + "/admin/realms/master",
                        headers={"Authorization": "Bearer " + tokens["access_token"]},
                    ).status_code
                    == 403
                )
            finally:
                browser.close()
                server.shutdown()
                server.server_close()
                thread.join()
    finally:
        admin.close()
