"""Explicit one-time local administrator setup; never run during normal startup."""

import argparse
import getpass
import json
import os
import secrets
import subprocess
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
TEMP_USER = "identity-bootstrap"


class SetupError(Exception):
    """Safe diagnostic without response bodies, passwords or tokens."""


class Admin:
    def __init__(self, origin, username, password):
        self.client = httpx.Client(base_url=origin, timeout=15, trust_env=False)
        response = self.client.post(
            "/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": username,
                "password": password,
            },
        )
        if response.status_code != 200:
            self.client.close()
            raise SetupError("Administrator authentication failed.")
        self.client.headers["Authorization"] = "Bearer " + response.json()["access_token"]

    def request(self, method, path, body=None, expected=(200, 201, 204)):
        response = self.client.request(method, "/admin/realms/" + path, json=body)
        if response.status_code not in expected:
            raise SetupError(f"Identity administration failed (HTTP {response.status_code}).")
        return response

    def close(self):
        self.client.close()


def create_realm(admin, realm):
    desired = json.loads((ROOT / "config/realm.json").read_text(encoding="utf-8"))
    response = admin.request("GET", realm, expected=(200, 404))
    if response.status_code == 404:
        admin.request("POST", "", {"realm": realm, **desired})
    else:
        actual = response.json()
        if any(actual.get(key) != value for key, value in desired.items()):
            raise SetupError("Existing realm differs from desired settings; review it manually.")
    # Existing users, credentials and clients are never imported or overwritten.


def validate_administrator(username, password):
    if username == TEMP_USER or not username.isascii() or not username.replace("-", "").isalnum():
        raise SetupError(
            "Use a distinct ASCII administrator name containing letters, digits or '-'."
        )
    if len(password) < 16:
        raise SetupError("Administrator password must contain at least 16 characters.")


def establish_admin(admin, origin, username, password, realm):
    validate_administrator(username, password)
    users = admin.request("GET", "master/users?username=" + username + "&exact=true").json()
    if users:
        raise SetupError(
            "Administrator already exists; verify access manually, never reset it blindly."
        )
    admin.request(
        "POST",
        "master/users",
        {
            "username": username,
            "enabled": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    user_id = admin.request("GET", "master/users?username=" + username + "&exact=true").json()[0][
        "id"
    ]
    role = admin.request("GET", "master/roles/admin").json()
    admin.request("POST", f"master/users/{user_id}/role-mappings/realm", [role])
    permanent = Admin(origin, username, password)
    try:
        permanent.request("GET", "master")
        create_realm(permanent, realm)
        # Verify the replacement before removing the temporary administrator.
        temporary = permanent.request(
            "GET", "master/users?username=" + TEMP_USER + "&exact=true"
        ).json()
        if len(temporary) != 1:
            raise SetupError("Temporary administrator not uniquely identified; review manually.")
        permanent.request("DELETE", "master/users/" + temporary[0]["id"])
    finally:
        permanent.close()


def compose(*arguments, environment=None):
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env.postgres",
            "-f",
            "compose.yaml",
            "-f",
            "compose.runtime.yaml",
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=240,
    )
    if result.returncode:
        raise SetupError("Identity setup command failed; inspect local container state securely.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin", required=True, help="Named permanent platform administrator")
    args = parser.parse_args()
    password = getpass.getpass("New administrator password (16+ characters): ")
    if password != getpass.getpass("Confirm password: ") or len(password) < 16:
        raise SetupError("Passwords must match and contain at least 16 characters.")
    validate_administrator(args.admin, password)
    temporary_password = secrets.token_urlsafe(32)
    environment = dict(os.environ, KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=temporary_password)
    # Local single-node topology only. Other nodes must be stopped before recovery.
    compose("stop", "identity-keycloak")
    running = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.project=datalens-identity-local",
            "--format",
            '{{.Label "com.docker.compose.service"}}',
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if running.returncode or set(running.stdout.splitlines()) - {
        "identity-postgres",
        "identity-mailpit",
    }:
        raise SetupError("Stop legacy or additional identity nodes before offline bootstrap.")
    compose("up", "-d", "--wait", "--wait-timeout", "90", "identity-postgres")
    try:
        compose(
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
            environment=environment,
        )
    finally:
        compose("up", "-d", "--wait", "--wait-timeout", "180")
    admin = Admin("http://localhost:8081", TEMP_USER, temporary_password)
    try:
        establish_admin(admin, "http://localhost:8081", args.admin, password, "datalens")
    finally:
        admin.close()
    print("Named administrator and realm verified; temporary access removed.")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, httpx.HTTPError, subprocess.SubprocessError, KeyError, ValueError) as error:
        # Never render raw exceptions: an HTTP response or command could contain secrets.
        print(str(error) if isinstance(error, SetupError) else "Identity setup failed safely.")
        raise SystemExit(1) from None
