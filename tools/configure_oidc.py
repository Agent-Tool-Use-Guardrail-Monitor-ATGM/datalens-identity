"""Explicit application client setup; secrets stay in Keycloak, not exported files."""

import argparse
import getpass

import httpx
from bootstrap_identity import Admin, SetupError

CLIENT = "agent-api"


def configure(admin, realm, callback_origin):
    base = realm + "/clients"
    clients = admin.request("GET", base + "?clientId=" + CLIENT).json()
    desired = {
        "clientId": CLIENT,
        "protocol": "openid-connect",
        "enabled": True,
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "fullScopeAllowed": False,
        "redirectUris": [callback_origin + "/auth/callback"],
        "webOrigins": [],
        "defaultClientScopes": ["basic", "email"],
        "optionalClientScopes": [],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": callback_origin + "/",
            "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false",
        },
        "protocolMappers": [
            {
                "name": "agent-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": CLIENT,
                    "access.token.claim": "true",
                    "introspection.token.claim": "true",
                    "id.token.claim": "false",
                },
            },
            {
                "name": "agent-roles",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-client-role-mapper",
                "config": {
                    "usermodel.clientRoleMapping.clientId": CLIENT,
                    "claim.name": "resource_access.agent-api.roles",
                    "jsonType.label": "String",
                    "multivalued": "true",
                    "access.token.claim": "true",
                    "introspection.token.claim": "true",
                    "id.token.claim": "false",
                },
            },
        ],
    }
    if not clients:
        admin.request("POST", base, desired)
        clients = admin.request("GET", base + "?clientId=" + CLIENT).json()
    else:
        # Fail visibly on drift; never overwrite an existing secret or unknown settings.
        actual = admin.request("GET", base + "/" + clients[0]["id"]).json()
        for field in ("defaultClientScopes", "optionalClientScopes"):
            if set(actual.get(field, [])) != set(desired[field]):
                raise SetupError("Existing client scopes differ; review manually.")
        for mapper in desired["protocolMappers"]:
            matches = [m for m in actual.get("protocolMappers", []) if m["name"] == mapper["name"]]
            if (
                len(matches) != 1
                or any(matches[0].get(k) != v for k, v in mapper.items() if k != "config")
                or any(
                    matches[0].get("config", {}).get(k) != v for k, v in mapper["config"].items()
                )
            ):
                raise SetupError("Existing token mapper differs; review manually.")
        for key in desired.keys() - {
            "protocolMappers",
            "defaultClientScopes",
            "optionalClientScopes",
        }:
            if key == "attributes":
                if any(actual.get(key, {}).get(k) != v for k, v in desired[key].items()):
                    raise SetupError("Existing client attributes differ; review manually.")
            elif actual.get(key) != desired[key]:
                raise SetupError("Existing client differs; review manually.")
    client_id = clients[0]["id"]
    path = base + "/" + client_id
    for name in ("user", "admin"):
        if admin.request("GET", path + "/roles/" + name, expected=(200, 404)).status_code == 404:
            admin.request("POST", path + "/roles", {"name": name})
    roles = [admin.request("GET", path + "/roles/" + name).json() for name in ("user", "admin")]
    admin.request("POST", path + "/roles/admin/composites", [roles[0]])
    admin.request("POST", path + "/scope-mappings/clients/" + client_id, roles)
    admin.request("PUT", realm, {"revokeRefreshToken": True, "refreshTokenMaxReuse": 0})
    return client_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin", required=True)
    args = parser.parse_args()
    admin = Admin("http://localhost:8081", args.admin, getpass.getpass("Administrator password: "))
    try:
        configure(admin, "datalens", "http://localhost:8000")
    finally:
        admin.close()
    print("Application roles and OIDC client configured. Retrieve its secret through the console.")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, httpx.HTTPError, KeyError, ValueError):
        print("OIDC setup failed; inspect configuration securely.")
        raise SystemExit(1) from None
