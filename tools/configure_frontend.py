"""Explicit public PKCE client setup; never exports credentials or modifies agent-api."""

import argparse
import getpass
import re
from urllib.parse import urlsplit

import httpx
from bootstrap_identity import Admin, SetupError
from configure_oidc import CLIENT as API_CLIENT
from configure_oidc import api_token_mappers

CLIENT = "agent-web"


def origin(value, *, hosted=False):
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (
            not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.port == 0
            or any(c.isspace() or not c.isprintable() for c in value)
            or any(c in value for c in ("%", "\\", "*", "?", "#"))
            or host != host.lower()
            or not host.isascii()
            or parsed.geturl() != value
            or (parsed.scheme == "https" and parsed.port == 443)
            or (parsed.scheme == "http" and parsed.port == 80)
        ):
            raise ValueError
        authority = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            authority += f":{parsed.port}"
        if parsed.netloc != authority:
            raise ValueError
        if parsed.scheme != "https" and not (
            not hosted and parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise SetupError("Use an exact HTTPS origin, or explicit local loopback HTTP.") from None
    return value


def realm_identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
        raise SetupError("Invalid realm identifier.")
    return value


def client_definition(frontend_origin, *, hosted=False):
    frontend_origin = origin(frontend_origin, hosted=hosted)
    mappers = api_token_mappers()
    for mapper in mappers:
        mapper["config"]["userinfo.token.claim"] = "false"
    return {
        "clientId": CLIENT,
        "protocol": "openid-connect",
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "fullScopeAllowed": False,
        "redirectUris": [frontend_origin + "/auth/callback"],
        "webOrigins": [frontend_origin],
        "defaultClientScopes": ["basic", "email", "profile"],
        "optionalClientScopes": [],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": frontend_origin + "/",
            "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false",
        },
        "protocolMappers": mappers,
    }


def check_existing(actual, desired):
    for key, value in desired.items():
        if key == "protocolMappers":
            mappers = actual.get(key, [])
            if {item.get("name") for item in mappers} != {item["name"] for item in value}:
                raise SetupError("Existing frontend mappers differ; review manually.")
            for mapper in value:
                matches = [item for item in mappers if item.get("name") == mapper["name"]]
                if len(matches) != 1 or any(matches[0].get(k) != v for k, v in mapper.items()):
                    raise SetupError("Existing frontend mapper differs; review manually.")
        elif key == "attributes":
            if any(actual.get(key, {}).get(k) != v for k, v in value.items()):
                raise SetupError("Existing frontend attributes differ; review manually.")
        elif key.endswith("ClientScopes"):
            if set(actual.get(key, [])) != set(value):
                raise SetupError("Existing frontend scopes differ; review manually.")
        elif actual.get(key) != value:
            raise SetupError("Existing frontend client differs; review manually.")


def configure(admin, realm, frontend_origin, *, hosted=False):
    realm_identifier(realm)
    desired = client_definition(frontend_origin, hosted=hosted)
    base = realm + "/clients"
    api = admin.request("GET", base + "?clientId=" + API_CLIENT).json()
    if len(api) != 1:
        raise SetupError("Configure the existing agent-api client/roles first.")
    api_id = api[0]["id"]
    roles = [
        admin.request("GET", f"{base}/{api_id}/roles/{name}").json() for name in ("user", "admin")
    ]
    clients = admin.request("GET", base + "?clientId=" + CLIENT).json()
    if not clients:
        admin.request("POST", base, desired)
        clients = admin.request("GET", base + "?clientId=" + CLIENT).json()
    if len(clients) != 1:
        raise SetupError("Frontend client is not uniquely identified.")
    path = base + "/" + clients[0]["id"]
    check_existing(admin.request("GET", path).json(), desired)
    mapping = path + "/scope-mappings/clients/" + api_id
    actual = admin.request("GET", mapping).json()
    if any(role.get("name") not in {"user", "admin"} for role in actual):
        raise SetupError("Unexpected frontend role scope; review manually.")
    missing = [role for role in roles if role["id"] not in {item["id"] for item in actual}]
    if missing:
        admin.request("POST", mapping, missing)
    # Native Account Console owns edits; no custom password or user-management API.
    admin.request(
        "PUT",
        realm,
        {
            "editUsernameAllowed": True,
            "revokeRefreshToken": True,
            "refreshTokenMaxReuse": 0,
        },
    )
    return clients[0]["id"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin", required=True)
    parser.add_argument("--frontend-origin", required=True)
    parser.add_argument("--identity-origin", default="http://localhost:8081")
    parser.add_argument("--realm", default="datalens")
    parser.add_argument("--hosted", action="store_true")
    args = parser.parse_args(argv)
    try:
        identity_origin = origin(args.identity_origin, hosted=args.hosted)
        client_definition(args.frontend_origin, hosted=args.hosted)
        realm_identifier(args.realm)
        admin = Admin(identity_origin, args.admin, getpass.getpass("Administrator password: "))
        try:
            configure(admin, args.realm, args.frontend_origin, hosted=args.hosted)
        finally:
            admin.close()
    except (SetupError, httpx.HTTPError, KeyError, TypeError, ValueError):
        print("Frontend client setup failed; inspect configuration securely.")
        return 1
    print("Public frontend PKCE client and native username editing configured; no secret exported.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
