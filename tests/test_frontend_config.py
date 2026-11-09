"""Public-client least privilege and exact-origin configuration before admin I/O."""

import copy

import pytest
from bootstrap_identity import SetupError
from configure_frontend import check_existing, client_definition, configure, main, origin
from configure_oidc import api_token_mappers


@pytest.mark.parametrize(
    "value",
    [
        "http://public.example",
        "https://web.example/path",
        "https://web.example/",
        "https://user:password@web.example",
        "https://*.web.example",
        "https://web.example?x=y",
        "https://web.example#fragment",
        "https://web.example\\evil",
        "https://web.example:0",
        "https://web.example:443",
        "http://localhost:80",
        "HTTPS://web.example",
    ],
)
def test_invalid_frontend_origins_are_rejected(value):
    with pytest.raises(SetupError):
        client_definition(value)


def test_hosted_uses_https_and_public_client_has_no_credential_or_implicit_grant():
    assert origin("https://web.example", hosted=True) == "https://web.example"
    with pytest.raises(SetupError):
        origin("http://localhost:5173", hosted=True)
    value = client_definition("http://localhost:5173")
    assert value["publicClient"] and value["standardFlowEnabled"]
    assert not any(
        value[key]
        for key in (
            "implicitFlowEnabled",
            "directAccessGrantsEnabled",
            "serviceAccountsEnabled",
            "fullScopeAllowed",
        )
    )
    assert value["webOrigins"] == ["http://localhost:5173"]
    assert value["redirectUris"] == ["http://localhost:5173/auth/callback"]
    assert value["attributes"]["pkce.code.challenge.method"] == "S256"
    assert value["defaultClientScopes"] == ["basic", "email", "profile"]
    assert "secret" not in value and "picture" not in str(value)
    assert all(m["config"]["userinfo.token.claim"] == "false" for m in value["protocolMappers"])
    mappers = api_token_mappers()
    mappers[0]["config"]["included.client.audience"] = "changed"
    assert api_token_mappers()[0]["config"]["included.client.audience"] == "agent-api"


def test_mapper_normalization_does_not_relax_audience_drift_checks():
    desired = client_definition("http://localhost:5173")
    actual = copy.deepcopy(desired)
    actual["protocolMappers"][0]["id"] = "provider-generated-id"
    check_existing(actual, desired)
    actual["protocolMappers"][0]["config"]["included.client.audience"] = "wrong-api"
    with pytest.raises(SetupError, match="mapper differs"):
        check_existing(actual, desired)


def test_invalid_input_never_reaches_admin_and_cli_diagnostics_are_safe(capsys):
    class Forbidden:
        def request(self, *args, **kwargs):
            pytest.fail("Invalid configuration must not contact identity administration")

    with pytest.raises(SetupError):
        configure(Forbidden(), "../master", "http://localhost:5173")
    assert main(["--admin", "test", "--frontend-origin", "https://user:private@host"]) == 1
    assert (
        capsys.readouterr().out == "Frontend client setup failed; inspect configuration securely.\n"
    )
