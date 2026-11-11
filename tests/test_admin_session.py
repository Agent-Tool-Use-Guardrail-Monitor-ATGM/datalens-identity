"""Bounded administrative-tool renewal, separate from application authentication."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from urllib.parse import parse_qs

import httpx
import pytest
from bootstrap_identity import Admin, SetupError


def admin_client(monkeypatch, handler):
    client = httpx.Client(
        base_url="https://identity.example", transport=httpx.MockTransport(handler)
    )
    monkeypatch.setattr("bootstrap_identity.httpx.Client", lambda **kwargs: client)
    return Admin("https://identity.example", "synthetic-admin", "synthetic-password")


def tokens(access="initial", refresh="refresh-initial"):
    return httpx.Response(200, json={"access_token": access, "refresh_token": refresh})


def test_authentication_rejection_renews_rotates_and_replays_once(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/token"):
            form = parse_qs(request.content.decode())
            if form["grant_type"] == ["password"]:
                return tokens()
            assert form == {
                "grant_type": ["refresh_token"],
                "client_id": ["admin-cli"],
                "refresh_token": ["refresh-initial"],
            }
            assert "authorization" not in request.headers
            return tokens("renewed", "refresh-rotated")
        if request.headers["authorization"] == "Bearer initial":
            return httpx.Response(401)
        return httpx.Response(204)

    admin = admin_client(monkeypatch, handler)
    try:
        assert admin.request("PUT", "test/users/user", {"firstName": "Updated"}).status_code == 204
        assert len(calls) == 4
        assert calls[1].content == calls[3].content
        assert admin._refresh_token == "refresh-rotated"
    finally:
        admin.close()
    assert admin._refresh_token == "" and "authorization" not in admin.client.headers


@pytest.mark.parametrize("status, expected", [(403, (204,)), (500, (204,)), (401, (401,))])
def test_no_renewal_or_replay_for_other_responses(monkeypatch, status, expected):
    calls = []

    def handler(request):
        calls.append(request)
        return tokens() if len(calls) == 1 else httpx.Response(status)

    admin = admin_client(monkeypatch, handler)
    try:
        if status in expected:
            assert admin.request("PUT", "test", {}, expected).status_code == status
        else:
            with pytest.raises(SetupError, match=f"HTTP {status}"):
                admin.request("PUT", "test", {}, expected)
        assert len(calls) == 2
    finally:
        admin.close()


@pytest.mark.parametrize("refresh_status", [200, 400])
def test_failed_renewal_or_second_rejection_fails_without_password_fallback(
    monkeypatch, refresh_status
):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return tokens()
        if request.url.path.endswith("/token"):
            return tokens("renewed", "rotated") if refresh_status == 200 else httpx.Response(400)
        return httpx.Response(401)

    admin = admin_client(monkeypatch, handler)
    try:
        with pytest.raises(SetupError):
            admin.request("GET", "test")
        assert len(calls) == (4 if refresh_status == 200 else 3)
    finally:
        admin.close()


def test_network_failure_is_not_replayed(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return tokens()
        raise httpx.ReadTimeout("Synthetic timeout")

    admin = admin_client(monkeypatch, handler)
    try:
        with pytest.raises(httpx.ReadTimeout):
            admin.request("POST", "test/users", {})
        assert len(calls) == 2
    finally:
        admin.close()


def test_concurrent_authentication_rejections_share_one_renewal(monkeypatch):
    barrier = Barrier(2)
    grants = []

    def handler(request):
        if request.url.path.endswith("/token"):
            grant = parse_qs(request.content.decode())["grant_type"][0]
            grants.append(grant)
            return tokens() if grant == "password" else tokens("renewed", "rotated")
        if request.headers["authorization"] == "Bearer initial":
            barrier.wait(timeout=5)
            return httpx.Response(401)
        return httpx.Response(204)

    admin = admin_client(monkeypatch, handler)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert list(
                pool.map(lambda _: admin.request("PUT", "test", {}).status_code, range(2))
            ) == [204, 204]
        assert grants == ["password", "refresh_token"]
    finally:
        admin.close()


@pytest.mark.parametrize(
    "body",
    [
        {},
        [],
        {"access_token": "valid", "refresh_token": None},
        {"access_token": "", "refresh_token": "valid"},
        {"access_token": "invalid token", "refresh_token": "valid"},
    ],
)
def test_invalid_provider_tokens_fail_safely_and_close_the_client(monkeypatch, body):
    client = httpx.Client(
        base_url="https://identity.example",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
    )
    monkeypatch.setattr("bootstrap_identity.httpx.Client", lambda **kwargs: client)
    with pytest.raises(SetupError, match="token response was invalid"):
        Admin("https://identity.example", "synthetic-admin", "synthetic-password")
    assert client.is_closed


@pytest.mark.parametrize(
    "origin, local", [("http://localhost:18081", True), ("https://identity.azure.example", False)]
)
def test_only_local_admin_transport_uses_ipv4_without_rewriting_the_issuer(
    monkeypatch, origin, local
):
    transports, options = [], []
    client = httpx.Client(base_url=origin, transport=httpx.MockTransport(lambda _: tokens()))
    sentinel = object()

    def transport(**kwargs):
        transports.append(kwargs)
        return sentinel

    def factory(**kwargs):
        options.append(kwargs)
        return client

    monkeypatch.setattr("bootstrap_identity.httpx.HTTPTransport", transport)
    monkeypatch.setattr("bootstrap_identity.httpx.Client", factory)
    admin = Admin(origin, "synthetic-admin", "synthetic-password")
    try:
        assert transports == ([{"local_address": "0.0.0.0", "trust_env": False}] if local else [])
        assert options[0]["base_url"] == origin
        assert options[0]["transport"] is (sentinel if local else None)
        assert options[0]["trust_env"] is False
    finally:
        admin.close()
