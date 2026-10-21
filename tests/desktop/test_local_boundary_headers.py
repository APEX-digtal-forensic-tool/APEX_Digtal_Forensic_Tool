"""Reject malformed transport headers before dispatching local operations."""

import httpx
import pytest
from fastapi.testclient import TestClient

from apex_desktop.app import create_app

TOKEN = "a" * 48


@pytest.fixture
def client(tmp_path):
    with TestClient(
        create_app(tmp_path / "data", TOKEN),
        base_url="http://127.0.0.1",
        headers={"Authorization": f"Bearer {TOKEN}"},
        raise_server_exceptions=False,
    ) as connection:
        yield connection


@pytest.mark.parametrize(
    "host",
    [
        "[invalid",
        "127.0.0.1/attacker.test",
        "attacker.test@127.0.0.1",
        "127.0.0.1#attacker.test",
        "127.0.0.1:invalid",
        "127.0.0.1:65536",
        "127.0.0.1:0",
        "127.0.0.1:",
        "127.0.0.1.attacker.test",
        "attacker.test",
    ],
)
def test_rejects_invalid_host_without_url_fallback(client, host):
    response = client.post(
        "/v1/operations/cases.create", headers={"Host": host}, json={"name": "denied"}
    )
    assert response.status_code == 403
    assert response.json() == {"ok": False, "error": {"code": "LOCAL_ORIGIN_DENIED"}}
    assert client.post("/v1/operations/cases.list", json={}).json()["data"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("hosts", [[], ["127.0.0.1", "attacker.test"]])
async def test_requires_one_explicit_host(client, hosts):
    # TestClient inserts a missing Host; ASGITransport preserves the raw list.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=client.app, raise_app_exceptions=False),
        base_url="http://127.0.0.1",
    ) as connection:
        request = connection.build_request("GET", "/health")
        request.headers = httpx.Headers(
            [("Authorization", f"Bearer {TOKEN}"), *(("Host", host) for host in hosts)]
        )
        response = await connection.send(request)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "LOCAL_ORIGIN_DENIED"


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:80", "127.0.0.1:49152"])
def test_accepts_loopback_host_and_port(client, host):
    assert client.get("/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "authorization", [b"Bearer \xff", b"Bearer \xc3\xa9", b"", b"Bearer wrong"]
)
def test_invalid_authorization_is_json_401(client, authorization):
    response = client.get("/health", headers={b"Authorization": authorization})
    assert response.status_code == 401
    assert response.json() == {"ok": False, "error": {"code": "LOCAL_SESSION_REQUIRED"}}
    assert client.get("/health").status_code == 200


def test_rejects_ambiguous_authorization(client):
    response = client.get(
        "/health",
        headers=[("Authorization", f"Bearer {TOKEN}"), ("Authorization", "Bearer wrong")],
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "LOCAL_SESSION_REQUIRED"
