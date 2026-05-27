"""E2E test for the Google One Tap plugin via ASGI + MockIdP.

Uses `MockIdP.id_token_for(...)` to produce a real RS256 id_token, then POSTs it
to /one-tap/verify with the MockIdP's JWKS URL configured. Verifies a session
cookie is set and a user row is created.
"""

from __future__ import annotations

import httpx
import pytest

from kernia.auth import init
from kernia.plugins.one_tap import OneTapOptions, one_tap
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver
from kernia_test_utils.mock_idp import MockIdP


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(issuer="https://test-idp", audience="client-A")


@pytest.fixture
def driver(idp: MockIdP) -> ASGIDriver:
    client = httpx.AsyncClient(transport=idp.mock_transport())
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                one_tap(
                    OneTapOptions(
                        client_id="client-A",
                        jwks_url="https://test-idp/.well-known/jwks.json",
                        issuer="https://test-idp",
                    )
                )
            ],
            advanced={"http_client": client, "disable_csrf_check": True},
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_one_tap_creates_user_and_session(driver: ASGIDriver, idp: MockIdP) -> None:
    token = idp.id_token_for(
        "user-123",
        email="alice@example.com",
        email_verified=True,
        name="Alice",
    )
    r = await driver.request(
        "POST",
        "/one-tap/verify",
        json_body={"id_token": token},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "session" in body
    assert "better-auth.session_token" in driver.cookies


async def test_one_tap_repeat_returns_existing_user(driver: ASGIDriver, idp: MockIdP) -> None:
    token_1 = idp.id_token_for("user-x", email="x@example.com", email_verified=True, name="X")
    r = await driver.request("POST", "/one-tap/verify", json_body={"id_token": token_1})
    assert r.status == 200
    user_id_1 = r.json()["user"]["id"]
    driver.cookies.clear()

    token_2 = idp.id_token_for("user-x", email="x@example.com", email_verified=True, name="X")
    r = await driver.request("POST", "/one-tap/verify", json_body={"id_token": token_2})
    assert r.status == 200
    assert r.json()["user"]["id"] == user_id_1


async def test_one_tap_rejects_bad_audience(idp: MockIdP) -> None:
    client = httpx.AsyncClient(transport=idp.mock_transport())
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[
                one_tap(
                    OneTapOptions(
                        client_id="DIFFERENT",
                        jwks_url="https://test-idp/.well-known/jwks.json",
                        issuer="https://test-idp",
                    )
                )
            ],
            advanced={"http_client": client, "disable_csrf_check": True},
        )
    )
    d = ASGIDriver(app=auth.router.mount())
    token = idp.id_token_for("user-y", email="y@example.com", email_verified=True)
    r = await d.request("POST", "/one-tap/verify", json_body={"id_token": token})
    assert r.status == 400


async def test_one_tap_disable_sign_up(idp: MockIdP) -> None:
    client = httpx.AsyncClient(transport=idp.mock_transport())
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[
                one_tap(
                    OneTapOptions(
                        client_id="client-A",
                        jwks_url="https://test-idp/.well-known/jwks.json",
                        issuer="https://test-idp",
                        disable_sign_up=True,
                    )
                )
            ],
            advanced={"http_client": client, "disable_csrf_check": True},
        )
    )
    d = ASGIDriver(app=auth.router.mount())
    token = idp.id_token_for("user-z", email="z@example.com", email_verified=True)
    r = await d.request("POST", "/one-tap/verify", json_body={"id_token": token})
    assert r.status == 403
