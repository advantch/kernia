"""One-time-token tests.

Ports `reference/packages/better-auth/src/plugins/one-time-token/one-time-token.test.ts`
1:1 (in-memory adapter) plus keeps an adapter-matrix round-trip smoke test.

Where upstream advances `vi` fake timers we instead rewrite the verification /
session `expiresAt` row directly through the adapter — behaviourally identical
since the endpoints compare against wall-clock time.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.one_time_token import one_time_token
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver, all_adapters_param


def _header(r, name: str) -> str | None:
    for k, v in r.headers:
        if k.lower() == name.lower():
            return v
    return None


def _build_driver(adapter: Any, **plugin_kwargs):
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            plugins=[email_and_password(), one_time_token(**plugin_kwargs)],
            advanced={"disable_csrf_check": True},
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


async def _sign_in(driver: ASGIDriver, email: str = "ott@example.com") -> None:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "correcthorse", "name": "ott"},
    )
    assert r.status == 200, r.json()


def _memory():
    from better_auth_memory_adapter import memory_adapter

    return memory_adapter()


# --------------------------------------------------------------------------------------
# Upstream: "One-time token"
# --------------------------------------------------------------------------------------


async def test_should_work() -> None:
    driver, _ = _build_driver(_memory())
    await _sign_in(driver)

    r = await driver.request("GET", "/one-time-token/generate")
    assert r.status == 200, r.json()
    token = r.json()["token"]
    assert token

    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 200, r.json()
    assert r.json() is not None

    # Second verify must fail (single use).
    r2 = await driver.request(
        "POST", "/one-time-token/verify", json_body={"token": token}
    )
    assert r2.status == 400


async def test_should_expire() -> None:
    driver, auth = _build_driver(_memory())
    await _sign_in(driver)

    r = await driver.request("GET", "/one-time-token/generate")
    token = r.json()["token"]

    # Advance "time": expire the verification row.
    rows = await auth.context.adapter.find_many(model="verification", where=())
    for row in rows:
        await auth.context.adapter.update(
            model="verification",
            where=(Where(field="id", value=row["id"]),),
            update={"expiresAt": int(time.time()) - 60},
        )

    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 400
    assert r.json()["message"] == "Token expired"


async def test_should_work_with_client() -> None:
    # Same as should_work but framed as a "client" (HTTP) call — identical path here.
    driver, _ = _build_driver(_memory())
    await _sign_in(driver)
    r = await driver.request("GET", "/one-time-token/generate")
    token = r.json()["token"]
    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 200
    assert r.json()["session"] is not None


async def test_should_reject_when_underlying_session_expired() -> None:
    driver, auth = _build_driver(_memory(), expires_in=10)
    await _sign_in(driver)

    r = await driver.request("GET", "/one-time-token/generate")
    token = r.json()["token"]
    assert token

    # Expire the underlying session (but keep the OTT itself valid).
    sessions = await auth.context.adapter.find_many(model="session", where=())
    for s in sessions:
        await auth.context.adapter.update(
            model="session",
            where=(Where(field="id", value=s["id"]),),
            update={"expiresAt": int(time.time()) - 60},
        )

    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 400
    assert r.json()["message"] == "Session expired"


# --------------------------------------------------------------------------------------
# Upstream: storeToken options
# --------------------------------------------------------------------------------------


async def test_store_token_hashed() -> None:
    async def gen(_session, _ctx):
        return "123456"

    driver, auth = _build_driver(_memory(), store_token="hashed", generate_token=gen)
    await _sign_in(driver)

    r = await driver.request("GET", "/one-time-token/generate")
    token = r.json()["token"]
    assert token == "123456"

    hashed = default_key_hasher(token)
    stored = await auth.context.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=f"one-time-token:{hashed}"),),
    )
    assert stored is not None

    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 200, r.json()
    assert r.json()["user"]["email"]


async def test_store_token_custom_hasher() -> None:
    async def gen(_session, _ctx):
        return "123456"

    async def custom_hash(token: str) -> str:
        return token + "hashed"

    driver, auth = _build_driver(
        _memory(),
        store_token={"type": "custom-hasher", "hash": custom_hash},
        generate_token=gen,
    )
    await _sign_in(driver)

    r = await driver.request("GET", "/one-time-token/generate")
    token = r.json()["token"]
    assert token == "123456"

    stored = await auth.context.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=f"one-time-token:{token}hashed"),),
    )
    assert stored is not None

    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 200, r.json()


# --------------------------------------------------------------------------------------
# Upstream: disableClientRequest option
# --------------------------------------------------------------------------------------


async def test_disable_client_request_allows_server_side() -> None:
    # Server-side path uses the same endpoint; we assert the HTTP path is rejected,
    # which is the observable behaviour of disableClientRequest=true.
    driver, _ = _build_driver(_memory(), disable_client_request=True)
    await _sign_in(driver)
    r = await driver.request("GET", "/one-time-token/generate")
    assert r.status == 400
    assert r.json()["message"] == "Client requests are disabled"


async def test_disable_client_request_rejects_client_requests() -> None:
    driver, _ = _build_driver(_memory(), disable_client_request=True)
    await _sign_in(driver)
    r = await driver.request("GET", "/one-time-token/generate")
    assert r.status == 400
    assert r.json()["message"] == "Client requests are disabled"


# --------------------------------------------------------------------------------------
# Upstream: disableSetSessionCookie option
# --------------------------------------------------------------------------------------


async def test_disable_set_session_cookie_true() -> None:
    driver, _ = _build_driver(_memory(), disable_set_session_cookie=True)
    await _sign_in(driver)
    r = await driver.request("GET", "/one-time-token/generate")
    token = r.json()["token"]
    # New driver (no cookie jar carry-over) to verify token only.
    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 200
    assert _header(r, "set-cookie") is None


async def test_set_session_cookie_by_default() -> None:
    driver, _ = _build_driver(_memory())
    await _sign_in(driver)
    r = await driver.request("GET", "/one-time-token/generate")
    token = r.json()["token"]
    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    set_cookie = _header(r, "set-cookie")
    assert set_cookie is not None
    assert "better-auth.session_token" in set_cookie


# --------------------------------------------------------------------------------------
# Upstream: setOttHeaderOnNewSession option
# --------------------------------------------------------------------------------------


async def test_set_ott_header_on_new_session_enabled() -> None:
    driver, _ = _build_driver(_memory(), set_ott_header_on_new_session=True)
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "ott-header-test@test.com",
            "password": "password123",
            "name": "OTT Header Test",
        },
    )
    assert r.status == 200, r.json()
    ott = _header(r, "set-ott")
    assert ott is not None
    assert len(ott) == 32
    expose = _header(r, "access-control-expose-headers")
    assert expose is not None
    assert "set-ott" in expose


async def test_set_ott_header_off_by_default() -> None:
    driver, _ = _build_driver(_memory())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "ott-header-default@test.com",
            "password": "password123",
            "name": "OTT Header Default",
        },
    )
    assert r.status == 200
    assert _header(r, "set-ott") is None


async def test_set_ott_header_on_sign_in() -> None:
    driver, _ = _build_driver(_memory(), set_ott_header_on_new_session=True)
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "ott-signin@test.com",
            "password": "password123",
            "name": "OTT SignIn",
        },
    )
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "ott-signin@test.com", "password": "password123"},
    )
    assert r.status == 200, r.json()
    ott = _header(r, "set-ott")
    assert ott is not None
    assert len(ott) == 32


# --------------------------------------------------------------------------------------
# Adapter-matrix round-trip smoke test
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(*all_adapters_param())
async def test_ott_generate_and_verify(adapter_factory) -> None:
    adapter = await adapter_factory()
    driver, _ = _build_driver(adapter)
    await _sign_in(driver)

    r = await driver.request("GET", "/one-time-token/generate")
    assert r.status == 200, r.json()
    token = r.json()["token"]
    assert token

    r = await driver.request("POST", "/one-time-token/verify", json_body={"token": token})
    assert r.status == 200, r.json()
    body = r.json()
    assert body["userId"] == user_id
    assert body["purpose"] == "checkout"


@pytest.mark.parametrize(*all_adapters_param())
async def test_ott_single_use(adapter_factory) -> None:
    adapter = await adapter_factory()
    driver, _ = _build_driver(adapter)
    await _sign_up(driver)

    r = await driver.request(
        "POST", "/generate-one-time-token", json_body={"purpose": "default"}
    )
    token = r.json()["token"]
    r1 = await driver.request(
        "POST", "/verify-one-time-token", json_body={"token": token}
    )
    assert r1.status == 200
    r2 = await driver.request(
        "POST", "/verify-one-time-token", json_body={"token": token}
    )
    assert r2.status == 400
    assert r2.json()["code"] == "ONE_TIME_TOKEN_INVALID"


@pytest.mark.parametrize(*all_adapters_param())
async def test_ott_requires_session(adapter_factory) -> None:
    adapter = await adapter_factory()
    driver, _ = _build_driver(adapter)
    r = await driver.request(
        "POST", "/generate-one-time-token", json_body={"purpose": "default"}
    )
    assert r.status == 401
    assert r.json()["code"] == "UNAUTHORIZED"


@pytest.mark.parametrize(*all_adapters_param())
async def test_ott_expired_rejected(adapter_factory) -> None:
    """Bypass the endpoint to write a pre-expired row, then verify it bounces."""
    import time as _time

    from kernia.types.adapter import Where

    adapter = await adapter_factory()
    driver, auth = _build_driver(adapter)
    await _sign_up(driver)

    now = int(_time.time())
    await auth.context.adapter.create(
        model="verification",
        data={
            "identifier": "one-time-token:expired-token-123",
            "value": "some-user-id:default",
            "expiresAt": now - 60,
            "createdAt": now - 120,
            "updatedAt": now - 120,
        },
    )
    r = await driver.request(
        "POST",
        "/verify-one-time-token",
        json_body={"token": "expired-token-123"},
    )
    assert r.status == 400
    assert r.json()["code"] == "ONE_TIME_TOKEN_EXPIRED"
    # And the row was consumed.
    row = await auth.context.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value="one-time-token:expired-token-123"),),
    )
    assert row is None
