"""One-time-token integration tests across every adapter.

Exercises the generate/verify round-trip plus failure modes. Uses the
email-password plugin to mint the session that owns the token.
"""

from __future__ import annotations

from typing import Any

import pytest

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.one_time_token import one_time_token
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver, all_adapters_param


def _build_driver(adapter: Any):
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            plugins=[email_and_password(), one_time_token()],
            advanced={"disable_csrf_check": True},
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


async def _sign_up(driver: ASGIDriver, email: str = "user@example.com") -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    return r.json()["user"]["id"]


@pytest.mark.parametrize(*all_adapters_param())
async def test_ott_generate_and_verify(adapter_factory) -> None:
    adapter = await adapter_factory()
    driver, _ = _build_driver(adapter)
    user_id = await _sign_up(driver)

    r = await driver.request(
        "POST",
        "/generate-one-time-token",
        json_body={"purpose": "checkout"},
    )
    assert r.status == 200, r.json()
    token = r.json()["token"]
    assert token

    r = await driver.request(
        "POST", "/verify-one-time-token", json_body={"token": token}
    )
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
