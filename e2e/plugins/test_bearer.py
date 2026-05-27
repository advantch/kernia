"""End-to-end: bearer-token authentication."""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.plugins import bearer, email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver
from kernia_test_utils.adapter_fixtures import all_adapters_param


@pytest.mark.parametrize(*all_adapters_param())
async def test_bearer_token_authenticates(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="bearer-secret",
            plugins=[email_and_password(), bearer()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # Sign up via cookie path to obtain a session cookie.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "mobile@example.com", "password": "tokens-rule"},
    )
    assert r.status == 200, r.json()
    signed_token = driver.cookies["better-auth.session_token"]

    # Now drop the cookie and replay the same value via Authorization header.
    driver.cookies.clear()
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"Authorization": f"Bearer {signed_token}"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body is not None
    assert body["user"]["email"] == "mobile@example.com"


@pytest.mark.parametrize(*all_adapters_param())
async def test_bearer_invalid_signature_rejected(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="bearer-secret",
            plugins=[email_and_password(), bearer()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "x@example.com", "password": "passpass1"},
    )
    signed_token = driver.cookies["better-auth.session_token"]
    driver.cookies.clear()

    # Tamper signature.
    tampered = signed_token[:-2] + "XX"
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"Authorization": f"Bearer {tampered}"},
    )
    assert r.status == 200
    assert r.json() is None
