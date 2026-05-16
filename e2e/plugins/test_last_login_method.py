"""End-to-end: last-login-method cookie is emitted on successful sign-in."""

from __future__ import annotations

import pytest

from better_auth.auth import init
from better_auth.plugins import email_and_password, last_login_method
from better_auth.types.init_options import BetterAuthOptions
from better_auth_test_utils import ASGIDriver
from better_auth_test_utils.adapter_fixtures import all_adapters_param


@pytest.mark.parametrize(*all_adapters_param())
async def test_last_login_method_cookie_set(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), last_login_method()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # Sign up → email path → cookie set.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@example.com", "password": "passpass1"},
    )
    assert r.status == 200, r.json()
    assert driver.cookies.get("better-auth.last_login_method") == "email"

    # Sign out (clears session) and sign in again — cookie still resolves to "email".
    await driver.request("POST", "/sign-out")
    driver.cookies.pop("better-auth.last_login_method", None)
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "u@example.com", "password": "passpass1"},
    )
    assert r.status == 200, r.json()
    assert driver.cookies.get("better-auth.last_login_method") == "email"


@pytest.mark.parametrize(*all_adapters_param())
async def test_last_login_method_not_set_on_failed_signin(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), last_login_method()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "nope@example.com", "password": "wrongpass"},
    )
    assert r.status == 401
    assert "better-auth.last_login_method" not in driver.cookies
