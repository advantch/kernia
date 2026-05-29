"""Same email/password flow, but on the SQLAlchemy adapter.

Demonstrates that swapping adapters changes zero application code.
"""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.types.init_options import BetterAuthOptions
from better_auth_sqlalchemy import sqlalchemy_adapter
from better_auth_test_utils import ASGIDriver


@pytest.fixture
async def driver() -> ASGIDriver:
    adapter = await sqlalchemy_adapter(url="sqlite+aiosqlite:///:memory:")
    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="test-secret",
            plugins=[email_and_password()],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_signup_signin_signout_on_sqlalchemy(driver: ASGIDriver) -> None:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "alice@example.com", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    assert "better-auth.session_token" in driver.cookies

    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["email"] == "alice@example.com"

    await driver.request("POST", "/sign-out")

    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "alice@example.com", "password": "correcthorse"},
    )
    assert r.status == 200
    assert "better-auth.session_token" in driver.cookies
