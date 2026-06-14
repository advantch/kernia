"""Same email/password flow, but on the SQLAlchemy adapter.

Demonstrates that swapping adapters changes zero application code.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_sqlalchemy import sqlalchemy_adapter
from kernia_test_utils import ASGIDriver


@pytest.fixture
async def driver() -> ASGIDriver:
    adapter = await sqlalchemy_adapter(url="sqlite+aiosqlite:///:memory:")
    auth = init(
        KerniaOptions(
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
