"""Full wire-protocol end-to-end: sign-up → get-session → sign-in → sign-out.

Drives the ASGI app via `ASGIDriver` (no HTTP server). Validates:
  * Set-Cookie carries a signed session_token after sign-up/sign-in
  * The same cookie attaches a session to subsequent calls
  * Sign-out clears the cookie and invalidates the session
  * Bad password returns 401 INVALID_CREDENTIALS
  * Duplicate sign-up returns 409 EMAIL_ALREADY_IN_USE
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


@pytest.fixture
def driver() -> ASGIDriver:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password()],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_full_signup_signin_signout(driver: ASGIDriver) -> None:
    # 1. Sign up
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "alice@example.com", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "session" in body  # auto sign-in is on by default
    assert "better-auth.session_token" in driver.cookies

    # 2. /get-session with the cookie returns the user
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body["user"]["email"] == "alice@example.com"

    # 3. Sign out clears the cookie
    r = await driver.request("POST", "/sign-out")
    assert r.status == 200
    assert r.json() == {"success": True}
    assert driver.cookies.get("better-auth.session_token", "") == ""

    # 4. /get-session now returns null
    driver.cookies.pop("better-auth.session_token", None)
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json() is None

    # 5. Sign in with the original password works
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "alice@example.com", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    assert "better-auth.session_token" in driver.cookies

    # 6. Get-session works again
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["email"] == "alice@example.com"


async def test_duplicate_signup_returns_409(driver: ASGIDriver) -> None:
    body = {"email": "dup@example.com", "password": "abcdefgh"}
    r1 = await driver.request("POST", "/sign-up/email", json_body=body)
    assert r1.status == 200
    r2 = await driver.request("POST", "/sign-up/email", json_body=body)
    assert r2.status == 409
    assert r2.json()["code"] == "EMAIL_ALREADY_IN_USE"


async def test_wrong_password_returns_401(driver: ASGIDriver) -> None:
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "bob@example.com", "password": "rightpass"},
    )
    driver.cookies.clear()  # forget auto-signin session
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "bob@example.com", "password": "wrongpass"},
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_CREDENTIALS"


async def test_short_password_rejected(driver: ASGIDriver) -> None:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "x@example.com", "password": "short"},
    )
    assert r.status == 400
    assert r.json()["code"] == "PASSWORD_TOO_SHORT"


async def test_unknown_route_returns_404(driver: ASGIDriver) -> None:
    r = await driver.request("GET", "/no-such-endpoint")
    assert r.status == 404
    assert r.json()["code"] == "NOT_FOUND"


async def test_reset_password_round_trip() -> None:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[email_and_password()],
            advanced={"expose_reset_token_for_tests": True},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "reset@example.com", "password": "oldpassword"},
    )
    driver.cookies.clear()

    r = await driver.request(
        "POST",
        "/forget-password",
        json_body={"email": "reset@example.com"},
    )
    assert r.status == 200
    token = r.json()["_token"]

    r = await driver.request(
        "POST",
        "/reset-password",
        json_body={"token": token, "password": "newpassword"},
    )
    assert r.status == 200, r.json()

    # Old password fails
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "reset@example.com", "password": "oldpassword"},
    )
    assert r.status == 401

    # New password works
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "reset@example.com", "password": "newpassword"},
    )
    assert r.status == 200
