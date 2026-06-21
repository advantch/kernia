"""Integration tests for the always-on core routes (account, session, update-user,
email-verification, ok, error).

Exercises the routes via the ASGI driver end-to-end against a memory adapter.
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
            secret="test-secret",
            plugins=[email_and_password()],
            advanced={"expose_verification_token_for_tests": True},
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _sign_up(
    driver: ASGIDriver, email: str = "u@example.com", pw: str = "correcthorse"
) -> None:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": pw},
    )
    assert r.status == 200, r.json()


async def test_ok_route(driver: ASGIDriver) -> None:
    r = await driver.request("GET", "/ok")
    assert r.status == 200
    assert r.json() == {"ok": True}


async def test_error_route(driver: ASGIDriver) -> None:
    r = await driver.request("GET", "/error", query="error=SOMETHING")
    assert r.status == 400
    assert r.json()["code"] == "SOMETHING"


async def test_list_sessions_requires_auth(driver: ASGIDriver) -> None:
    r = await driver.request("GET", "/list-sessions")
    assert r.status == 401


async def test_list_sessions_after_signin(driver: ASGIDriver) -> None:
    await _sign_up(driver)
    r = await driver.request("GET", "/list-sessions")
    assert r.status == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["current"] is True


async def test_revoke_other_sessions(driver: ASGIDriver) -> None:
    await _sign_up(driver)
    # second sign-in with a fresh driver, but same auth — create another session
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[email_and_password()],
        )
    )
    d1 = ASGIDriver(app=auth.router.mount())
    d2 = ASGIDriver(app=auth.router.mount())
    await d1.request(
        "POST", "/sign-up/email", json_body={"email": "x@example.com", "password": "longpasswd"}
    )
    await d2.request(
        "POST", "/sign-in/email", json_body={"email": "x@example.com", "password": "longpasswd"}
    )
    # Now revoke others from d1's perspective — d2's session should die.
    r = await d1.request("POST", "/revoke-other-sessions")
    assert r.status == 200
    assert r.json()["revoked"] == 1


async def test_update_user(driver: ASGIDriver) -> None:
    await _sign_up(driver)
    r = await driver.request("POST", "/update-user", json_body={"name": "Alice"})
    assert r.status == 200
    assert r.json()["user"]["name"] == "Alice"


async def test_change_password(driver: ASGIDriver) -> None:
    await _sign_up(driver, pw="oldpassword")
    r = await driver.request(
        "POST",
        "/change-password",
        json_body={"current_password": "oldpassword", "new_password": "newpassword"},
    )
    assert r.status == 200
    # Sign out + back in with the new password.
    await driver.request("POST", "/sign-out")
    r = await driver.request(
        "POST", "/sign-in/email", json_body={"email": "u@example.com", "password": "newpassword"}
    )
    assert r.status == 200


async def test_change_password_rejects_wrong_current(driver: ASGIDriver) -> None:
    await _sign_up(driver, pw="rightpassword")
    r = await driver.request(
        "POST",
        "/change-password",
        json_body={"current_password": "wrong", "new_password": "anothernewpassword"},
    )
    assert r.status == 401


async def test_delete_user_cascades(driver: ASGIDriver) -> None:
    await _sign_up(driver, pw="thepassword")
    r = await driver.request(
        "POST",
        "/delete-user",
        json_body={"current_password": "thepassword"},
    )
    assert r.status == 200
    # session cookie is still in the jar but the row is gone — get-session is null
    r = await driver.request("GET", "/get-session")
    assert r.json() is None


async def test_send_and_verify_email(driver: ASGIDriver) -> None:
    await _sign_up(driver)
    r = await driver.request("POST", "/send-verification-email", json_body={})
    assert r.status == 200
    token = r.json()["_token"]
    r2 = await driver.request("POST", "/verify-email", json_body={"token": token})
    assert r2.status == 200
    assert r2.json()["user"]["emailVerified"] is True


async def test_list_accounts(driver: ASGIDriver) -> None:
    await _sign_up(driver)
    r = await driver.request("GET", "/list-accounts")
    assert r.status == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["providerId"] == "credential"


async def test_unlink_account_404_when_unknown(driver: ASGIDriver) -> None:
    await _sign_up(driver)
    r = await driver.request("POST", "/unlink-account", json_body={"provider_id": "google"})
    assert r.status == 404
