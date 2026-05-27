"""Integration tests for the two-factor plugin.

Validates:
  * enable → otpauth URL returned with the freshly-issued secret
  * verify-totp accepts the current code, rejects an old / wrong code
  * sign-in is gated by 2FA: returns `requiresTwoFactor` + a confirmation id
  * confirmation id can be exchanged for a real session by verify-totp
  * backup codes work and are single-use
"""

from __future__ import annotations

import pyotp

from kernia.auth import init
from kernia.plugins import email_and_password, two_factor
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def _build() -> ASGIDriver:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password(), two_factor()],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_enable_and_verify_totp_happy_path() -> None:
    driver = _build()
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "ada@example.com", "password": "correcthorse"},
    )
    assert r.status == 200

    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": "correcthorse"}
    )
    assert r.status == 200, r.json()
    secret = r.json()["secret"]
    assert r.json()["otpauth_url"].startswith("otpauth://totp/")

    code = pyotp.TOTP(secret).now()
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": code}
    )
    assert r.status == 200, r.json()


async def test_old_totp_code_rejected() -> None:
    driver = _build()
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "x@example.com", "password": "correcthorse"},
    )
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": "correcthorse"}
    )
    secret = r.json()["secret"]

    # Code from 5 minutes ago should be rejected with the default valid_window=0.
    import time

    old_code = pyotp.TOTP(secret).at(int(time.time()) - 600)
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": old_code}
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_TWO_FACTOR_CODE"


async def test_sign_in_gated_by_two_factor() -> None:
    driver = _build()
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "mfa@example.com", "password": "correcthorse"},
    )
    assert r.status == 200

    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": "correcthorse"}
    )
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": code}
    )
    assert r.status == 200

    # Now sign out and try to sign back in — must require 2FA.
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "mfa@example.com", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body.get("requiresTwoFactor") is True
    assert "confirmationId" in body
    # Cookies should NOT carry a session yet.
    assert driver.cookies.get("better-auth.session_token", "") == ""

    confirmation_id = body["confirmationId"]
    code = pyotp.TOTP(secret).now()
    r = await driver.request(
        "POST",
        "/two-factor/verify-totp",
        json_body={"code": code, "confirmation_id": confirmation_id},
    )
    assert r.status == 200, r.json()
    assert "session" in r.json()
    # And a session cookie was set this time.
    assert driver.cookies.get("better-auth.session_token")


async def test_backup_codes_round_trip() -> None:
    driver = _build()
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "bc@example.com", "password": "correcthorse"},
    )
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": "correcthorse"}
    )
    secret = r.json()["secret"]
    await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": pyotp.TOTP(secret).now()}
    )
    r = await driver.request("POST", "/two-factor/generate-backup-codes")
    assert r.status == 200, r.json()
    codes = r.json()["backup_codes"]
    assert len(codes) == 8

    code0 = codes[0]
    r = await driver.request(
        "POST", "/two-factor/verify-backup-code", json_body={"code": code0}
    )
    assert r.status == 200, r.json()
    # Second use of the same code must fail (single-use).
    r = await driver.request(
        "POST", "/two-factor/verify-backup-code", json_body={"code": code0}
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_BACKUP_CODE"
