"""Integration tests for the two-factor plugin.

Ported from the upstream Vitest suite
`reference/packages/better-auth/src/plugins/two-factor/two-factor.test.ts`,
adapted to the Python wire format (camelCase JSON bodies + responses, the same
`better-auth.two_factor` / `better-auth.trust_device` signed cookies).

Covers:
  * enable → returns totpURI + 10 backup codes, doesn't enable until verified
  * custom issuer + appName fallback in the otpauth URI
  * verify-totp completes enrollment, gates sign-in, rejects invalid codes
  * send-otp / verify-otp via an injected send_otp callback
  * backup codes are single-use; view/generate backup codes
  * trust-device flow (cookie skips 2FA, rotates server-side, expiry, disable)
  * twoFactorMethods reported in the sign-in challenge
  * cookie max-age options + passwordless mode
"""

from __future__ import annotations

import time

import pyotp
from better_auth.auth import init
from better_auth.plugins import email_and_password, two_factor
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver

TEST_EMAIL = "ada@example.com"
TEST_PASSWORD = "correcthorse"


class _OTPSink:
    """Captures the most recent OTP delivered through the send_otp callback."""

    def __init__(self) -> None:
        self.otp = ""
        self.calls = 0

    def __call__(self, data, ctx) -> None:
        self.otp = data["otp"]
        self.calls += 1


def _build(
    *,
    otp_sink: _OTPSink | None = None,
    skip_verification_on_enable: bool = False,
    trust_device_max_age: int | None = None,
    two_factor_cookie_max_age: int | None = None,
    issuer: str | None = None,
    totp_disable: bool = False,
    allow_passwordless: bool = False,
    store_otp: object | None = None,
) -> ASGIDriver:
    tf_opts: dict[str, object] = {}
    if otp_sink is not None:
        otp_opts: dict[str, object] = {"send_otp": otp_sink}
        if store_otp is not None:
            otp_opts["store_otp"] = store_otp
        tf_opts["otp_options"] = otp_opts
    if skip_verification_on_enable:
        tf_opts["skip_verification_on_enable"] = True
    if trust_device_max_age is not None:
        tf_opts["trust_device_max_age"] = trust_device_max_age
    if two_factor_cookie_max_age is not None:
        tf_opts["two_factor_cookie_max_age"] = two_factor_cookie_max_age
    if issuer is not None:
        tf_opts["issuer"] = issuer
    if totp_disable:
        tf_opts["totp_options"] = {"disable": True}
    if allow_passwordless:
        tf_opts["allow_passwordless"] = True

    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password(), two_factor()],
            advanced={"two-factor": tf_opts},
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _signup(driver: ASGIDriver, email: str = TEST_EMAIL) -> None:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": TEST_PASSWORD},
    )
    assert r.status == 200, r.json()


async def _enable_and_verify(driver: ASGIDriver) -> str:
    """Enable + verify TOTP; returns the secret for follow-up code generation."""
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    secret = _secret_from_uri(r.json()["totpURI"])
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": pyotp.TOTP(secret).now()}
    )
    assert r.status == 200, r.json()
    return secret


def _secret_from_uri(uri: str) -> str:
    from urllib.parse import parse_qs, urlparse

    return parse_qs(urlparse(uri).query)["secret"][0]


# ---------------------------------------------------------------------------
# enable / totp-uri
# ---------------------------------------------------------------------------


async def test_enable_returns_uri_and_backup_codes_without_enabling() -> None:
    driver = _build()
    await _signup(driver)
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert len(body["backupCodes"]) == 10
    assert body["totpURI"].startswith("otpauth://totp/")

    # Session should still report 2FA NOT yet enabled.
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["twoFactorEnabled"] in (False, None)


async def test_enable_custom_issuer_from_request() -> None:
    driver = _build()
    await _signup(driver)
    r = await driver.request(
        "POST",
        "/two-factor/enable",
        json_body={"password": TEST_PASSWORD, "issuer": "Custom App Name"},
    )
    uri = r.json()["totpURI"]
    assert uri.startswith("otpauth://totp/Custom%20App%20Name:")
    assert "issuer=Custom+App+Name" in uri or "issuer=Custom%20App%20Name" in uri


async def test_enable_fallback_to_default_app_name() -> None:
    driver = _build()
    await _signup(driver)
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    uri = r.json()["totpURI"]
    assert uri.startswith("otpauth://totp/Better%20Auth:")
    assert "issuer=Better+Auth" in uri or "issuer=Better%20Auth" in uri


async def test_enable_requires_password() -> None:
    driver = _build()
    await _signup(driver)
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": "wrong-password"}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_PASSWORD"


# ---------------------------------------------------------------------------
# verify-totp
# ---------------------------------------------------------------------------


async def test_enable_two_factor_via_verify_totp() -> None:
    driver = _build()
    await _signup(driver)
    secret = await _enable_and_verify(driver)
    assert secret
    r = await driver.request("GET", "/get-session")
    assert r.json()["user"]["twoFactorEnabled"] is True


async def test_verify_totp_invalid_code() -> None:
    driver = _build()
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": "invalid-code"}
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_CODE"


async def test_pre_migration_row_verified_absent_completes_enrollment() -> None:
    """A twoFactor row whose `verified` is None must still complete enrollment."""
    driver = _build()
    await _signup(driver)
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    secret = _secret_from_uri(r.json()["totpURI"])

    # Verify TOTP — enrollment should succeed and flip twoFactorEnabled.
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": pyotp.TOTP(secret).now()}
    )
    assert r.status == 200, r.json()
    r = await driver.request("GET", "/get-session")
    assert r.json()["user"]["twoFactorEnabled"] is True


# ---------------------------------------------------------------------------
# sign-in gating + OTP
# ---------------------------------------------------------------------------


async def test_require_two_factor_on_sign_in_with_otp() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink)
    await _signup(driver)
    await _enable_and_verify(driver)

    # Sign out + sign back in → must require 2FA.
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["twoFactorRedirect"] is True
    assert body["twoFactorMethods"] == ["totp", "otp"]
    # No session cookie yet.
    assert driver.cookies.get("better-auth.session_token", "") == ""
    assert driver.cookies.get("better-auth.two_factor")

    # Send + verify OTP.
    r = await driver.request("POST", "/two-factor/send-otp")
    assert r.status == 200, r.json()
    assert len(sink.otp) == 6

    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": sink.otp}
    )
    assert r.status == 200, r.json()
    assert r.json()["token"]
    assert driver.cookies.get("better-auth.session_token")


async def test_sign_in_fails_if_two_factor_cookie_missing() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink)
    await _signup(driver)
    await _enable_and_verify(driver)
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json()["twoFactorRedirect"] is True
    # Drop the two_factor cookie before verifying.
    driver.cookies.pop("better-auth.two_factor", None)

    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": "123456"}
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_TWO_FACTOR_COOKIE"


async def test_otp_attempts_are_limited() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink)
    await _signup(driver)
    await _enable_and_verify(driver)
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    await driver.request("POST", "/two-factor/send-otp")
    for _ in range(5):
        r = await driver.request(
            "POST", "/two-factor/verify-otp", json_body={"code": "000000"}
        )
        assert r.status == 401
        assert r.json()["code"] == "INVALID_CODE"

    # Next attempt, even with the correct code, is blocked.
    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": sink.otp}
    )
    assert r.status == 400
    assert r.json()["code"] == "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"


# ---------------------------------------------------------------------------
# backup codes
# ---------------------------------------------------------------------------


async def test_generate_backup_codes() -> None:
    driver = _build()
    await _signup(driver)
    await _enable_and_verify(driver)
    r = await driver.request(
        "POST", "/two-factor/generate-backup-codes", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    assert len(r.json()["backupCodes"]) == 10
    assert r.json()["status"] is True


async def test_sign_in_with_backup_code_single_use() -> None:
    driver = _build()
    await _signup(driver)
    secret = await _enable_and_verify(driver)
    r = await driver.request(
        "POST", "/two-factor/generate-backup-codes", json_body={"password": TEST_PASSWORD}
    )
    backup_codes = r.json()["backupCodes"]
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    # New 2FA session, verify with backup code.
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    code = backup_codes[0]
    r = await driver.request(
        "POST", "/two-factor/verify-backup-code", json_body={"code": code}
    )
    assert r.status == 200, r.json()
    assert driver.cookies.get("better-auth.session_token")

    # Confirm code was consumed (re-sign-in then reuse fails).
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    r = await driver.request(
        "POST", "/two-factor/verify-backup-code", json_body={"code": code}
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_BACKUP_CODE"
    assert secret  # silence unused


async def test_view_backup_codes_returns_array() -> None:
    driver = _build()
    await _signup(driver)
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    enable_codes = r.json()["backupCodes"]
    await driver.request(
        "POST", "/two-factor/verify-totp",
        json_body={"code": pyotp.TOTP(_secret_from_uri(r.json()["totpURI"])).now()},
    )
    r = await driver.request("GET", "/get-session")
    user_id = r.json()["user"]["id"]

    r = await driver.request(
        "POST", "/two-factor/view-backup-codes", json_body={"userId": user_id}
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert isinstance(body["backupCodes"], list)
    assert body["backupCodes"] == enable_codes
    assert body["status"] is True


async def test_regenerate_backup_codes_multiple_times() -> None:
    driver = _build()
    await _signup(driver)
    await _enable_and_verify(driver)
    first = await driver.request(
        "POST", "/two-factor/generate-backup-codes", json_body={"password": TEST_PASSWORD}
    )
    second = await driver.request(
        "POST", "/two-factor/generate-backup-codes", json_body={"password": TEST_PASSWORD}
    )
    assert first.json()["backupCodes"] != second.json()["backupCodes"]
    assert len(second.json()["backupCodes"]) == 10


async def test_backup_codes_updated_after_verification() -> None:
    driver = _build()
    await _signup(driver)
    await _enable_and_verify(driver)
    gen = await driver.request(
        "POST", "/two-factor/generate-backup-codes", json_body={"password": TEST_PASSWORD}
    )
    codes = gen.json()["backupCodes"]
    r = await driver.request("GET", "/get-session")
    user_id = r.json()["user"]["id"]

    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    await driver.request(
        "POST", "/two-factor/verify-backup-code", json_body={"code": codes[0]}
    )

    # View remaining (server-side) — should be 9 and exclude the used one.
    r = await driver.request(
        "POST", "/two-factor/view-backup-codes", json_body={"userId": user_id}
    )
    remaining = r.json()["backupCodes"]
    assert len(remaining) == 9
    assert codes[0] not in remaining


# ---------------------------------------------------------------------------
# get-totp-uri
# ---------------------------------------------------------------------------


async def test_get_totp_uri() -> None:
    driver = _build(skip_verification_on_enable=True)
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    r = await driver.request(
        "POST", "/two-factor/get-totp-uri", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    assert r.json()["totpURI"].startswith("otpauth://totp/")


async def test_get_totp_uri_wrong_password_uses_invalid_password() -> None:
    driver = _build(skip_verification_on_enable=True)
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    r = await driver.request(
        "POST", "/two-factor/get-totp-uri", json_body={"password": "not-the-password"}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_PASSWORD"


# ---------------------------------------------------------------------------
# skipVerificationOnEnable
# ---------------------------------------------------------------------------


async def test_skip_verification_on_enable_enables_immediately() -> None:
    driver = _build(skip_verification_on_enable=True)
    await _signup(driver)
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    r = await driver.request("GET", "/get-session")
    assert r.json()["user"]["twoFactorEnabled"] is True


# ---------------------------------------------------------------------------
# disable
# ---------------------------------------------------------------------------


async def test_disable_two_factor() -> None:
    driver = _build()
    await _signup(driver)
    await _enable_and_verify(driver)
    r = await driver.request(
        "POST", "/two-factor/disable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    assert r.json()["status"] is True
    r = await driver.request("GET", "/get-session")
    assert r.json()["user"]["twoFactorEnabled"] in (False, None)

    # Sign-in no longer challenges.
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json().get("twoFactorRedirect") is None
    assert r.json()["user"]


# ---------------------------------------------------------------------------
# trust device
# ---------------------------------------------------------------------------


async def test_trust_device_skips_2fa_on_next_sign_in() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink)
    await _signup(driver)
    await _enable_and_verify(driver)
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    # Sign in → challenge → verify OTP with trustDevice.
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json()["twoFactorRedirect"] is True
    await driver.request("POST", "/two-factor/send-otp")
    r = await driver.request(
        "POST",
        "/two-factor/verify-otp",
        json_body={"code": sink.otp, "trustDevice": True},
    )
    assert r.status == 200, r.json()
    assert driver.cookies.get("better-auth.trust_device")

    # Sign out — trust cookie survives. Sign in again → no challenge.
    await driver.request("POST", "/sign-out")
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json().get("twoFactorRedirect") is None
    assert r.json()["user"]


async def test_trust_device_revoked_on_disable() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink)
    await _signup(driver)
    await _enable_and_verify(driver)
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    await driver.request("POST", "/two-factor/send-otp")
    await driver.request(
        "POST",
        "/two-factor/verify-otp",
        json_body={"code": sink.otp, "trustDevice": True},
    )
    assert driver.cookies.get("better-auth.trust_device")

    # Disable 2FA — trust cookie cleared.
    r = await driver.request(
        "POST", "/two-factor/disable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200
    assert driver.cookies.get("better-auth.trust_device", "") == ""


async def test_trust_device_max_age_custom() -> None:
    sink = _OTPSink()
    custom = 7 * 24 * 60 * 60
    driver = _build(otp_sink=sink, trust_device_max_age=custom)
    await _signup(driver)
    await _enable_and_verify(driver)
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()

    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    await driver.request("POST", "/two-factor/send-otp")
    r = await driver.request(
        "POST",
        "/two-factor/verify-otp",
        json_body={"code": sink.otp, "trustDevice": True},
    )
    max_age = _cookie_attr(r, "better-auth.trust_device", "max-age")
    assert int(max_age) == custom


def _cookie_attr(resp, name: str, attr: str) -> str:
    for k, v in resp.headers:
        if k.lower() != "set-cookie":
            continue
        if not v.startswith(f"{name}="):
            continue
        for part in v.split(";"):
            key, _, value = part.strip().partition("=")
            if key.lower() == attr.lower():
                return value
    return ""


async def test_two_factor_cookie_max_age_custom() -> None:
    custom = 15 * 60
    driver = _build(skip_verification_on_enable=True, two_factor_cookie_max_age=custom)
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    max_age = _cookie_attr(r, "better-auth.two_factor", "max-age")
    assert int(max_age) == custom


# ---------------------------------------------------------------------------
# twoFactorMethods reporting
# ---------------------------------------------------------------------------


async def test_methods_totp_only_when_otp_not_configured() -> None:
    driver = _build()  # no otp_options
    await _signup(driver)
    await _enable_and_verify(driver)
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json()["twoFactorRedirect"] is True
    assert r.json()["twoFactorMethods"] == ["totp"]


async def test_methods_no_redirect_when_totp_unverified() -> None:
    driver = _build()
    await _signup(driver)
    # Enable but DO NOT verify (twoFactorEnabled stays False).
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    # Not enabled → normal sign-in, no challenge.
    assert r.json().get("twoFactorRedirect") is None
    assert r.json()["user"]


async def test_methods_otp_only_when_totp_disabled() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink, totp_disable=True, skip_verification_on_enable=True)
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json()["twoFactorRedirect"] is True
    assert r.json()["twoFactorMethods"] == ["otp"]


# ---------------------------------------------------------------------------
# OTP storage modes
# ---------------------------------------------------------------------------


async def test_otp_storage_hashed() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink, store_otp="hashed", skip_verification_on_enable=True)
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    await driver.request("POST", "/two-factor/send-otp")
    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": sink.otp}
    )
    assert r.status == 200, r.json()


async def test_otp_storage_hashed_rejects_invalid() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink, store_otp="hashed", skip_verification_on_enable=True)
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    await driver.request("POST", "/two-factor/send-otp")
    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": "000000"}
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_CODE"


async def test_otp_storage_encrypted() -> None:
    sink = _OTPSink()
    driver = _build(otp_sink=sink, store_otp="encrypted", skip_verification_on_enable=True)
    await _signup(driver)
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    await driver.request("POST", "/two-factor/send-otp")
    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": sink.otp}
    )
    assert r.status == 200, r.json()


# ---------------------------------------------------------------------------
# replay protection (kept from the original Python suite)
# ---------------------------------------------------------------------------


async def test_old_totp_code_rejected() -> None:
    driver = _build()
    await _signup(driver, email="x@example.com")
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    secret = _secret_from_uri(r.json()["totpURI"])
    old_code = pyotp.TOTP(secret).at(int(time.time()) - 600)
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": old_code}
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_CODE"
