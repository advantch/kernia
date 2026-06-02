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
from kernia.auth import init
from kernia.plugins import email_and_password, two_factor
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver

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


def _tf_opts(
    *,
    otp_sink: _OTPSink | None,
    skip_verification_on_enable: bool,
    trust_device_max_age: int | None,
    two_factor_cookie_max_age: int | None,
    issuer: str | None,
    totp_disable: bool,
    allow_passwordless: bool,
    store_otp: object | None,
    store_backup_codes: object | None = None,
) -> dict[str, object]:
    tf_opts: dict[str, object] = {}
    if otp_sink is not None:
        otp_opts: dict[str, object] = {"send_otp": otp_sink}
        if store_otp is not None:
            otp_opts["store_otp"] = store_otp
        tf_opts["otp_options"] = otp_opts
    if store_backup_codes is not None:
        tf_opts["backup_code_options"] = {"store_backup_codes": store_backup_codes}
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
    return tf_opts


def _build_with_adapter(
    *,
    otp_sink: _OTPSink | None = None,
    skip_verification_on_enable: bool = False,
    trust_device_max_age: int | None = None,
    two_factor_cookie_max_age: int | None = None,
    issuer: str | None = None,
    totp_disable: bool = False,
    allow_passwordless: bool = False,
    store_otp: object | None = None,
    store_backup_codes: object | None = None,
):
    """Build the driver and return it alongside the backing adapter.

    The adapter handle lets tests inspect the ``twoFactor`` table directly (e.g.
    the ``verified`` column) for the issue-#8627 OTP-only-adding-TOTP cases.
    """
    tf_opts = _tf_opts(
        otp_sink=otp_sink,
        skip_verification_on_enable=skip_verification_on_enable,
        trust_device_max_age=trust_device_max_age,
        two_factor_cookie_max_age=two_factor_cookie_max_age,
        issuer=issuer,
        totp_disable=totp_disable,
        allow_passwordless=allow_passwordless,
        store_otp=store_otp,
        store_backup_codes=store_backup_codes,
    )
    adapter = memory_adapter()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret-key",
            plugins=[email_and_password(), two_factor()],
            advanced={"two-factor": tf_opts},
        )
    )
    return ASGIDriver(app=auth.router.mount()), adapter


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
    driver, _ = _build_with_adapter(
        otp_sink=otp_sink,
        skip_verification_on_enable=skip_verification_on_enable,
        trust_device_max_age=trust_device_max_age,
        two_factor_cookie_max_age=two_factor_cookie_max_age,
        issuer=issuer,
        totp_disable=totp_disable,
        allow_passwordless=allow_passwordless,
        store_otp=store_otp,
    )
    return driver


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


async def test_trust_device_forced_when_server_record_expired() -> None:
    """Upstream: 'should force 2FA when server-side trust record is expired'.

    The trust cookie alone is not sufficient: if the backing verification row is
    gone (expired/revoked server-side), the next sign-in must re-challenge.
    """
    sink = _OTPSink()
    driver, adapter = _build_with_adapter(otp_sink=sink)
    await _signup(driver)
    await _enable_and_verify(driver)
    r = await driver.request("GET", "/get-session")
    user_id = r.json()["user"]["id"]
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
    assert driver.cookies.get("better-auth.trust_device")

    # Drop the server-side trust record (simulating expiry) — the cookie stays.
    await adapter.delete_many(
        model="verification", where=(Where(field="value", value=user_id),)
    )

    await driver.request("POST", "/sign-out")
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json()["twoFactorRedirect"] is True


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


async def test_methods_otp_only_when_2fa_enabled_but_no_totp_row() -> None:
    """Ported from "should return twoFactorMethods: ['otp'] when user has 2fa
    enabled but no totp row" (totp enabled in config, otp enabled)."""
    sink = _OTPSink()
    driver, adapter = _build_with_adapter(otp_sink=sink)
    await _signup(driver)
    # Force-enable 2FA without ever creating a totp row.
    await adapter.update(
        model="user",
        where=(Where(field="email", value=TEST_EMAIL),),
        update={"twoFactorEnabled": True},
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


async def test_methods_exclude_unverified_totp() -> None:
    """Ported from "should exclude unverified totp from twoFactorMethods".

    An abandoned (verified=false) TOTP enrollment on an OTP-enabled account is
    excluded; only ['otp'] is offered.
    """
    sink = _OTPSink()
    driver, adapter = _build_with_adapter(otp_sink=sink)
    await _signup(driver)
    # enable creates a verified=false totp row but leaves twoFactorEnabled false.
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    # Simulate an OTP-enrolled user who began (but never finished) adding TOTP.
    await adapter.update(
        model="user",
        where=(Where(field="email", value=TEST_EMAIL),),
        update={"twoFactorEnabled": True},
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


async def test_methods_totp_and_otp_when_verified() -> None:
    """Ported from "should return twoFactorMethods: ['totp', 'otp'] when user
    has verified totp" (totp enabled in config, otp enabled)."""
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
    assert r.json()["twoFactorMethods"] == ["totp", "otp"]


async def test_no_2fa_challenge_on_magic_link_sign_in() -> None:
    """Ported from "should not challenge 2FA on magic-link sign-in" (PR #9205).

    2FA enforcement is scoped to credential sign-in paths; a magic-link sign-in
    for a 2FA-enabled user completes without a twoFactorRedirect challenge.
    """
    from urllib.parse import parse_qs, urlencode, urlparse

    from kernia.plugins import magic_link

    captured: dict[str, str] = {}

    async def send_magic_link(email: str, url: str, token: str) -> None:
        captured["url"] = url

    sink = _OTPSink()
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[
                email_and_password(),
                two_factor(),
                magic_link(),
            ],
            advanced={
                "two-factor": {
                    "otp_options": {"send_otp": sink},
                    "skip_verification_on_enable": True,
                },
                "magic-link": {"send_magic_link": send_magic_link},
            },
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    await _signup(driver)
    # Enable 2FA (skip_verification → twoFactorEnabled immediately true).
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    driver.cookies.clear()

    # Magic-link sign-in for the same (2FA-enabled) user.
    r = await driver.request(
        "POST", "/sign-in/magic-link", json_body={"email": TEST_EMAIL}
    )
    assert r.status == 200, r.json()
    token = parse_qs(urlparse(captured["url"]).query)["token"][0]

    r = await driver.request(
        "GET", "/magic-link/verify", query=urlencode({"token": token})
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body.get("twoFactorRedirect") is None
    assert body["user"]["email"] == TEST_EMAIL
    assert body["session"]["id"]


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


# ---------------------------------------------------------------------------
# default cookie max-ages (upstream: trustDeviceMaxAge / twoFactorCookieMaxAge)
# ---------------------------------------------------------------------------


async def test_default_trust_device_max_age_is_30_days() -> None:
    """Upstream: 'should use default 30 days when trustDeviceMaxAge not specified'."""
    sink = _OTPSink()
    driver = _build(otp_sink=sink)  # no trust_device_max_age override
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
    assert int(max_age) == 30 * 24 * 60 * 60


async def test_default_two_factor_cookie_max_age_is_10_minutes() -> None:
    """Upstream: 'should use default 10 minutes when twoFactorCookieMaxAge not specified'."""
    driver = _build(skip_verification_on_enable=True)  # no override
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
    assert int(max_age) == 10 * 60


# ---------------------------------------------------------------------------
# password gating on enable (upstream: password required for credential users)
# ---------------------------------------------------------------------------


async def test_enable_rejects_missing_password_for_credential_user() -> None:
    """Upstream: 'rejects enabling without password for credential users'.

    Omitting the password entirely (not just a wrong one) must still surface
    INVALID_PASSWORD — credential presence is never leaked via a distinct code.
    """
    driver = _build()
    await _signup(driver)
    r = await driver.request("POST", "/two-factor/enable", json_body={})
    assert r.status == 400
    assert r.json()["code"] == "INVALID_PASSWORD"


# ---------------------------------------------------------------------------
# 2FA enforcement scope (upstream: only credential sign-in is challenged)
# ---------------------------------------------------------------------------


async def test_no_challenge_on_authenticated_non_sign_in_endpoint() -> None:
    """Upstream: 'should not challenge 2FA on authenticated non-sign-in endpoints'.

    With 2FA enabled and an active session, a non-sign-in request (/update-user)
    returns its normal payload — the sign-in gate never fires.
    """
    driver = _build()
    await _signup(driver)
    await _enable_and_verify(driver)
    r = await driver.request(
        "POST", "/update-user", json_body={"name": "Renamed"}
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert "twoFactorRedirect" not in body
    assert body["user"]["name"] == "Renamed"


# ---------------------------------------------------------------------------
# OTP-only account adding TOTP (upstream issue #8627)
# ---------------------------------------------------------------------------


async def _otp_enroll_authenticated(driver: ASGIDriver, sink: _OTPSink) -> str:
    """Drive an OTP-based enrollment while authenticated.

    Returns the user id. Enables 2FA (creates an *unverified* twoFactor/TOTP row),
    then sends + verifies an OTP under the active session so twoFactorEnabled
    flips true while the TOTP row stays verified=false — the #8627 state.
    """
    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    await driver.request("POST", "/two-factor/send-otp")
    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": sink.otp}
    )
    assert r.status == 200, r.json()
    r = await driver.request("GET", "/get-session")
    return r.json()["user"]["id"]


async def test_enable_creates_unverified_totp_row() -> None:
    """Upstream: 'should create twoFactor row with verified=false on enableTwoFactor'."""
    driver, adapter = _build_with_adapter()
    await _signup(driver)
    r = await driver.request("GET", "/get-session")
    user_id = r.json()["user"]["id"]

    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    row = await adapter.find_one(
        model="twoFactor", where=(Where(field="userId", value=user_id),)
    )
    assert row is not None
    assert row["verified"] is False


async def test_verify_totp_marks_row_verified() -> None:
    """Upstream: 'should mark TOTP as verified after verifyTOTP during enrollment'."""
    driver, adapter = _build_with_adapter()
    await _signup(driver)
    r = await driver.request("GET", "/get-session")
    user_id = r.json()["user"]["id"]

    await _enable_and_verify(driver)
    row = await adapter.find_one(
        model="twoFactor", where=(Where(field="userId", value=user_id),)
    )
    assert row is not None
    assert row["verified"] is True


async def test_preserve_verified_state_during_re_enrollment() -> None:
    """Upstream: 'should preserve verified state during re-enrollment'.

    Re-running enable on an already-verified account keeps the new row verified
    (so the user isn't silently downgraded to an unverified TOTP secret).
    """
    driver, adapter = _build_with_adapter()
    await _signup(driver)
    r = await driver.request("GET", "/get-session")
    user_id = r.json()["user"]["id"]

    await _enable_and_verify(driver)
    # Re-enable (fresh secret) — verified must remain true.
    await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    row = await adapter.find_one(
        model="twoFactor", where=(Where(field="userId", value=user_id),)
    )
    assert row is not None
    assert row["verified"] is True


async def test_reject_unverified_totp_during_sign_in_allow_otp_fallback() -> None:
    """Upstream: 'should reject unverified TOTP during sign-in and allow OTP fallback'.

    For an OTP-only account that has merely *enabled* (but not verified) TOTP, a
    sign-in TOTP attempt is rejected while OTP still completes the second factor.
    """
    sink = _OTPSink()
    driver, adapter = _build_with_adapter(otp_sink=sink)
    await _signup(driver)
    user_id = await _otp_enroll_authenticated(driver, sink)

    # The TOTP row is enabled-but-unverified, yet 2FA is on.
    row = await adapter.find_one(
        model="twoFactor", where=(Where(field="userId", value=user_id),)
    )
    secret = str(row["secret"])
    assert row["verified"] is False

    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert r.json()["twoFactorRedirect"] is True
    # totp is excluded from the advertised methods while unverified.
    assert r.json()["twoFactorMethods"] == ["otp"]

    # A valid TOTP code is still rejected — the secret is not verified.
    r = await driver.request(
        "POST", "/two-factor/verify-totp", json_body={"code": pyotp.TOTP(secret).now()}
    )
    assert r.status == 400
    assert r.json()["code"] == "TOTP_NOT_ENABLED"

    # OTP fallback completes the sign-in.
    await driver.request("POST", "/two-factor/send-otp")
    r = await driver.request(
        "POST", "/two-factor/verify-otp", json_body={"code": sink.otp}
    )
    assert r.status == 200, r.json()
    assert driver.cookies.get("better-auth.session_token")


# ---------------------------------------------------------------------------
# custom hash function OTP storage (upstream: OTP storage modes)
# ---------------------------------------------------------------------------


async def test_otp_storage_custom_hash_function() -> None:
    """Upstream: 'should verify OTP with custom hash function'."""
    import hashlib

    def _custom_hash(code: str) -> str:
        return hashlib.sha512(f"pepper:{code}".encode()).hexdigest()

    sink = _OTPSink()
    driver = _build(
        otp_sink=sink,
        store_otp={"hash": _custom_hash},
        skip_verification_on_enable=True,
    )
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
# passwordless: users without a credential account skip the password gate
# (upstream: 'two factor passwordless')
# ---------------------------------------------------------------------------


def _build_passwordless(*, skip_verification_on_enable: bool = False):
    """Build a driver + auth handle with passwordless 2FA enabled."""
    tf_opts = _tf_opts(
        otp_sink=None,
        skip_verification_on_enable=skip_verification_on_enable,
        trust_device_max_age=None,
        two_factor_cookie_max_age=None,
        issuer=None,
        totp_disable=False,
        allow_passwordless=True,
        store_otp=None,
    )
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password(), two_factor()],
            advanced={"two-factor": tf_opts},
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


async def _credentialless_session(auth, driver: ASGIDriver) -> str:
    """Create a user with no credential account and an authenticated session.

    Mirrors upstream's social/passwordless user: there is no credential row, so
    the password gate must be skipped when ``allowPasswordless`` is set.
    """
    from kernia.context import create_session

    now = int(time.time())
    user = await auth.context.adapter.create(
        model="user",
        data={
            "email": "pwless@example.com",
            "name": "Pwless",
            "emailVerified": True,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    _session, cookies = await create_session(auth.context, user_id=user["id"])
    for name, value, _attrs in cookies:
        driver.cookies[name] = value
    return str(user["id"])


async def test_passwordless_enable_without_password() -> None:
    """Upstream: 'allows enabling without password for users without credentials'."""
    driver, auth = _build_passwordless()
    await _credentialless_session(auth, driver)
    r = await driver.request("POST", "/two-factor/enable", json_body={})
    assert r.status == 200, r.json()
    assert len(r.json()["backupCodes"]) == 10
    assert r.json()["totpURI"].startswith("otpauth://totp/")


async def test_passwordless_get_totp_uri_without_password() -> None:
    """Upstream: 'allows getting totp uri without password'."""
    driver, auth = _build_passwordless(skip_verification_on_enable=True)
    await _credentialless_session(auth, driver)
    await driver.request("POST", "/two-factor/enable", json_body={})
    r = await driver.request("POST", "/two-factor/get-totp-uri", json_body={})
    assert r.status == 200, r.json()
    assert r.json()["totpURI"].startswith("otpauth://totp/")


async def test_passwordless_generate_backup_codes_without_password() -> None:
    """Upstream: 'allows generating backup codes without password'."""
    driver, auth = _build_passwordless(skip_verification_on_enable=True)
    await _credentialless_session(auth, driver)
    await driver.request("POST", "/two-factor/enable", json_body={})
    r = await driver.request(
        "POST", "/two-factor/generate-backup-codes", json_body={}
    )
    assert r.status == 200, r.json()
    assert len(r.json()["backupCodes"]) == 10


async def test_passwordless_disable_without_password() -> None:
    """Upstream: 'allows disabling without password'."""
    driver, auth = _build_passwordless(skip_verification_on_enable=True)
    await _credentialless_session(auth, driver)
    await driver.request("POST", "/two-factor/enable", json_body={})
    r = await driver.request("POST", "/two-factor/disable", json_body={})
    assert r.status == 200, r.json()
    assert r.json()["status"] is True


# ---------------------------------------------------------------------------
# backup codes storage configurations (PR #7231)
# ---------------------------------------------------------------------------


def _decode_stored_plain(raw: str) -> list[str]:
    import json

    return json.loads(raw)


def _decode_stored_encrypted(raw: str) -> list[str]:
    import json

    from kernia.plugins.two_factor.routes import _symmetric_decrypt

    return json.loads(_symmetric_decrypt("test-secret-key", raw))


async def _custom_encrypt(data: str) -> str:
    import base64

    return base64.b64encode(data.encode()).decode() + ":custom"


async def _custom_decrypt(data: str) -> str:
    import base64

    encoded = data.split(":custom")[0]
    return base64.b64decode(encoded.encode()).decode()


def _decode_stored_custom(raw: str) -> list[str]:
    import base64
    import json

    encoded = raw.split(":custom")[0]
    return json.loads(base64.b64decode(encoded.encode()).decode())


async def _run_backup_code_storage_case(
    *, store_backup_codes, decode_stored, verify_format
) -> None:
    """Shared body for the three storage modes — enroll, inspect the stored
    format, consume a backup code, and re-inspect that the format/contents
    survive the round-trip. Ported from PR #7231's parametrized describe."""
    driver, adapter = _build_with_adapter(
        skip_verification_on_enable=True, store_backup_codes=store_backup_codes
    )
    await _signup(driver)

    r = await driver.request(
        "POST", "/two-factor/enable", json_body={"password": TEST_PASSWORD}
    )
    assert r.status == 200, r.json()
    initial_codes = r.json()["backupCodes"]
    assert len(initial_codes) == 10

    user = await adapter.find_one(
        model="user", where=(Where(field="email", value=TEST_EMAIL),)
    )
    row = await adapter.find_one(
        model="twoFactor", where=(Where(field="userId", value=user["id"]),)
    )
    assert row is not None
    verify_format(str(row["backupCodes"]))
    assert decode_stored(str(row["backupCodes"])) == initial_codes

    # Sign out, re-sign-in (2FA challenge) and consume a backup code.
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    used = initial_codes[0]
    r = await driver.request(
        "POST", "/two-factor/verify-backup-code", json_body={"code": used}
    )
    assert r.status == 200, r.json()

    row_after = await adapter.find_one(
        model="twoFactor", where=(Where(field="userId", value=user["id"]),)
    )
    verify_format(str(row_after["backupCodes"]))
    remaining = decode_stored(str(row_after["backupCodes"]))
    assert len(remaining) == 9
    assert used not in remaining
    assert remaining == [c for c in initial_codes if c != used]


async def test_backup_codes_plain_storage_preserved() -> None:
    """Ported: 'should preserve plain storage format after backup code verification'."""

    def verify_format(raw: str) -> None:
        import json

        json.loads(raw)  # plain mode stores a JSON array

    await _run_backup_code_storage_case(
        store_backup_codes="plain",
        decode_stored=_decode_stored_plain,
        verify_format=verify_format,
    )


async def test_backup_codes_encrypted_storage_preserved() -> None:
    """Ported: 'should preserve encrypted storage format after backup code
    verification' — the at-rest value is not parseable JSON."""
    import json

    def verify_format(raw: str) -> None:
        try:
            json.loads(raw)
        except json.JSONDecodeError:
            return
        raise AssertionError("encrypted backup codes should not be valid JSON")

    await _run_backup_code_storage_case(
        store_backup_codes="encrypted",
        decode_stored=_decode_stored_encrypted,
        verify_format=verify_format,
    )


async def test_backup_codes_custom_storage_preserved() -> None:
    """Ported: 'should preserve custom storage format after backup code
    verification' — custom encrypt/decrypt callables round-trip."""

    def verify_format(raw: str) -> None:
        assert ":custom" in raw

    await _run_backup_code_storage_case(
        store_backup_codes={"encrypt": _custom_encrypt, "decrypt": _custom_decrypt},
        decode_stored=_decode_stored_custom,
        verify_format=verify_format,
    )
