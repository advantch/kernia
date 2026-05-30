"""Email-OTP integration tests across every adapter.

Drives the ASGI app via `ASGIDriver`. `MockSMTP` captures the dispatched OTPs
(stored as `email.meta["otp"]`). Each test parametrizes over the adapter matrix
exposed by `all_adapters_param()`.
"""

from __future__ import annotations

from typing import Any

import pytest
from better_auth.auth import init
from better_auth.plugins.email_otp import email_otp
from better_auth.plugins.email_password import email_and_password
from better_auth.types.init_options import BetterAuthOptions
from better_auth_test_utils import (
    ASGIDriver,
    MockSMTP,
    SentEmail,
    all_adapters_param,
)


def _build_driver(
    adapter: Any,
    smtp: MockSMTP,
    *,
    expires_in: int = 60,
    disable_sign_up: bool = False,
    **extra_opts: Any,
):
    async def send_otp(email: str, otp: str, purpose: str) -> None:
        await smtp.send(
            SentEmail(
                to=email,
                subject=f"Code ({purpose})",
                body=f"Your code: {otp}",
                meta={"otp": otp, "purpose": purpose},
            )
        )

    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost:3000",
            plugins=[email_and_password(), email_otp()],
            advanced={
                "email-otp": {
                    "send_otp": send_otp,
                    "expires_in": expires_in,
                    "disable_sign_up": disable_sign_up,
                    **extra_opts,
                },
                "disable_csrf_check": True,
            },
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


@pytest.mark.parametrize(*all_adapters_param())
async def test_email_otp_sign_in_happy_path(adapter_factory) -> None:
    adapter = await adapter_factory()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)

    r = await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "alice@example.com"}
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True
    otp = smtp.sent[0].meta["otp"]
    assert len(otp) == 6
    assert otp.isdigit()

    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "alice@example.com", "otp": otp},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "better-auth.session_token" in driver.cookies


@pytest.mark.parametrize(*all_adapters_param())
async def test_email_otp_wrong_code(adapter_factory) -> None:
    adapter = await adapter_factory()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "x@example.com"}
    )
    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "x@example.com", "otp": "000000"},
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_OTP"


@pytest.mark.parametrize(*all_adapters_param())
async def test_email_otp_expired(adapter_factory) -> None:
    adapter = await adapter_factory()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp, expires_in=-10)  # already expired
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "expired@example.com"}
    )
    otp = smtp.sent[0].meta["otp"]
    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "expired@example.com", "otp": otp},
    )
    assert r.status == 400
    assert r.json()["code"] == "OTP_EXPIRED"


@pytest.mark.parametrize(*all_adapters_param())
async def test_email_otp_sign_up_disabled(adapter_factory) -> None:
    adapter = await adapter_factory()
    driver, _ = _build_driver(adapter, MockSMTP(), disable_sign_up=True)
    r = await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "unknown@example.com"}
    )
    assert r.status == 403
    assert r.json()["code"] == "EMAIL_OTP_SIGN_UP_DISABLED"


@pytest.mark.parametrize(*all_adapters_param())
async def test_email_otp_password_reset_round_trip(adapter_factory) -> None:
    adapter = await adapter_factory()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)

    # Create a user first via email/password.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "reset@example.com", "password": "oldpassword"},
    )
    assert r.status == 200, r.json()
    driver.cookies.clear()

    # Request OTP.
    smtp.clear()
    r = await driver.request(
        "POST",
        "/forget-password/email-otp",
        json_body={"email": "reset@example.com"},
    )
    assert r.status == 200
    otp = next(
        (e.meta["otp"] for e in smtp.sent if e.meta.get("purpose") == "forget-password"),
        None,
    )
    assert otp is not None

    # Reset password.
    r = await driver.request(
        "POST",
        "/email-otp/reset-password",
        json_body={
            "email": "reset@example.com",
            "otp": otp,
            "password": "newpassword",
        },
    )
    assert r.status == 200, r.json()

    # Old password fails.
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "reset@example.com", "password": "oldpassword"},
    )
    assert r.status == 401

    # New password works.
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "reset@example.com", "password": "newpassword"},
    )
    assert r.status == 200


# ----- ported from reference email-otp.test.ts (owned-endpoint subset) -----


async def test_too_many_attempts() -> None:
    """After `allowed_attempts` wrong codes, verify returns TOO_MANY_ATTEMPTS."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp, allowed_attempts=2)
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "attempts@example.com"}
    )
    for _ in range(2):
        bad = await driver.request(
            "POST",
            "/email-otp/verify",
            json_body={"email": "attempts@example.com", "otp": "000000"},
        )
        assert bad.status == 400
        assert bad.json()["code"] == "INVALID_OTP"
    third = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "attempts@example.com", "otp": "000000"},
    )
    assert third.status == 403
    assert third.json()["code"] == "TOO_MANY_ATTEMPTS"


async def test_custom_generate_otp() -> None:
    from better_auth_memory_adapter import memory_adapter

    def generate(_data: Any, _ctx: Any = None) -> str:
        return "135790"

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp, generate_otp=generate)
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "custom@example.com"}
    )
    assert smtp.sent[0].meta["otp"] == "135790"
    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "custom@example.com", "otp": "135790"},
    )
    assert r.status == 200, r.json()


async def test_store_otp_hashed_round_trip() -> None:
    """With store_otp='hashed' the raw code still verifies but is not stored plain."""
    from better_auth.plugins.email_otp.routes import default_key_hasher
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp, store_otp="hashed")
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "hashed@example.com"}
    )
    otp = smtp.sent[0].meta["otp"]

    # Stored value is the hash, never the plain code.
    rec = await adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value="email-otp:sign-in:hashed@example.com"),),
    )
    assert rec is not None
    stored = str(rec["value"]).rpartition(":")[0]
    assert stored != otp
    assert stored == default_key_hasher(otp)

    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "hashed@example.com", "otp": otp},
    )
    assert r.status == 200, r.json()


async def test_resend_reuse_returns_same_otp() -> None:
    """resend_strategy='reuse' resends the same plain OTP while it is valid."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp, resend_strategy="reuse")
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "reuse@example.com"}
    )
    first = smtp.sent[0].meta["otp"]
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "reuse@example.com"}
    )
    second = smtp.sent[1].meta["otp"]
    assert first == second


async def test_resend_rotate_returns_new_otp() -> None:
    """Default rotate strategy issues a fresh OTP each time (almost always different)."""
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "rotate@example.com"}
    )
    # Only the latest OTP row survives rotation.
    rows = await adapter.find_many(
        model="verification",
        where=(Where(field="identifier", value="email-otp:sign-in:rotate@example.com"),),
    )
    assert len(rows) == 1
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "rotate@example.com"}
    )
    rows = await adapter.find_many(
        model="verification",
        where=(Where(field="identifier", value="email-otp:sign-in:rotate@example.com"),),
    )
    assert len(rows) == 1


async def test_verify_email_round_trip() -> None:
    """An authenticated user verifies their own email via OTP."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp)

    # Sign in via OTP (creates the user + a session).
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "verify@example.com"}
    )
    sign_in_otp = smtp.sent[-1].meta["otp"]
    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "verify@example.com", "otp": sign_in_otp},
    )
    assert r.status == 200, r.json()

    # Request + consume an email-verification OTP.
    smtp.clear()
    r = await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "verify@example.com", "type": "email-verification"},
    )
    assert r.status == 200, r.json()
    verify_otp = smtp.sent[-1].meta["otp"]
    r = await driver.request(
        "POST",
        "/email-otp/verify-email",
        json_body={"email": "verify@example.com", "otp": verify_otp},
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True


# ----- additional ported cases (change-email, server-side OTP, enumeration) -----


async def test_reject_change_email_type_on_send_verification() -> None:
    """send-verification-otp with type=change-email is rejected (INVALID_OTP_TYPE).

    Ported from "should reject change-email type".
    """
    from better_auth_memory_adapter import memory_adapter

    driver, _ = _build_driver(memory_adapter(), MockSMTP())
    r = await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rt@example.com", "type": "change-email"},
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "INVALID_OTP_TYPE"


async def test_send_verification_invalid_email() -> None:
    """Ported from "should fail on invalid email"."""
    from better_auth_memory_adapter import memory_adapter

    driver, _ = _build_driver(memory_adapter(), MockSMTP())
    r = await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "not-an-email", "type": "email-verification"},
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "INVALID_EMAIL"


async def test_no_otp_email_for_nonexistent_user_when_disable_sign_up() -> None:
    """Enumeration protection: verification OTP is not sent for unknown users.

    Ported from "should not send OTP email for non-existent users when
    disableSignUp is enabled" + "should prevent user enumeration".
    """
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp, disable_sign_up=True)
    r = await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "ghost@example.com", "type": "email-verification"},
    )
    # Returns success (no enumeration) but sends nothing.
    assert r.status == 200, r.json()
    assert r.json()["success"] is True
    assert smtp.sent == []


async def test_create_and_get_verification_otp_server() -> None:
    """Server-side create + recover the plain OTP.

    Ported from "should create verification otp on server" + "should get
    verification otp on server".
    """
    from better_auth_memory_adapter import memory_adapter

    driver, _ = _build_driver(memory_adapter(), MockSMTP())
    r = await driver.request(
        "POST",
        "/email-otp/create-verification-otp",
        json_body={"email": "srv@example.com", "type": "sign-in"},
    )
    assert r.status == 200, r.json()
    created = r.json()
    assert isinstance(created, str)
    assert len(created) == 6

    r = await driver.request(
        "POST",
        "/email-otp/get-verification-otp",
        json_body={"email": "srv@example.com", "type": "sign-in"},
    )
    assert r.status == 200, r.json()
    assert r.json()["otp"] == created


async def test_get_verification_otp_hashed_rejected() -> None:
    """Cannot recover the plain OTP when store_otp='hashed'.

    Ported from "should not be allowed to get otp if storeOTP is hashed".
    """
    from better_auth_memory_adapter import memory_adapter

    driver, _ = _build_driver(memory_adapter(), MockSMTP(), store_otp="hashed")
    await driver.request(
        "POST",
        "/email-otp/create-verification-otp",
        json_body={"email": "h@example.com", "type": "sign-in"},
    )
    r = await driver.request(
        "POST",
        "/email-otp/get-verification-otp",
        json_body={"email": "h@example.com", "type": "sign-in"},
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "OTP_HASHED"


async def test_store_otp_encrypted_round_trip() -> None:
    """store_otp='encrypted' is recoverable and verifies; not stored plain.

    Ported from the "encrypted" storeOTP describe block.
    """
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp, store_otp="encrypted")
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "enc@example.com"}
    )
    otp = smtp.sent[0].meta["otp"]

    rec = await adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value="email-otp:sign-in:enc@example.com"),),
    )
    assert rec is not None
    stored = str(rec["value"]).rpartition(":")[0]
    assert stored != otp  # not plaintext at rest

    # Recoverable via get-verification-otp.
    r = await driver.request(
        "POST",
        "/email-otp/get-verification-otp",
        json_body={"email": "enc@example.com", "type": "sign-in"},
    )
    assert r.status == 200, r.json()
    assert r.json()["otp"] == otp

    # And verifies normally.
    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "enc@example.com", "otp": otp},
    )
    assert r.status == 200, r.json()


async def test_check_verification_otp_non_consuming() -> None:
    """check-verification-otp validates without consuming the OTP."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp)
    await driver.request(
        "POST",
        "/email-otp/create-verification-otp",
        json_body={"email": "chk@example.com", "type": "sign-in"},
    )
    r = await driver.request(
        "POST",
        "/email-otp/get-verification-otp",
        json_body={"email": "chk@example.com", "type": "sign-in"},
    )
    otp = r.json()["otp"]

    # Check twice: still valid both times (not consumed).
    for _ in range(2):
        r = await driver.request(
            "POST",
            "/email-otp/check-verification-otp",
            json_body={"email": "chk@example.com", "otp": otp, "type": "sign-in"},
        )
        assert r.status == 200, r.json()
        assert r.json()["success"] is True

    # Wrong code reports INVALID_OTP.
    r = await driver.request(
        "POST",
        "/email-otp/check-verification-otp",
        json_body={"email": "chk@example.com", "otp": "000000", "type": "sign-in"},
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_OTP"


def _build_change_email_driver(adapter, smtp, **extra):
    return _build_driver(
        adapter,
        smtp,
        change_email={"enabled": True, **extra},
    )


async def test_change_email_round_trip() -> None:
    """Full change-email flow: request OTP to new address, then confirm.

    Ported from change email "request" + "change" describes.
    """
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_change_email_driver(adapter, smtp)

    # Establish a session via OTP sign-in.
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "old@example.com"}
    )
    sign_in_otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "old@example.com", "otp": sign_in_otp},
    )

    # Request the change-email OTP (delivered to the NEW address).
    smtp.clear()
    r = await driver.request(
        "POST",
        "/email-otp/request-email-change",
        json_body={"new_email": "new@example.com"},
    )
    assert r.status == 200, r.json()
    sent = smtp.sent[-1]
    assert sent.to == "new@example.com"
    assert sent.meta["purpose"] == "change-email"
    change_otp = sent.meta["otp"]

    # Confirm the change.
    r = await driver.request(
        "POST",
        "/email-otp/change-email",
        json_body={"new_email": "new@example.com", "otp": change_otp},
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True

    # User's email is updated.
    from better_auth.types.adapter import Where

    user = await adapter.find_one(
        model="user", where=(Where(field="email", value="new@example.com"),)
    )
    assert user is not None


async def test_change_email_no_session() -> None:
    """Ported from "should not send otp for change email request if session
    does not exist"."""
    from better_auth_memory_adapter import memory_adapter

    driver, _ = _build_change_email_driver(memory_adapter(), MockSMTP())
    r = await driver.request(
        "POST",
        "/email-otp/request-email-change",
        json_body={"new_email": "new@example.com"},
    )
    assert r.status == 401, r.json()


async def test_change_email_disabled() -> None:
    """Ported from "should not send otp ... when change email with OTP is
    disabled"."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp)  # changeEmail not enabled
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "u@example.com"}
    )
    otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST", "/email-otp/verify", json_body={"email": "u@example.com", "otp": otp}
    )
    r = await driver.request(
        "POST",
        "/email-otp/request-email-change",
        json_body={"new_email": "new@example.com"},
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "CHANGE_EMAIL_DISABLED"


async def test_change_email_same_as_current() -> None:
    """Ported from "should not send otp ... if email is same as old email"."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_change_email_driver(memory_adapter(), smtp)
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "same@example.com"}
    )
    otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "same@example.com", "otp": otp},
    )
    r = await driver.request(
        "POST",
        "/email-otp/request-email-change",
        json_body={"new_email": "same@example.com"},
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "EMAIL_IS_THE_SAME"


async def test_request_password_reset_alias() -> None:
    """The new emailOtp.requestPasswordReset endpoint mirrors forget-password.

    Ported from "should reset password using new emailOtp.requestPasswordReset
    endpoint".
    """
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "alias@example.com", "password": "oldpassword"},
    )
    assert r.status == 200, r.json()
    driver.cookies.clear()

    smtp.clear()
    r = await driver.request(
        "POST",
        "/email-otp/request-password-reset",
        json_body={"email": "alias@example.com"},
    )
    assert r.status == 200, r.json()
    otp = next(
        e.meta["otp"]
        for e in smtp.sent
        if e.meta.get("purpose") == "forget-password"
    )
    r = await driver.request(
        "POST",
        "/email-otp/reset-password",
        json_body={
            "email": "alias@example.com",
            "otp": otp,
            "password": "newpassword",
        },
    )
    assert r.status == 200, r.json()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "alias@example.com", "password": "newpassword"},
    )
    assert r.status == 200, r.json()


async def test_on_password_reset_callback() -> None:
    """Ported from "should call onPasswordReset callback when resetting
    password"."""
    from better_auth_memory_adapter import memory_adapter

    called: list[dict] = []

    async def on_password_reset(data, _ctx=None) -> None:
        called.append(data)

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp, on_password_reset=on_password_reset)
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "cb@example.com", "password": "oldpassword"},
    )
    driver.cookies.clear()
    smtp.clear()
    await driver.request(
        "POST", "/forget-password/email-otp", json_body={"email": "cb@example.com"}
    )
    otp = next(
        e.meta["otp"]
        for e in smtp.sent
        if e.meta.get("purpose") == "forget-password"
    )
    r = await driver.request(
        "POST",
        "/email-otp/reset-password",
        json_body={"email": "cb@example.com", "otp": otp, "password": "newpassword"},
    )
    assert r.status == 200, r.json()
    assert len(called) == 1
    assert called[0]["user"]["email"] == "cb@example.com"


async def test_store_otp_custom_encryptor_round_trip() -> None:
    """store_otp={"encrypt","decrypt"} is recoverable, verifies, not stored plain.

    Ported from the "custom encryptor" describe (create / get / sign-in).
    """
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    async def encrypt(otp: str) -> str:
        return otp + "encrypted"

    async def decrypt(stored: str) -> str:
        return stored.replace("encrypted", "")

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(
        adapter, smtp, store_otp={"encrypt": encrypt, "decrypt": decrypt}
    )
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "ce@example.com", "type": "sign-in"},
    )
    otp = smtp.sent[-1].meta["otp"]

    # create: stored is not plaintext and the attempt suffix is ":0".
    rec = await adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value="email-otp:sign-in:ce@example.com"),),
    )
    assert rec is not None
    stored = str(rec["value"])
    assert len(stored) != 0
    assert stored.rpartition(":")[0] != otp
    assert stored.endswith(":0")

    # get: recoverable since custom decrypt is provided.
    r = await driver.request(
        "POST",
        "/email-otp/get-verification-otp",
        json_body={"email": "ce@example.com", "type": "sign-in"},
    )
    assert r.status == 200, r.json()
    assert r.json()["otp"] == otp
    assert len(otp) == 6

    # sign-in: verifies normally.
    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "ce@example.com", "otp": otp},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["email"] == "ce@example.com"


async def test_store_otp_custom_hasher_round_trip() -> None:
    """store_otp={"hash"} is one-way (get rejected) but still verifies on sign-in.

    Ported from the "custom hasher" describe (create / get-rejected / sign-in).
    """
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    async def _hash(otp: str) -> str:
        return otp + "hashed"

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp, store_otp={"hash": _hash})
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "ch@example.com", "type": "sign-in"},
    )
    otp = smtp.sent[-1].meta["otp"]

    rec = await adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value="email-otp:sign-in:ch@example.com"),),
    )
    assert rec is not None
    stored = str(rec["value"])
    assert len(stored) != 0
    assert stored.rpartition(":")[0] != otp
    assert stored.endswith(":0")

    # get: rejected — hashed OTPs are not recoverable.
    r = await driver.request(
        "POST",
        "/email-otp/get-verification-otp",
        json_body={"email": "ch@example.com", "type": "sign-in"},
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "OTP_HASHED"

    # sign-in: still verifies via the custom hash.
    r = await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "ch@example.com", "otp": otp},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["email"] == "ch@example.com"


async def test_verify_email_with_last_otp() -> None:
    """Re-issuing a verification OTP invalidates the previous one.

    Ported from "should verify email with last otp" (made assertive: only the
    most-recently-issued OTP verifies; earlier ones are INVALID_OTP).
    """
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(memory_adapter(), smtp)

    # Create the user + session via OTP sign-in.
    await driver.request(
        "POST", "/sign-in/email-otp", json_body={"email": "last@example.com"}
    )
    sign_in_otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST",
        "/email-otp/verify",
        json_body={"email": "last@example.com", "otp": sign_in_otp},
    )

    # Issue verification OTPs twice; only the second remains valid.
    smtp.clear()
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "last@example.com", "type": "email-verification"},
    )
    first_otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "last@example.com", "type": "email-verification"},
    )
    last_otp = smtp.sent[-1].meta["otp"]

    if first_otp != last_otp:
        r = await driver.request(
            "POST",
            "/email-otp/verify-email",
            json_body={"email": "last@example.com", "otp": first_otp},
        )
        assert r.status == 400, r.json()
        assert r.json()["code"] == "INVALID_OTP"

    r = await driver.request(
        "POST",
        "/email-otp/verify-email",
        json_body={"email": "last@example.com", "otp": last_otp},
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True


async def test_delete_otp_after_successful_sign_in() -> None:
    """Ported from race-condition "should delete OTP after successful sign-in"."""
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "race@example.com", "type": "sign-in"},
    )
    otp = smtp.sent[-1].meta["otp"]

    r = await driver.request(
        "POST", "/email-otp/verify", json_body={"email": "race@example.com", "otp": otp}
    )
    assert r.status == 200, r.json()

    rec = await adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value="email-otp:sign-in:race@example.com"),),
    )
    assert rec is None

    # Replaying the consumed OTP fails.
    r = await driver.request(
        "POST", "/email-otp/verify", json_body={"email": "race@example.com", "otp": otp}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_OTP"


async def test_delete_otp_after_successful_email_verification() -> None:
    """Ported from "should delete OTP after successful email verification"."""
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)

    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rv@example.com", "type": "sign-in"},
    )
    sign_in_otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST", "/email-otp/verify", json_body={"email": "rv@example.com", "otp": sign_in_otp}
    )

    smtp.clear()
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rv@example.com", "type": "email-verification"},
    )
    otp = smtp.sent[-1].meta["otp"]
    r = await driver.request(
        "POST", "/email-otp/verify-email", json_body={"email": "rv@example.com", "otp": otp}
    )
    assert r.status == 200, r.json()
    assert r.json()["status"] is True

    rec = await adapter.find_one(
        model="verification",
        where=(
            Where(
                field="identifier",
                value="email-otp:email-verification:rv@example.com",
            ),
        ),
    )
    assert rec is None

    r = await driver.request(
        "POST", "/email-otp/verify-email", json_body={"email": "rv@example.com", "otp": otp}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_OTP"


async def test_delete_otp_after_successful_password_reset() -> None:
    """Ported from "should delete OTP after successful password reset"."""
    from better_auth.types.adapter import Where
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)

    # Establish the user via OTP sign-in.
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rr@example.com", "type": "sign-in"},
    )
    sign_in_otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST", "/email-otp/verify", json_body={"email": "rr@example.com", "otp": sign_in_otp}
    )
    driver.cookies.clear()

    smtp.clear()
    await driver.request(
        "POST", "/email-otp/request-password-reset", json_body={"email": "rr@example.com"}
    )
    otp = next(
        e.meta["otp"] for e in smtp.sent if e.meta.get("purpose") == "forget-password"
    )
    r = await driver.request(
        "POST",
        "/email-otp/reset-password",
        json_body={"email": "rr@example.com", "otp": otp, "password": "newpass1"},
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True

    rec = await adapter.find_one(
        model="verification",
        where=(
            Where(
                field="identifier", value="email-otp:forget-password:rr@example.com"
            ),
        ),
    )
    assert rec is None

    r = await driver.request(
        "POST",
        "/email-otp/reset-password",
        json_body={"email": "rr@example.com", "otp": otp, "password": "newpass2"},
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_OTP"


async def test_reuse_but_hashed_generates_new_otp() -> None:
    """Ported from "should generate new OTP when resendStrategy is reuse but
    storeOTP is hashed" — hashed OTPs cannot be retrieved so a fresh one issues."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(
        memory_adapter(), smtp, resend_strategy="reuse", store_otp="hashed"
    )
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rh@example.com", "type": "sign-in"},
    )
    first = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rh@example.com", "type": "sign-in"},
    )
    second = smtp.sent[-1].meta["otp"]
    assert second != first


async def test_reuse_but_custom_hash_generates_new_otp() -> None:
    """Ported from "should generate new OTP when resendStrategy is reuse but
    storeOTP is custom hash"."""
    from better_auth_memory_adapter import memory_adapter

    async def _hash(otp: str) -> str:
        return f"hashed-{otp}"

    smtp = MockSMTP()
    driver, _ = _build_driver(
        memory_adapter(), smtp, resend_strategy="reuse", store_otp={"hash": _hash}
    )
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rch@example.com", "type": "sign-in"},
    )
    first = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rch@example.com", "type": "sign-in"},
    )
    second = smtp.sent[-1].meta["otp"]
    assert second != first


async def test_reuse_generates_fresh_otp_when_attempts_exhausted() -> None:
    """Ported from "should generate fresh OTP when attempts are exhausted"."""
    from better_auth_memory_adapter import memory_adapter

    smtp = MockSMTP()
    driver, _ = _build_driver(
        memory_adapter(), smtp, resend_strategy="reuse", allowed_attempts=2
    )

    # Establish the user so email-verification OTPs are actually sent.
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rex@example.com", "type": "sign-in"},
    )
    sign_in_otp = smtp.sent[-1].meta["otp"]
    await driver.request(
        "POST", "/email-otp/verify", json_body={"email": "rex@example.com", "otp": sign_in_otp}
    )

    smtp.clear()
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rex@example.com", "type": "email-verification"},
    )
    first = smtp.sent[-1].meta["otp"]

    # Exhaust attempts with wrong codes.
    for _ in range(2):
        await driver.request(
            "POST",
            "/email-otp/verify-email",
            json_body={"email": "rex@example.com", "otp": "000000"},
        )

    # A reuse request now rotates because the prior OTP is locked out.
    await driver.request(
        "POST",
        "/email-otp/send-verification-otp",
        json_body={"email": "rex@example.com", "type": "email-verification"},
    )
    second = smtp.sent[-1].meta["otp"]
    assert second != first


async def test_block_reset_password_after_too_many_attempts() -> None:
    """Ported from "should block reset password after exceeding allowed
    attempts"."""
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp, allowed_attempts=2)
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "blk@example.com", "password": "oldpassword"},
    )
    driver.cookies.clear()
    smtp.clear()
    await driver.request(
        "POST", "/forget-password/email-otp", json_body={"email": "blk@example.com"}
    )
    for _ in range(2):
        r = await driver.request(
            "POST",
            "/email-otp/reset-password",
            json_body={
                "email": "blk@example.com",
                "otp": "000000",
                "password": "x",
            },
        )
        assert r.json()["code"] == "INVALID_OTP"
    r = await driver.request(
        "POST",
        "/email-otp/reset-password",
        json_body={"email": "blk@example.com", "otp": "000000", "password": "x"},
    )
    assert r.status == 403
    assert r.json()["code"] == "TOO_MANY_ATTEMPTS"
