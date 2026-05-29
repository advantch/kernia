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
