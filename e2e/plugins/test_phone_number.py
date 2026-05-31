"""Phone-number integration tests.

The phone-number plugin extends the `user` table with `phoneNumber` /
`phoneNumberVerified` columns. The SQLAlchemy adapter materializes columns up
front from `ModelDef`, so we hand it the merged user model via `extra_models`
plus a tweaked CORE_MODELS list. The memory adapter accepts arbitrary fields
freely, so it needs no extra wiring.

We define a local adapter-factory matrix here so each adapter can apply the
plugin's schema extension. Mongo is skipped automatically when Docker isn't
available; the mongo factory is a placeholder until the adapter lands.
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest

from kernia.auth import init
from kernia.db.schema import CORE_MODELS
from kernia.plugins.phone_number import phone_number, phone_number_schema
from kernia.types.adapter import ModelDef
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import (
    ASGIDriver,
    MockSMS,
    docker_available,
)

# ---------- adapter factories with phone-number schema extension --------------


def _extended_user_model() -> ModelDef:
    """Re-build the user model with the plugin's extra fields appended."""
    user = next(m for m in CORE_MODELS if m.name == "user")
    extra = phone_number_schema().extend["user"]
    return ModelDef(name="user", fields=tuple(user.fields) + tuple(extra))


async def _memory_factory() -> Any:
    from kernia_memory_adapter import memory_adapter

    return memory_adapter()


async def _sqlite_factory() -> Any:
    """SQLAlchemy on shared-cache in-memory SQLite, with the extended user table."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from kernia.types.adapter import ModelDef
    from kernia_sqlalchemy.adapter import SQLAlchemyAdapter, build_metadata

    url = f"sqlite+aiosqlite:///file:{secrets.token_hex(8)}?mode=memory&cache=shared&uri=true"
    engine = create_async_engine(url, future=True)
    models: tuple[ModelDef, ...] = tuple(
        m if m.name != "user" else _extended_user_model() for m in CORE_MODELS
    )
    metadata = build_metadata(models)
    adapter = SQLAlchemyAdapter(engine=engine, metadata=metadata, models=models)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    return adapter


def _phone_number_adapters() -> tuple[str, list[Any]]:
    has_docker = docker_available()
    return (
        "adapter_factory",
        [
            pytest.param(_memory_factory, id="memory"),
            pytest.param(_sqlite_factory, id="sqlalchemy-sqlite"),
            pytest.param(
                _mongo_placeholder,
                id="mongo",
                marks=pytest.mark.skipif(
                    not has_docker, reason="Docker required for mongo"
                ),
            ),
        ],
    )


async def _mongo_placeholder() -> Any:
    try:
        from kernia_mongo import mongo_adapter  # type: ignore[attr-defined]
    except ImportError:
        pytest.skip("kernia_mongo.mongo_adapter is not implemented yet")
    from kernia_test_utils.containers import mongodb_container

    with mongodb_container() as url:
        return await mongo_adapter(url=url)


# ---------- driver helper ------------------------------------------------------


def _build_driver(adapter: Any, sms: MockSMS, *, disable_sign_up: bool = False):
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            plugins=[phone_number()],
            advanced={
                "phone-number": {
                    "send_sms": sms.send,
                    "expires_in": 60,
                    "disable_sign_up": disable_sign_up,
                },
                "disable_csrf_check": True,
            },
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


def _build_driver_opts(adapter: Any, sms: MockSMS, **opts: Any):
    phone_opts: dict[str, Any] = {"send_sms": sms.send, "expires_in": 60, **opts}
    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="test-secret",
            plugins=[phone_number()],
            advanced={"phone-number": phone_opts, "disable_csrf_check": True},
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


# ---------- tests --------------------------------------------------------------


@pytest.mark.parametrize(*_phone_number_adapters())
async def test_phone_number_signup_via_otp(adapter_factory) -> None:
    adapter = await adapter_factory()
    sms = MockSMS()
    driver, _ = _build_driver(adapter, sms)

    r = await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": "+15551112222"}
    )
    assert r.status == 200, r.json()
    otp = sms.find_otp("+15551112222")

    r = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15551112222", "otp": otp},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["isNewUser"] is True
    assert body["user"]["phoneNumber"] == "+15551112222"
    assert body["user"]["phoneNumberVerified"] is True
    assert "better-auth.session_token" in driver.cookies


@pytest.mark.parametrize(*_phone_number_adapters())
async def test_phone_number_wrong_otp(adapter_factory) -> None:
    adapter = await adapter_factory()
    sms = MockSMS()
    driver, _ = _build_driver(adapter, sms)
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": "+15551113333"}
    )
    r = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15551113333", "otp": "000000"},
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_OTP"


@pytest.mark.parametrize(*_phone_number_adapters())
async def test_phone_number_sign_in_with_password(adapter_factory) -> None:
    """End-to-end: verify phone, set a password via reset, then sign in by phone."""
    adapter = await adapter_factory()
    sms = MockSMS()
    driver, _ = _build_driver(adapter, sms)

    # Create + verify the user.
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": "+15551114444"}
    )
    otp = sms.find_otp("+15551114444")
    await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15551114444", "otp": otp},
    )
    driver.cookies.clear()
    sms.clear()

    # Set a password via the reset flow.
    await driver.request(
        "POST",
        "/phone-number/request-password-reset",
        json_body={"phone_number": "+15551114444"},
    )
    reset_otp = sms.find_otp("+15551114444")
    r = await driver.request(
        "POST",
        "/phone-number/reset-password",
        json_body={
            "phone_number": "+15551114444",
            "otp": reset_otp,
            "new_password": "phonesecret",
        },
    )
    assert r.status == 200, r.json()

    # Now sign in by phone.
    r = await driver.request(
        "POST",
        "/sign-in/phone-number",
        json_body={"phone_number": "+15551114444", "password": "phonesecret"},
    )
    assert r.status == 200, r.json()
    assert "better-auth.session_token" in driver.cookies


@pytest.mark.parametrize(*_phone_number_adapters())
async def test_phone_number_sign_in_unknown(adapter_factory) -> None:
    adapter = await adapter_factory()
    driver, _ = _build_driver(adapter, MockSMS())
    r = await driver.request(
        "POST",
        "/sign-in/phone-number",
        json_body={"phone_number": "+15550000000", "password": "whatever"},
    )
    assert r.status == 401
    assert r.json()["code"] == "INVALID_PHONE_NUMBER_OR_PASSWORD"


@pytest.mark.parametrize(*_phone_number_adapters())
async def test_phone_number_signup_disabled(adapter_factory) -> None:
    adapter = await adapter_factory()
    sms = MockSMS()
    driver, _ = _build_driver(adapter, sms, disable_sign_up=True)
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": "+15551115555"}
    )
    otp = sms.find_otp("+15551115555")
    r = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15551115555", "otp": otp},
    )
    assert r.status == 403
    assert r.json()["code"] == "PHONE_NUMBER_SIGN_UP_DISABLED"


# ----- ported from reference phone-number.test.ts (owned-endpoint subset) -----


async def test_verify_otp_not_found() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver, _ = _build_driver(memory_adapter(), MockSMS())
    # No send-otp first, so the verification row doesn't exist.
    r = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15559990000", "otp": "123456"},
    )
    assert r.status == 400
    assert r.json()["code"] == "OTP_NOT_FOUND"


async def test_verify_accepts_code_alias() -> None:
    from better_auth_memory_adapter import memory_adapter

    sms = MockSMS()
    driver, _ = _build_driver(memory_adapter(), sms)
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": "+15559991111"}
    )
    otp = sms.find_otp("+15559991111")
    r = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15559991111", "code": otp},
    )
    assert r.status == 200, r.json()
    assert r.json()["status"] is True


async def test_verify_disable_session() -> None:
    from better_auth_memory_adapter import memory_adapter

    sms = MockSMS()
    driver, _ = _build_driver(memory_adapter(), sms)
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": "+15559992222"}
    )
    otp = sms.find_otp("+15559992222")
    r = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={
            "phone_number": "+15559992222",
            "otp": otp,
            "disable_session": True,
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["status"] is True
    assert body["token"] is None
    assert "better-auth.session_token" not in driver.cookies


async def test_too_many_attempts() -> None:
    from better_auth_memory_adapter import memory_adapter

    sms = MockSMS()
    driver, _ = _build_driver_opts(memory_adapter(), sms, allowed_attempts=2)
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": "+15559993333"}
    )
    # Two wrong attempts increment the counter; the third trips TOO_MANY_ATTEMPTS.
    for _ in range(2):
        bad = await driver.request(
            "POST",
            "/phone-number/verify",
            json_body={"phone_number": "+15559993333", "otp": "000000"},
        )
        assert bad.status == 400
        assert bad.json()["code"] == "INVALID_OTP"
    third = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15559993333", "otp": "000000"},
    )
    assert third.status == 403
    assert third.json()["code"] == "TOO_MANY_ATTEMPTS"


async def test_sign_in_requires_verification() -> None:
    import time

    from better_auth.crypto import hash_password
    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    sms = MockSMS()
    driver, _ = _build_driver_opts(adapter, sms, require_verification=True)

    # Seed an UNVERIFIED phone user directly with a credential password.
    now = int(time.time())
    user = await adapter.create(
        model="user",
        data={
            "email": "unverified@phone.local",
            "emailVerified": False,
            "phoneNumber": "+15559994444",
            "phoneNumberVerified": False,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    await adapter.create(
        model="account",
        data={
            "userId": user["id"],
            "accountId": user["id"],
            "providerId": "credential",
            "password": hash_password("phonesecret"),
            "createdAt": now,
            "updatedAt": now,
        },
    )

    # Sign-in is gated: 401 PHONE_NUMBER_NOT_VERIFIED and an OTP is dispatched.
    r = await driver.request(
        "POST",
        "/sign-in/phone-number",
        json_body={"phone_number": "+15559994444", "password": "phonesecret"},
    )
    assert r.status == 401
    assert r.json()["code"] == "PHONE_NUMBER_NOT_VERIFIED"
    assert sms.find_otp("+15559994444") is not None


async def test_verify_expired_code() -> None:
    """Upstream: 'should not verify if code expired'.

    A verification row whose ``expiresAt`` is in the past is rejected with
    ``OTP_EXPIRED`` and deleted, mirroring upstream's expiry check.
    """
    import time

    from better_auth_memory_adapter import memory_adapter

    adapter = memory_adapter()
    driver, _ = _build_driver(adapter, MockSMS())
    # Seed an already-expired OTP row directly (identifier + "<otp>:<attempts>").
    now = int(time.time())
    await adapter.create(
        model="verification",
        data={
            "identifier": "phone-number:sign-in:+15559995555",
            "value": "123456:0",
            "expiresAt": now - 10,
            "createdAt": now - 70,
            "updatedAt": now - 70,
        },
    )
    r = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": "+15559995555", "otp": "123456"},
    )
    assert r.status == 400
    assert r.json()["code"] == "OTP_EXPIRED"


async def test_verify_last_code_invalidates_previous() -> None:
    """Upstream: 'should verify the last code'.

    Requesting a second OTP supersedes the first: the stale code no longer
    verifies, but the freshly issued one does.
    """
    from better_auth_memory_adapter import memory_adapter

    sms = MockSMS()
    driver, _ = _build_driver(memory_adapter(), sms)
    phone = "+15559996666"

    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": phone}
    )
    first_otp = sms.find_otp(phone)
    sms.clear()
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": phone}
    )
    second_otp = sms.find_otp(phone)
    assert second_otp != first_otp

    # The superseded code is rejected.
    stale = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": phone, "otp": first_otp},
    )
    assert stale.status == 400
    assert stale.json()["code"] == "INVALID_OTP"

    # The latest code verifies.
    ok = await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": phone, "otp": second_otp},
    )
    assert ok.status == 200, ok.json()
    assert ok.json()["status"] is True


async def test_request_password_reset_unknown_user_succeeds() -> None:
    """Upstream: request-password-reset must not leak which numbers exist.

    An unknown phone returns success with no SMS dispatched.
    """
    from better_auth_memory_adapter import memory_adapter

    sms = MockSMS()
    driver, _ = _build_driver(memory_adapter(), sms)
    r = await driver.request(
        "POST",
        "/phone-number/request-password-reset",
        json_body={"phone_number": "+15550009999"},
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True
    assert not [m for m in sms.sent if m.to == "+15550009999"]


async def test_reset_password_creates_credential_account() -> None:
    """Upstream: 'should reset password and create credential account'.

    A phone-only user (verified via OTP, no password) gains a credential
    account through the reset flow, after which phone+password sign-in works.
    """
    from better_auth_memory_adapter import memory_adapter

    sms = MockSMS()
    driver, _ = _build_driver(memory_adapter(), sms)
    phone = "+15559997777"

    # Create + verify a phone-only user (no credential account yet).
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": phone}
    )
    await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": phone, "otp": sms.find_otp(phone)},
    )
    driver.cookies.clear()
    sms.clear()

    # Reset password -> creates the credential account.
    await driver.request(
        "POST",
        "/phone-number/request-password-reset",
        json_body={"phone_number": phone},
    )
    r = await driver.request(
        "POST",
        "/phone-number/reset-password",
        json_body={
            "phone_number": phone,
            "otp": sms.find_otp(phone),
            "new_password": "freshsecret",
        },
    )
    assert r.status == 200, r.json()

    # The new credential lets the user sign in by phone.
    signin = await driver.request(
        "POST",
        "/sign-in/phone-number",
        json_body={"phone_number": phone, "password": "freshsecret"},
    )
    assert signin.status == 200, signin.json()
    assert "better-auth.session_token" in driver.cookies


async def test_reset_password_too_many_attempts() -> None:
    """Upstream: 'should block reset password after exceeding allowed attempts'.

    Wrong reset codes increment the attempt counter; exceeding the limit trips
    ``TOO_MANY_ATTEMPTS`` on the reset-password endpoint too.
    """
    from better_auth_memory_adapter import memory_adapter

    sms = MockSMS()
    driver, _ = _build_driver_opts(memory_adapter(), sms, allowed_attempts=2)
    phone = "+15559998888"

    # Create + verify a user so request-password-reset issues a code.
    await driver.request(
        "POST", "/phone-number/send-otp", json_body={"phone_number": phone}
    )
    await driver.request(
        "POST",
        "/phone-number/verify",
        json_body={"phone_number": phone, "otp": sms.find_otp(phone)},
    )
    sms.clear()
    await driver.request(
        "POST",
        "/phone-number/request-password-reset",
        json_body={"phone_number": phone},
    )

    for _ in range(2):
        bad = await driver.request(
            "POST",
            "/phone-number/reset-password",
            json_body={
                "phone_number": phone,
                "otp": "000000",
                "new_password": "whatever1",
            },
        )
        assert bad.status == 400
        assert bad.json()["code"] == "INVALID_OTP"

    blocked = await driver.request(
        "POST",
        "/phone-number/reset-password",
        json_body={
            "phone_number": phone,
            "otp": "000000",
            "new_password": "whatever1",
        },
    )
    assert blocked.status == 403
    assert blocked.json()["code"] == "TOO_MANY_ATTEMPTS"
