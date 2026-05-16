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

from better_auth.auth import init
from better_auth.db.schema import CORE_MODELS
from better_auth.plugins.phone_number import phone_number, phone_number_schema
from better_auth.types.adapter import ModelDef
from better_auth.types.init_options import BetterAuthOptions
from better_auth_test_utils import (
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
    from better_auth_memory_adapter import memory_adapter

    return memory_adapter()


async def _sqlite_factory() -> Any:
    """SQLAlchemy on shared-cache in-memory SQLite, with the extended user table."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from better_auth.types.adapter import ModelDef
    from better_auth_sqlalchemy.adapter import SQLAlchemyAdapter, build_metadata

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
        from better_auth_mongo import mongo_adapter  # type: ignore[attr-defined]
    except ImportError:
        pytest.skip("better_auth_mongo.mongo_adapter is not implemented yet")
    from better_auth_test_utils.containers import mongodb_container

    with mongodb_container() as url:
        return await mongo_adapter(url=url)


# ---------- driver helper ------------------------------------------------------


def _build_driver(adapter: Any, sms: MockSMS, *, disable_sign_up: bool = False):
    auth = init(
        BetterAuthOptions(
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
