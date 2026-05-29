"""Integration tests for the username plugin.

The username plugin extends the `user` table; the SQLAlchemy adapter needs the
extra columns materialized upfront so we build a local factory matrix.
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from better_auth.auth import init
from better_auth.db.schema import CORE_MODELS
from better_auth.plugins import email_and_password, username
from better_auth.types.adapter import ModelDef
from better_auth.types.init_options import BetterAuthOptions
from better_auth_test_utils import ASGIDriver, docker_available


def _extended_user_model() -> ModelDef:
    from better_auth.plugins.username import _USERNAME_USER_FIELDS  # type: ignore[attr-defined]

    user = next(m for m in CORE_MODELS if m.name == "user")
    return ModelDef(name="user", fields=tuple(user.fields) + tuple(_USERNAME_USER_FIELDS))


async def _memory_factory() -> Any:
    from better_auth_memory_adapter import memory_adapter

    return memory_adapter()


async def _sqlite_factory() -> Any:
    from better_auth_sqlalchemy.adapter import SQLAlchemyAdapter, build_metadata
    from sqlalchemy.ext.asyncio import create_async_engine

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


def _adapters() -> tuple[str, list[Any]]:
    has_docker = docker_available()
    return (
        "adapter_factory",
        [
            pytest.param(_memory_factory, id="memory"),
            pytest.param(_sqlite_factory, id="sqlalchemy-sqlite"),
            pytest.param(
                _mongo_placeholder,
                id="mongo",
                marks=pytest.mark.skipif(not has_docker, reason="Docker required"),
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


def _build(adapter: Any, username_plugin: Any = None) -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="test-secret-key",
            plugins=[email_and_password(), username_plugin or username()],
        )
    )
    return ASGIDriver(app=auth.router.mount())


@pytest.mark.parametrize(*_adapters())
async def test_username_sign_up_then_case_insensitive_sign_in(
    adapter_factory: Any,
) -> None:
    adapter = await adapter_factory()
    driver = _build(adapter)

    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "Alice", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["username"] == "alice"
    assert r.json()["user"]["displayUsername"] == "Alice"
    driver.cookies.clear()

    r = await driver.request(
        "POST",
        "/sign-in/username",
        json_body={"username": "ALICE", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["username"] == "alice"


async def test_duplicate_username_409() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    body = {"username": "bob", "password": "abcdefgh"}
    r1 = await driver.request("POST", "/sign-up/username", json_body=body)
    assert r1.status == 200
    r2 = await driver.request("POST", "/sign-up/username", json_body=body)
    assert r2.status == 409
    assert r2.json()["code"] == "USERNAME_IS_ALREADY_TAKEN"


async def test_invalid_username_returns_422() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "has space!", "password": "abcdefgh"},
    )
    assert r.status == 422
    assert r.json()["code"] == "INVALID_USERNAME"


async def test_short_username_returns_422() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "ab", "password": "abcdefgh"},
    )
    assert r.status == 422
    assert r.json()["code"] == "USERNAME_TOO_SHORT"


# ----- ported from reference username.test.ts (owned-endpoint subset) -----


async def _signed_up(driver: ASGIDriver, username: str, password: str) -> None:
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": username, "password": password},
    )
    assert r.status == 200, r.json()
    driver.cookies.clear()


async def test_sign_in_redirects_to_callback_url() -> None:
    # @see https://github.com/better-auth/better-auth/issues/9469
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up(driver, "new_username", "new-password")
    r = await driver.request(
        "POST",
        "/sign-in/username",
        json_body={
            "username": "new_username",
            "password": "new-password",
            "callbackURL": "/dashboard",
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["redirect"] is True
    assert body["url"] == "/dashboard"
    assert body["token"]


async def test_sign_in_no_redirect_without_callback_url() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up(driver, "new_username", "new-password")
    r = await driver.request(
        "POST",
        "/sign-in/username",
        json_body={"username": "new_username", "password": "new-password"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["redirect"] is False
    assert body.get("url") is None


async def test_sign_in_normalizes_username() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up(driver, "Custom_User", "test-password")
    r = await driver.request(
        "POST",
        "/sign-in/username",
        json_body={"username": "Custom_User", "password": "test-password"},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["username"] == "custom_user"
    assert r.json()["user"]["displayUsername"] == "Custom_User"


async def test_custom_normalization() -> None:
    from better_auth_memory_adapter import memory_adapter

    plugin = username(
        min_username_length=4,
        username_normalization=lambda u: u.replace("0", "o")
        .replace("4", "a")
        .lower(),
    )
    driver = _build(memory_adapter(), plugin)
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "H4XX0R", "password": "new-password"},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["username"] == "haxxor"
    # Duplicate (already-normalized form) collides.
    driver.cookies.clear()
    r2 = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "haxxor", "password": "new-password"},
    )
    assert r2.status == 409
    assert r2.json()["code"] == "USERNAME_IS_ALREADY_TAKEN"


async def test_display_username_normalization() -> None:
    from better_auth_memory_adapter import memory_adapter

    plugin = username(display_username_normalization=lambda d: d.lower())
    driver = _build(memory_adapter(), plugin)
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={
            "username": "test_username",
            "password": "new-password",
            "displayUsername": "Test Username",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["username"] == "test_username"
    assert r.json()["user"]["displayUsername"] == "test username"


async def test_display_username_validator_rejects() -> None:
    import re

    from better_auth_memory_adapter import memory_adapter

    plugin = username(
        display_username_validator=lambda d: bool(re.match(r"^[a-zA-Z0-9_-]+$", d))
    )
    driver = _build(memory_adapter(), plugin)
    ok = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={
            "username": "valid_user",
            "password": "test-password",
            "displayUsername": "Valid_Display-123",
        },
    )
    assert ok.status == 200, ok.json()
    driver.cookies.clear()
    bad = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={
            "username": "another_user",
            "password": "test-password",
            "displayUsername": "Invalid Display!",
        },
    )
    assert bad.status == 400
    assert bad.json()["code"] == "INVALID_DISPLAY_USERNAME"


async def test_post_normalization_sets_display_to_original() -> None:
    from better_auth_memory_adapter import memory_adapter

    plugin = username(
        username_validation_order="post-normalization",
        display_username_validation_order="post-normalization",
        username_normalization=lambda u: "_".join(u.split(" ")).lower(),
    )
    driver = _build(memory_adapter(), plugin)
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "Test Username", "password": "test-password"},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["username"] == "test_username"
    assert r.json()["user"]["displayUsername"] == "Test Username"


async def test_is_username_available_true_false_and_normalized() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up(driver, "priority_user", "test-password")

    taken = await driver.request(
        "POST", "/is-username-available", json_body={"username": "priority_user"}
    )
    assert taken.json()["available"] is False

    taken_case = await driver.request(
        "POST", "/is-username-available", json_body={"username": "PRIORITY_USER"}
    )
    assert taken_case.json()["available"] is False

    free = await driver.request(
        "POST", "/is-username-available", json_body={"username": "new_username_2.2"}
    )
    assert free.json()["available"] is True


async def test_is_username_available_validation_errors() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    invalid = await driver.request(
        "POST", "/is-username-available", json_body={"username": "invalid username!"}
    )
    assert invalid.status == 422
    assert invalid.json()["code"] == "INVALID_USERNAME"

    short = await driver.request(
        "POST", "/is-username-available", json_body={"username": "ab"}
    )
    assert short.status == 422
    assert short.json()["code"] == "USERNAME_TOO_SHORT"

    long = await driver.request(
        "POST", "/is-username-available", json_body={"username": "a" * 31}
    )
    assert long.status == 422
    assert long.json()["code"] == "USERNAME_TOO_LONG"


async def test_is_username_available_custom_validator() -> None:
    from better_auth_memory_adapter import memory_adapter

    plugin = username(username_validator=lambda u: u.startswith("user_"))
    driver = _build(memory_adapter(), plugin)
    ok = await driver.request(
        "POST", "/is-username-available", json_body={"username": "user_valid123"}
    )
    assert ok.json()["available"] is True
    bad = await driver.request(
        "POST", "/is-username-available", json_body={"username": "invalid_user"}
    )
    assert bad.status == 422
    assert bad.json()["code"] == "INVALID_USERNAME"


async def test_custom_validator_rejects_sign_in() -> None:
    from better_auth_memory_adapter import memory_adapter

    plugin = username(username_validator=lambda u: u.startswith("user_"))
    driver = _build(memory_adapter(), plugin)
    sign_in = await driver.request(
        "POST",
        "/sign-in/username",
        json_body={"username": "invalid_user", "password": "password1234"},
    )
    assert sign_in.status == 422
    assert sign_in.json()["code"] == "INVALID_USERNAME"


# ----- update-user flow (ported from username.test.ts, issue #8689) --------


async def _signed_up_keep_session(
    driver: ASGIDriver, username: str, password: str, *, email: str | None = None
) -> None:
    body: dict[str, Any] = {"username": username, "password": password}
    if email is not None:
        body["email"] = email
    r = await driver.request("POST", "/sign-up/username", json_body=body)
    assert r.status == 200, r.json()


async def _session_user(driver: ASGIDriver) -> dict[str, Any]:
    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    return r.json()["user"]


async def test_update_username() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up_keep_session(driver, "new_username", "new-password")
    r = await driver.request(
        "POST", "/update-user", json_body={"username": "new_username_2.1"}
    )
    assert r.status == 200, r.json()
    user = await _session_user(driver)
    assert user["username"] == "new_username_2.1"


async def test_update_user_duplicate_different_user_400() -> None:
    # @see https://github.com/better-auth/better-auth/issues/8689
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up_keep_session(driver, "duplicate_user", "new_password1")
    driver.cookies.clear()
    await _signed_up_keep_session(driver, "second_user", "new_password1")
    r = await driver.request(
        "POST", "/update-user", json_body={"username": "duplicate_user"}
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "USERNAME_IS_ALREADY_TAKEN"


async def test_update_user_duplicate_different_casing_400() -> None:
    # @see https://github.com/better-auth/better-auth/issues/8689
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up_keep_session(driver, "casetestuser", "new_password1")
    driver.cookies.clear()
    await _signed_up_keep_session(driver, "another_user", "new_password1")
    r = await driver.request(
        "POST", "/update-user", json_body={"username": "CaseTestUser"}
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "USERNAME_IS_ALREADY_TAKEN"


async def test_update_user_duplicate_same_user_succeeds() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up_keep_session(driver, "new_username_2.1", "new-password")
    # Re-applying a differently-cased form of the SAME user's username is allowed.
    r = await driver.request(
        "POST", "/update-user", json_body={"username": "New_username_2.1"}
    )
    assert r.status == 200, r.json()
    user = await _session_user(driver)
    assert user["username"] == "new_username_2.1"


async def test_update_user_preserves_both_username_and_display() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    await _signed_up_keep_session(driver, "start_user", "new-password")
    r = await driver.request(
        "POST",
        "/update-user",
        json_body={
            "username": "priority_user",
            "displayUsername": "Priority Display Name",
        },
    )
    assert r.status == 200, r.json()
    user = await _session_user(driver)
    assert user["username"] == "priority_user"
    assert user["displayUsername"] == "Priority Display Name"


async def test_update_display_username_valid() -> None:
    import re

    from better_auth_memory_adapter import memory_adapter

    plugin = username(
        display_username_validator=lambda d: bool(re.match(r"^[a-zA-Z0-9_-]+$", d))
    )
    driver = _build(memory_adapter(), plugin)
    await _signed_up_keep_session(driver, "initial_name", "test-password")
    r = await driver.request(
        "POST", "/update-user", json_body={"displayUsername": "Updated_Name-123"}
    )
    assert r.status == 200, r.json()
    user = await _session_user(driver)
    assert user["displayUsername"] == "Updated_Name-123"
    # The username itself is untouched by a display-only update.
    assert user["username"] == "initial_name"


async def test_update_display_username_invalid_rejected() -> None:
    import re

    from better_auth_memory_adapter import memory_adapter

    plugin = username(
        display_username_validator=lambda d: bool(re.match(r"^[a-zA-Z0-9_-]+$", d))
    )
    driver = _build(memory_adapter(), plugin)
    await _signed_up_keep_session(driver, "valid_name", "test-password")
    r = await driver.request(
        "POST", "/update-user", json_body={"displayUsername": "Invalid Display!"}
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "INVALID_DISPLAY_USERNAME"


def _build_verify(adapter: Any) -> ASGIDriver:
    from better_auth.types.init_options import EmailPasswordOptions

    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="test-secret-key",
            email_and_password=EmailPasswordOptions(
                enabled=True, require_email_verification=True
            ),
            plugins=[email_and_password(), username()],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_email_verification_no_info_leak() -> None:
    from better_auth_memory_adapter import memory_adapter

    driver = _build_verify(memory_adapter())
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={
            "username": "unverified_user",
            "password": "correct-password",
            "email": "unverified-user@example.com",
        },
    )
    assert r.status == 200, r.json()
    driver.cookies.clear()

    # Wrong password -> generic 401 even though email unverified.
    wrong = await driver.request(
        "POST",
        "/sign-in/username",
        json_body={"username": "unverified_user", "password": "wrong-password"},
    )
    assert wrong.status == 401
    assert wrong.json()["code"] == "INVALID_USERNAME_OR_PASSWORD"

    # Correct password -> 403 EMAIL_NOT_VERIFIED.
    correct = await driver.request(
        "POST",
        "/sign-in/username",
        json_body={"username": "unverified_user", "password": "correct-password"},
    )
    assert correct.status == 403
    assert correct.json()["code"] == "EMAIL_NOT_VERIFIED"
