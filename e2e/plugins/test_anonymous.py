"""Integration tests for the anonymous plugin.

Key invariant: after anon sign-in followed by a real email sign-up using the
same browser, exactly ONE user row remains.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from typing import Any

import pytest
from kernia.auth import init
from kernia.db.schema import CORE_MODELS
from kernia.plugins import anonymous, email_and_password
from kernia.types.adapter import ModelDef, Where
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver, docker_available


def _extended_user_model() -> ModelDef:
    from kernia.plugins.anonymous import _ANONYMOUS_USER_FIELDS  # type: ignore[attr-defined]

    user = next(m for m in CORE_MODELS if m.name == "user")
    return ModelDef(name="user", fields=tuple(user.fields) + tuple(_ANONYMOUS_USER_FIELDS))


async def _memory_factory() -> AsyncIterator[Any]:
    from kernia_memory_adapter import memory_adapter

    yield memory_adapter()


async def _sqlite_factory() -> AsyncIterator[Any]:
    from kernia_sqlalchemy.adapter import SQLAlchemyAdapter, build_metadata
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
    yield adapter


async def _mongo_factory() -> AsyncIterator[Any]:
    try:
        from kernia_mongo import mongo_adapter  # type: ignore[attr-defined]
    except ImportError:
        pytest.skip("kernia_mongo.mongo_adapter is not implemented yet")
    from kernia_test_utils.containers import mongodb_container

    # Yield inside the `with` so the container stays alive for the test body.
    with mongodb_container() as url:
        # Each test gets its own random db so parametrize doesn't leak state.
        yield await mongo_adapter(
            url=url,
            db_name=f"kernia_test_{secrets.token_hex(4)}",
        )


def _adapter_params() -> list[Any]:
    has_docker = docker_available()
    return [
        pytest.param(_memory_factory, id="memory"),
        pytest.param(_sqlite_factory, id="sqlalchemy-sqlite"),
        pytest.param(
            _mongo_factory,
            id="mongo",
            marks=pytest.mark.skipif(not has_docker, reason="Docker required"),
        ),
    ]


@pytest.fixture(params=_adapter_params())
async def adapter(request: pytest.FixtureRequest) -> AsyncIterator[Any]:
    """Parametrized adapter fixture; backing containers stay alive per test."""
    async for a in request.param():
        yield a


def _build(adapter: Any, on_link: Any = None, **anon_opts: Any) -> tuple[ASGIDriver, Any]:
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret-key",
            plugins=[email_and_password(), anonymous(on_link=on_link, **anon_opts)],
        )
    )
    return ASGIDriver(app=auth.router.mount()), adapter


async def test_anonymous_sign_in_creates_user_and_session(adapter: Any) -> None:
    driver, _ = _build(adapter)
    r = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["isAnonymous"] is True
    assert "session" in body

    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["isAnonymous"] is True


async def test_anonymous_to_email_signup_merges_users() -> None:
    """Sign-in-anon + sign-up-email leaves exactly ONE user row."""
    from kernia_memory_adapter import memory_adapter

    seen: dict[str, Any] = {}

    async def on_link(anon_user: dict, new_user: dict, _ctx: Any) -> None:
        seen["anon_id"] = anon_user["id"]
        seen["new_id"] = new_user["id"]

    adapter = memory_adapter()
    driver, _ = _build(adapter, on_link=on_link)

    r1 = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r1.status == 200
    anon_user_id = r1.json()["user"]["id"]

    r2 = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "real@example.com", "password": "correcthorse"},
    )
    assert r2.status == 200, r2.json()
    new_user_id = r2.json()["user"]["id"]

    assert anon_user_id != new_user_id
    assert seen.get("anon_id") == anon_user_id
    assert seen.get("new_id") == new_user_id

    remaining = await adapter.find_many(model="user", where=())
    assert len(remaining) == 1
    assert remaining[0]["id"] == new_user_id

    gone = await adapter.find_one(model="user", where=(Where(field="id", value=anon_user_id),))
    assert gone is None


async def test_double_anonymous_sign_in_rejected() -> None:
    from kernia_memory_adapter import memory_adapter

    driver, _ = _build(memory_adapter())
    r1 = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r1.status == 200
    r2 = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r2.status == 400
    assert r2.json()["code"] == "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"


# ----- ported from reference anonymous tests -----


async def test_delete_anonymous_user() -> None:
    from kernia_memory_adapter import memory_adapter

    adapter = memory_adapter()
    driver, _ = _build(adapter)
    r1 = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r1.status == 200
    anon_id = r1.json()["user"]["id"]

    r = await driver.request("POST", "/delete-anonymous-user", json_body={})
    assert r.status == 200, r.json()
    assert r.json()["success"] is True

    gone = await adapter.find_one(model="user", where=(Where(field="id", value=anon_id),))
    assert gone is None


async def test_delete_anonymous_user_disabled() -> None:
    from kernia_memory_adapter import memory_adapter

    driver, _ = _build(memory_adapter(), disable_delete_anonymous_user=True)
    await driver.request("POST", "/sign-in/anonymous", json_body={})
    r = await driver.request("POST", "/delete-anonymous-user", json_body={})
    assert r.status == 400
    assert r.json()["code"] == "DELETE_ANONYMOUS_USER_DISABLED"


async def test_delete_rejects_non_anonymous_user() -> None:
    from kernia_memory_adapter import memory_adapter

    driver, _ = _build(memory_adapter())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "real@example.com", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()
    r = await driver.request("POST", "/delete-anonymous-user", json_body={})
    assert r.status == 403
    assert r.json()["code"] == "USER_IS_NOT_ANONYMOUS"


async def test_custom_email_domain_name() -> None:
    from kernia_memory_adapter import memory_adapter

    driver, _ = _build(memory_adapter(), email_domain_name="my-app.com")
    r = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r.status == 200, r.json()
    assert r.json()["user"]["email"].endswith("@my-app.com")


async def test_generate_random_email_invalid_format() -> None:
    from kernia_memory_adapter import memory_adapter

    driver, _ = _build(memory_adapter(), generate_random_email=lambda: "not-an-email")
    r = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r.status == 400
    assert r.json()["code"] == "INVALID_EMAIL_FORMAT"


async def test_generate_name() -> None:
    from kernia_memory_adapter import memory_adapter

    driver, _ = _build(memory_adapter(), generate_name=lambda _ctx: "Custom Name")
    r = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r.status == 200, r.json()
    assert r.json()["user"]["name"] == "Custom Name"
