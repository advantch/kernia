"""Integration tests for the anonymous plugin.

Key invariant: after anon sign-in followed by a real email sign-up using the
same browser, exactly ONE user row remains.
"""

from __future__ import annotations

import secrets
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


async def _memory_factory() -> Any:
    from kernia_memory_adapter import memory_adapter

    return memory_adapter()


async def _sqlite_factory() -> Any:
    from sqlalchemy.ext.asyncio import create_async_engine

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
        from kernia_mongo import mongo_adapter  # type: ignore[attr-defined]
    except ImportError:
        pytest.skip("kernia_mongo.mongo_adapter is not implemented yet")
    from kernia_test_utils.containers import mongodb_container

    with mongodb_container() as url:
        return await mongo_adapter(url=url)


def _build(adapter: Any, on_link: Any = None) -> tuple[ASGIDriver, Any]:
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret-key",
            plugins=[email_and_password(), anonymous(on_link=on_link)],
        )
    )
    return ASGIDriver(app=auth.router.mount()), adapter


@pytest.mark.parametrize(*_adapters())
async def test_anonymous_sign_in_creates_user_and_session(
    adapter_factory: Any,
) -> None:
    adapter = await adapter_factory()
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

    gone = await adapter.find_one(
        model="user", where=(Where(field="id", value=anon_user_id),)
    )
    assert gone is None


async def test_double_anonymous_sign_in_rejected() -> None:
    from kernia_memory_adapter import memory_adapter

    driver, _ = _build(memory_adapter())
    r1 = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r1.status == 200
    r2 = await driver.request("POST", "/sign-in/anonymous", json_body={})
    assert r2.status == 400
    assert r2.json()["code"] == "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
