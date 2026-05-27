"""Integration tests for the username plugin.

The username plugin extends the `user` table; the SQLAlchemy adapter needs the
extra columns materialized upfront so we build a local factory matrix.
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest

from kernia.auth import init
from kernia.db.schema import CORE_MODELS
from kernia.plugins import email_and_password, username
from kernia.types.adapter import ModelDef
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver, docker_available


def _extended_user_model() -> ModelDef:
    from kernia.plugins.username import _USERNAME_USER_FIELDS  # type: ignore[attr-defined]

    user = next(m for m in CORE_MODELS if m.name == "user")
    return ModelDef(name="user", fields=tuple(user.fields) + tuple(_USERNAME_USER_FIELDS))


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


def _build(adapter: Any) -> ASGIDriver:
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret-key",
            plugins=[email_and_password(), username()],
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
    from kernia_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    body = {"username": "bob", "password": "abcdefgh"}
    r1 = await driver.request("POST", "/sign-up/username", json_body=body)
    assert r1.status == 200
    r2 = await driver.request("POST", "/sign-up/username", json_body=body)
    assert r2.status == 409
    assert r2.json()["code"] == "USERNAME_IS_ALREADY_TAKEN"


async def test_invalid_username_returns_422() -> None:
    from kernia_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "has space!", "password": "abcdefgh"},
    )
    assert r.status == 422
    assert r.json()["code"] == "INVALID_USERNAME"


async def test_short_username_returns_422() -> None:
    from kernia_memory_adapter import memory_adapter

    driver = _build(memory_adapter())
    r = await driver.request(
        "POST",
        "/sign-up/username",
        json_body={"username": "ab", "password": "abcdefgh"},
    )
    assert r.status == 422
    assert r.json()["code"] == "USERNAME_TOO_SHORT"
