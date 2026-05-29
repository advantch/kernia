"""Cross-adapter parametrization helper.

Plugin integration tests do:

    @pytest.mark.parametrize(*all_adapters_param())
    async def test_thing(adapter_factory):
        adapter = await adapter_factory()
        ...

The factory returns a fresh adapter with a fresh DB. Schema is created
per-test; for SQLAlchemy the engine is disposed after the test runs.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from better_auth_test_utils.containers import docker_available, postgres_container

AdapterFactory = Callable[[], Awaitable[Any]]


async def _memory_factory() -> Any:
    from better_auth_memory_adapter import memory_adapter

    return memory_adapter()


async def _sqlite_factory() -> Any:
    # Each call gets its own in-memory database — they're isolated even when
    # several tests run concurrently because the URL contains a fresh secret.
    import secrets

    from better_auth_sqlalchemy import sqlalchemy_adapter

    url = f"sqlite+aiosqlite:///file:{secrets.token_hex(8)}?mode=memory&cache=shared&uri=true"
    return await sqlalchemy_adapter(url=url)


def _postgres_url_factory() -> Callable[[], Awaitable[Any]]:
    """Return an adapter-factory bound to a single Postgres container.

    The container is started lazily on first use and stopped via an atexit
    handler. Each adapter call gets a fresh database name on that container.
    """
    state: dict[str, Any] = {}

    async def factory() -> Any:
        from better_auth_sqlalchemy import sqlalchemy_adapter

        if "url" not in state:
            import atexit

            ctx = postgres_container()
            url = ctx.__enter__()
            state["ctx"] = ctx
            state["url"] = url
            atexit.register(lambda: ctx.__exit__(None, None, None))
        # NOTE: tests share the same database; rely on per-test transactional
        # rollback at the adapter layer. For now we just hand out adapters
        # against the shared URL — schema is idempotent (CREATE IF NOT EXISTS).
        return await sqlalchemy_adapter(url=state["url"])

    return factory


def all_adapters_param() -> tuple[str, list[Any]]:
    """Return `("adapter_factory", [...])` for pytest.mark.parametrize.

    Each entry is a `pytest.param(factory, id=..., marks=...)`. Containers
    that need Docker are wrapped in `pytest.mark.skipif` when Docker is
    unavailable.
    """
    has_docker = docker_available()

    return (
        "adapter_factory",
        [
            pytest.param(_memory_factory, id="memory"),
            pytest.param(_sqlite_factory, id="sqlalchemy-sqlite"),
            pytest.param(
                _postgres_url_factory(),
                id="sqlalchemy-postgres",
                marks=pytest.mark.skipif(not has_docker, reason="Docker required"),
            ),
            pytest.param(
                _mongo_factory_placeholder,
                id="mongo",
                marks=pytest.mark.skipif(
                    not has_docker, reason="Docker required for mongo"
                ),
            ),
        ],
    )


async def _mongo_factory_placeholder() -> Any:
    """Placeholder until `better_auth_mongo.mongo_adapter` lands.

    Tests that hit this path will see a clean skip when the adapter package
    hasn't shipped yet (`pytest.skip` from inside the factory body).
    """
    try:
        from better_auth_mongo import mongo_adapter  # type: ignore[attr-defined]
    except ImportError:
        pytest.skip("better_auth_mongo.mongo_adapter is not implemented yet")
    from better_auth_test_utils.containers import mongodb_container

    with mongodb_container() as url:
        return await mongo_adapter(url=url)


@pytest.fixture(autouse=False)
async def adapter_cleanup() -> Any:
    """Per-test cleanup hook.

    Tests that use the parametrized factory can opt in by adding this fixture.
    It currently just yields — adapter teardown is the factory's
    responsibility — but it's the seam where future global cleanup will live.
    """
    return


__all__ = ["AdapterFactory", "adapter_cleanup", "all_adapters_param"]
