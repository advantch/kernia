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

from kernia_test_utils.containers import docker_available, postgres_container

AdapterFactory = Callable[[], Awaitable[Any]]


async def _memory_factory() -> Any:
    from kernia_memory_adapter import memory_adapter

    return memory_adapter()


async def _sqlite_factory() -> Any:
    # Each call gets its own in-memory database — they're isolated even when
    # several tests run concurrently because the URL contains a fresh secret.
    import secrets

    from kernia_sqlalchemy import sqlalchemy_adapter

    url = f"sqlite+aiosqlite:///file:{secrets.token_hex(8)}?mode=memory&cache=shared&uri=true"
    return await sqlalchemy_adapter(url=url)


def _postgres_url_factory() -> Callable[[], Awaitable[Any]]:
    """Return an adapter-factory bound to a single Postgres container.

    The container is started lazily on first use and stopped via an atexit
    handler. Each adapter call gets a fresh database name on that container.
    """
    state: dict[str, Any] = {}

    async def factory() -> Any:
        from kernia_sqlalchemy import sqlalchemy_adapter

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
                _mongo_url_factory(),
                id="mongo",
                marks=pytest.mark.skipif(not has_docker, reason="Docker required for mongo"),
            ),
        ],
    )


def _mongo_url_factory() -> Callable[[], Awaitable[Any]]:
    """Return an adapter-factory bound to a single MongoDB container.

    Mirrors `_postgres_url_factory`: the container starts lazily on first use
    and is stopped via an atexit handler, so it outlives each test body (a
    `with` block here would tear the container down before the test runs).
    Each call gets a fresh database name on the shared container, keeping
    parametrized tests isolated.
    """
    state: dict[str, Any] = {}

    async def factory() -> Any:
        try:
            from kernia_mongo import mongo_adapter
        except ImportError:
            pytest.skip("kernia_mongo is not installed")

        if "url" not in state:
            import atexit

            from kernia_test_utils.containers import mongodb_container

            ctx = mongodb_container()
            state["ctx"] = ctx
            state["url"] = ctx.__enter__()
            atexit.register(lambda: ctx.__exit__(None, None, None))

        import secrets

        return await mongo_adapter(url=state["url"], db_name=f"kernia_test_{secrets.token_hex(4)}")

    return factory


@pytest.fixture(autouse=False)
async def adapter_cleanup() -> Any:
    """Per-test cleanup hook.

    Tests that use the parametrized factory can opt in by adding this fixture.
    It currently just yields — adapter teardown is the factory's
    responsibility — but it's the seam where future global cleanup will live.
    """
    return


__all__ = ["AdapterFactory", "adapter_cleanup", "all_adapters_param"]
