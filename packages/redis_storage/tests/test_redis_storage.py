"""Conformance suite for `SecondaryStorage`.

Runs the same five cases against:
- `InMemorySecondaryStorage` (no Docker, always runs)
- `RedisStorage` (started via a redis testcontainer; skipped without Docker)

Cases:
- set/get round-trip
- set with ttl actually expires
- get_and_delete is atomic (second call returns None)
- delete removes the key
- missing keys return None
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest

from kernia.types.secondary_storage import SecondaryStorage
from kernia.utils.in_memory_storage import InMemorySecondaryStorage
from kernia_redis_storage import redis_storage
from kernia_test_utils.containers import docker_available, redis_container


# --------------------------------------------------------------------------- factories


async def _make_in_memory() -> AsyncIterator[SecondaryStorage]:
    yield InMemorySecondaryStorage()


async def _make_redis() -> AsyncIterator[SecondaryStorage]:
    if not docker_available():
        pytest.skip("Docker is not available")
    with redis_container() as url:
        store = await redis_storage(url=url)
        try:
            yield store
        finally:
            await store.client.aclose()  # type: ignore[attr-defined]


STORES: list[tuple[str, Callable[[], AsyncIterator[SecondaryStorage]]]] = [
    ("in_memory", _make_in_memory),
    ("redis", _make_redis),
]


@pytest.fixture(params=STORES, ids=[name for name, _ in STORES])
async def store(request: pytest.FixtureRequest) -> AsyncIterator[SecondaryStorage]:
    _, factory = request.param
    async for s in factory():
        yield s


# --------------------------------------------------------------------------- tests


async def test_set_get_round_trip(store: SecondaryStorage) -> None:
    await store.set("k", "hello")
    assert await store.get("k") == "hello"


async def test_missing_key_returns_none(store: SecondaryStorage) -> None:
    assert await store.get("nonexistent") is None


async def test_delete_removes_key(store: SecondaryStorage) -> None:
    await store.set("k", "v")
    await store.delete("k")
    assert await store.get("k") is None


async def test_ttl_expires(store: SecondaryStorage) -> None:
    await store.set("k", "v", ttl=1)
    assert await store.get("k") == "v"
    await asyncio.sleep(1.2)
    assert await store.get("k") is None


async def test_get_and_delete_is_atomic(store: SecondaryStorage) -> None:
    await store.set("k", "v")
    first = await store.get_and_delete("k")
    assert first == "v"
    # Second call must see nothing — the row is gone.
    second = await store.get_and_delete("k")
    assert second is None


async def test_get_and_delete_missing_returns_none(store: SecondaryStorage) -> None:
    assert await store.get_and_delete("nope") is None


async def test_set_overwrites(store: SecondaryStorage) -> None:
    await store.set("k", "first")
    await store.set("k", "second")
    assert await store.get("k") == "second"


# --------------------------------------------------------------------------- direct factory


async def test_redis_storage_constructor_accepts_kwargs() -> None:
    """Smoke check that the factory wires through to redis.from_url."""
    if not docker_available():
        pytest.skip("Docker is not available")
    with redis_container() as url:
        store = await redis_storage(url=url, decode_responses=False)
        try:
            await store.set("k", "v")
            assert await store.get("k") == "v"
        finally:
            await store.client.aclose()  # type: ignore[attr-defined]


# Quieten unused-import lint when redis is unavailable (Awaitable left over).
_ = Awaitable
