"""Redis-backed `SecondaryStorage` implementation.

Uses `redis.asyncio.Redis`. `get_and_delete` is implemented via a Lua script so
the read+delete is atomic on the server (a pipeline isn't atomic if the connection
is shared with other coroutines).

Mirrors `reference/packages/better-auth/src/utils/secondary-storage.ts` plus the
intent of `reference/packages/redis-storage/` in the JS tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kernia.types.secondary_storage import SecondaryStorage


# Server-side atomic GETDEL fallback (Redis 6.2+ has GETDEL natively; we keep
# Lua for broader compatibility and to make the contract explicit).
_GET_AND_DELETE_LUA = (
    "local v = redis.call('GET', KEYS[1]); "
    "if v then redis.call('DEL', KEYS[1]) end; "
    "return v"
)


@dataclass
class RedisStorage:
    """`SecondaryStorage` backed by a `redis.asyncio.Redis` client."""

    client: Any  # redis.asyncio.Redis — typed as Any to keep redis an optional import

    async def get(self, key: str) -> str | None:
        raw = await self.client.get(key)
        return _decode(raw)

    async def set(self, key: str, value: str, *, ttl: int | None = None) -> None:
        if ttl is not None:
            await self.client.set(key, value, ex=ttl)
        else:
            await self.client.set(key, value)

    async def delete(self, key: str) -> None:
        await self.client.delete(key)

    async def get_and_delete(self, key: str) -> str | None:
        raw = await self.client.eval(_GET_AND_DELETE_LUA, 1, key)
        return _decode(raw)


def _decode(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


async def redis_storage(
    *,
    url: str = "redis://localhost:6379",
    **kwargs: Any,
) -> SecondaryStorage:
    """Build a `RedisStorage` connected to `url`.

    Additional `kwargs` (decode_responses, db, password, …) are forwarded to
    `redis.asyncio.Redis.from_url`.
    """
    import redis.asyncio as redis_asyncio  # local import — optional dep

    client = redis_asyncio.Redis.from_url(url, **kwargs)
    return RedisStorage(client=client)


__all__ = ["RedisStorage", "redis_storage"]
