"""In-memory implementation of `SecondaryStorage`.

For tests and single-process development. Not durable; not shared across workers.
For production, use the `kernia-redis-storage` package.

Mirrors the behavior the `redis_storage` package implements over Redis.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from kernia.types.secondary_storage import SecondaryStorage


@dataclass
class InMemorySecondaryStorage:
    """Dict-backed `SecondaryStorage` with best-effort TTL eviction.

    Values are evicted lazily on access. A background sweep is intentionally
    avoided — the storage Protocol only promises eviction on read.
    """

    _data: dict[str, tuple[str, float | None]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def get(self, key: str) -> str | None:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at is not None and time.monotonic() >= expires_at:
                self._data.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: str, *, ttl: int | None = None) -> None:
        async with self._lock:
            expires_at = time.monotonic() + ttl if ttl is not None else None
            self._data[key] = (value, expires_at)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def get_and_delete(self, key: str) -> str | None:
        async with self._lock:
            entry = self._data.pop(key, None)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at is not None and time.monotonic() >= expires_at:
                return None
            return value


def in_memory_secondary_storage() -> SecondaryStorage:
    """Construct a fresh in-memory secondary storage."""
    return InMemorySecondaryStorage()


__all__ = ["InMemorySecondaryStorage", "in_memory_secondary_storage"]
