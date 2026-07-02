"""Redis-backed secondary storage for Kernia."""

from __future__ import annotations

from kernia_redis_storage.storage import RedisStorage, redis_storage

__all__ = ["RedisStorage", "redis_storage"]
