"""Rate-limit enforcement.

Mirrors `reference/packages/better-auth/src/api/rate-limiter/index.ts`. The router
calls `enforce_rate_limit` after the trusted-origin check and before resolving the
endpoint handler. Each plugin contributes its own per-endpoint `RateLimitRule` list
via `KerniaPlugin.rate_limit`; the core merges those with the global
`KerniaOptions.rate_limit` window.

Two storage backends live here:

  * `InMemoryRateLimitStore` — fixed-window counter kept in a process-local dict.
    Suited to single-process deployments and tests.
  * `RedisRateLimitStore` — atomic INCR + EXPIRE via a tiny Lua script so multiple
    workers share state. Accepts any `SecondaryStorage` whose underlying client
    exposes `.eval(...)` (i.e. the Redis client we expose via `redis_storage`).

Both implement `RateLimitStore`:

    async def hit(self, key, window, max_) -> RateLimitDecision
"""

from __future__ import annotations

import fnmatch
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from kernia.error import APIError
from kernia.types.context import EndpointContext


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Result of a single rate-limit check."""

    allowed: bool
    remaining: int
    reset_at: int  # unix seconds when the window resets


@runtime_checkable
class RateLimitStore(Protocol):
    """Backend contract for rate-limit storage."""

    async def hit(self, key: str, *, window: int, max_: int) -> RateLimitDecision: ...


# --------------------------------------------------------------------------- in-memory


@dataclass
class _Bucket:
    count: int = 0
    expires_at: int = 0


@dataclass
class InMemoryRateLimitStore:
    """Fixed-window counter kept in a dict. Not multi-process safe."""

    _buckets: dict[str, _Bucket] = field(default_factory=lambda: defaultdict(_Bucket))

    async def hit(self, key: str, *, window: int, max_: int) -> RateLimitDecision:
        now = int(time.time())
        bucket = self._buckets[key]
        if bucket.expires_at <= now:
            bucket.count = 0
            bucket.expires_at = now + window
        bucket.count += 1
        allowed = bucket.count <= max_
        remaining = max(0, max_ - bucket.count)
        return RateLimitDecision(allowed=allowed, remaining=remaining, reset_at=bucket.expires_at)


# --------------------------------------------------------------------------- redis


# INCR + EXPIRE-if-fresh, returning (count, ttl_remaining). The Lua script is
# atomic on the server, which is the property that makes multi-worker correctness
# straightforward.
_REDIS_HIT_LUA = (
    "local c = redis.call('INCR', KEYS[1]); "
    "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; "
    "local ttl = redis.call('TTL', KEYS[1]); "
    "return {c, ttl}"
)


@dataclass
class RedisRateLimitStore:
    """Redis-backed rate-limit store.

    Accepts either a `SecondaryStorage` from `redis_storage` (we'll reach into
    `.client`) or a direct `redis.asyncio.Redis` instance.
    """

    client: Any  # redis.asyncio.Redis | RedisStorage

    def _redis(self) -> Any:
        c = self.client
        return getattr(c, "client", c)

    async def hit(self, key: str, *, window: int, max_: int) -> RateLimitDecision:
        result = await self._redis().eval(_REDIS_HIT_LUA, 1, key, window)
        count = int(result[0])
        ttl = int(result[1])
        if ttl < 0:
            ttl = window
        reset_at = int(time.time()) + ttl
        return RateLimitDecision(
            allowed=count <= max_, remaining=max(0, max_ - count), reset_at=reset_at
        )


# --------------------------------------------------------------------------- key + rule matching


def _client_ip(ctx: EndpointContext) -> str:
    headers = ctx.request.headers
    return (
        headers.get("x-forwarded-for", "").split(",")[0].strip()
        or headers.get("x-real-ip", "")
        or "unknown"
    )


def _matches(rule_path: str, request_path: str) -> bool:
    if rule_path == request_path:
        return True
    if "*" in rule_path or "?" in rule_path:
        return fnmatch.fnmatchcase(request_path, rule_path)
    return False


def _rule_for(ctx: EndpointContext) -> tuple[str, int, int] | None:
    """Return `(owner_id, window, max)` for the most specific matching rule.

    The router fills `EndpointContext.auth.plugins` with the registered plugins;
    we walk those, then fall back to the global option. The first match wins
    (consistent with better-auth's first-wins semantics).
    """
    path = ctx.request.path
    for plugin in ctx.auth.plugins:
        rules = getattr(plugin, "rate_limit", None) or ()
        for rule in rules:
            if _matches(rule.path, path):
                return (getattr(plugin, "id", "plugin"), rule.window, rule.max)
    return None


async def enforce_rate_limit(ctx: EndpointContext, store: RateLimitStore | None) -> None:
    """Apply rate-limit rules to the current request.

    Raises `APIError(429, "RATE_LIMITED")` with a `Retry-After` response header
    if the matched rule's quota is exhausted. No-ops when the global option
    is disabled, no rule matches, or no store is configured.
    """
    opts = ctx.auth.options.rate_limit
    if not opts.enabled or store is None:
        return

    rule = _rule_for(ctx)
    if rule is None:
        # Fall through to the global default so floods get clipped too.
        owner, window, max_ = "core", opts.window, opts.max
    else:
        owner, window, max_ = rule

    actor = ctx.session.user_id if ctx.session else _client_ip(ctx)
    key = f"rl:{owner}:{ctx.request.path}:{actor}"

    decision = await store.hit(key, window=window, max_=max_)
    if not decision.allowed:
        retry_after = max(1, decision.reset_at - int(time.time()))
        ctx.response_headers["Retry-After"] = str(retry_after)
        raise APIError(
            429,
            "RATE_LIMITED",
            message=f"Too many requests. Retry in {retry_after}s.",
        )


__all__ = [
    "InMemoryRateLimitStore",
    "RateLimitDecision",
    "RateLimitStore",
    "RedisRateLimitStore",
    "enforce_rate_limit",
]
