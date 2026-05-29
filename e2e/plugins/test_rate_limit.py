"""Rate-limit end-to-end.

Validates that:
  * After N matching requests within the window, the (N+1)-th returns 429.
  * The 429 carries a `Retry-After` header.
  * Disabling rate-limit in options lets the same burst succeed.

Runs against the in-memory store (always available); the Redis branch is
exercised in `packages/redis_storage/tests/` when docker is up.
"""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.auth.rate_limit import InMemoryRateLimitStore
from better_auth.plugins import email_and_password
from better_auth.types.init_options import BetterAuthOptions, RateLimitOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver


def _make_driver(store: object | None = None, *, enabled: bool = True) -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="rl-secret",
            plugins=[email_and_password()],
            rate_limit=RateLimitOptions(enabled=enabled, window=60, max=10),
            rate_limit_store=store,
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_sign_in_burst_429_after_quota_exhausted() -> None:
    driver = _make_driver(InMemoryRateLimitStore())
    body = {"email": "rate@example.com", "password": "doesntmatter"}
    # email-password plugin rate_limit: /sign-in/email window=60 max=10
    statuses: list[int] = []
    for _ in range(11):
        driver.cookies.clear()
        r = await driver.request("POST", "/sign-in/email", json_body=body)
        statuses.append(r.status)
    # First 10 should be 401 (invalid creds); the 11th should be 429.
    assert statuses[:10] == [401] * 10, statuses
    assert statuses[10] == 429, statuses


async def test_429_carries_retry_after_header() -> None:
    driver = _make_driver(InMemoryRateLimitStore())
    for _ in range(10):
        driver.cookies.clear()
        await driver.request(
            "POST",
            "/sign-in/email",
            json_body={"email": "x@y.z", "password": "p"},
        )
    driver.cookies.clear()
    r = await driver.request(
        "POST", "/sign-in/email", json_body={"email": "x@y.z", "password": "p"}
    )
    assert r.status == 429
    headers = dict(r.headers)
    assert "Retry-After" in headers
    assert int(headers["Retry-After"]) >= 0


async def test_disabled_rate_limit_does_not_throttle() -> None:
    driver = _make_driver(enabled=False)
    for _ in range(20):
        driver.cookies.clear()
        r = await driver.request(
            "POST",
            "/sign-in/email",
            json_body={"email": "x@y.z", "password": "p"},
        )
        # Without rate-limiting, requests keep returning 401.
        assert r.status == 401


async def test_in_memory_store_decision_shape() -> None:
    store = InMemoryRateLimitStore()
    d1 = await store.hit("k", window=60, max_=2)
    d2 = await store.hit("k", window=60, max_=2)
    d3 = await store.hit("k", window=60, max_=2)
    assert d1.allowed and d2.allowed
    assert not d3.allowed
    assert d3.remaining == 0
    assert d3.reset_at > 0


@pytest.mark.skip(reason="Redis store is exercised in packages/redis_storage tests")
async def test_redis_store_placeholder() -> None:
    """The Redis-backed store contract is exercised by the redis_storage tests.

    Kept here as a sentinel so the lane's intent (two store backends) is visible
    from the e2e suite even when docker isn't available locally.
    """
    pass
