"""HIBP plugin end-to-end.

Mocks `https://api.pwnedpasswords.com/range/<prefix>` via `httpx.MockTransport`.
Validates:
  * A known-pwned hash is rejected with `PASSWORD_COMPROMISED`.
  * A clean hash passes through.
  * SecondaryStorage cache saves the second HTTP call.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest

from better_auth.auth import init
from better_auth.plugins import email_and_password, have_i_been_pwned
from better_auth.types.init_options import (
    BetterAuthOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver


def _pwned_suffix(password: str) -> tuple[str, str]:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    return sha1[:5], sha1[5:]


def _transport(*, known_password: str, breach_count: int = 9999) -> tuple[httpx.MockTransport, list[str]]:
    """Build a transport that returns a range hit for `known_password`.

    Returns the transport and a list that records each (prefix) called, so we
    can assert cache behavior.
    """
    prefix, suffix = _pwned_suffix(known_password)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen = request.url.path.rsplit("/", 1)[-1]
        calls.append(seen)
        if seen == prefix:
            body = f"{suffix}:{breach_count}\nABCDE12345:1\n"
        else:
            body = "ZZZZZZZZZZ:1\n"
        return httpx.Response(200, text=body)

    return httpx.MockTransport(handler), calls


class _MemorySecondaryStorage:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._data.get(key)

    async def set(self, key: str, value: str, *, ttl: int | None = None) -> None:
        self._data[key] = value

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def get_and_delete(self, key: str) -> str | None:
        return self._data.pop(key, None)


def _make_driver(
    transport: httpx.MockTransport,
    *,
    storage: object | None = None,
    threshold: int = 0,
) -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="hibp-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[
                email_and_password(),
                have_i_been_pwned(transport=transport, count_threshold=threshold),
            ],
            rate_limit=RateLimitOptions(enabled=False),
            secondary_storage=storage,
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_pwned_password_rejected_on_sign_up() -> None:
    transport, _calls = _transport(known_password="hunter2hunter2")
    driver = _make_driver(transport)
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "p@example.com", "password": "hunter2hunter2"},
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "PASSWORD_COMPROMISED"


async def test_clean_password_passes_through() -> None:
    transport, _calls = _transport(known_password="hunter2hunter2")
    driver = _make_driver(transport)
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "clean@example.com", "password": "uniqueLongPassword!"},
    )
    assert r.status == 200, r.json()


async def test_cache_hit_skips_second_http_call() -> None:
    transport, calls = _transport(known_password="someBadPassword")
    storage = _MemorySecondaryStorage()
    driver = _make_driver(transport, storage=storage)

    # First call — populates the cache.
    r1 = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "a@example.com", "password": "someBadPassword"},
    )
    assert r1.status == 400
    n_first = len(calls)
    assert n_first == 1

    # Second call with the same password hits the cache, so no extra fetch.
    driver.cookies.clear()
    r2 = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "b@example.com", "password": "someBadPassword"},
    )
    assert r2.status == 400
    assert len(calls) == n_first, "cache hit should have skipped the second HTTP call"


@pytest.mark.parametrize("threshold,count,expected", [(0, 5, 400), (10, 5, 200)])
async def test_threshold_gates_rejection(
    threshold: int, count: int, expected: int
) -> None:
    transport, _ = _transport(known_password="thresholdTest!", breach_count=count)
    driver = _make_driver(transport, threshold=threshold)
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "t@example.com", "password": "thresholdTest!"},
    )
    assert r.status == expected
