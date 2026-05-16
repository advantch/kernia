"""Adapter conformance suite.

Every adapter (memory, SQLAlchemy, …) must pass this identical test set. The fixture
parameterizes over registered adapter factories so adding a new adapter is a
one-line addition. Mirrors the spirit of `reference/e2e/adapter/`.

Run:  uv run pytest e2e/adapter/test_adapter_contract.py
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from better_auth.types.adapter import CustomAdapter, SortBy, Where
from better_auth_memory_adapter import memory_adapter


# Registry: list of (id, factory). Add new adapters here.
ADAPTERS: list[tuple[str, Callable[[], CustomAdapter]]] = [
    ("memory", memory_adapter),
]


@pytest.fixture(params=ADAPTERS, ids=[name for name, _ in ADAPTERS])
def adapter(request: pytest.FixtureRequest) -> CustomAdapter:
    _, factory = request.param
    return factory()


# --------------------------------------------------------------------------- CRUD


async def test_create_and_find_one(adapter: CustomAdapter) -> None:
    row = await adapter.create(
        model="user",
        data={"email": "a@example.com", "emailVerified": False},
    )
    assert row["email"] == "a@example.com"
    assert row["id"]

    found = await adapter.find_one(
        model="user",
        where=(Where(field="email", value="a@example.com"),),
    )
    assert found is not None
    assert found["id"] == row["id"]


async def test_find_one_missing_returns_none(adapter: CustomAdapter) -> None:
    found = await adapter.find_one(
        model="user",
        where=(Where(field="email", value="nope@example.com"),),
    )
    assert found is None


async def test_find_many_with_sort_and_limit(adapter: CustomAdapter) -> None:
    for i in range(5):
        await adapter.create(model="user", data={"email": f"u{i}@example.com"})
    rows = await adapter.find_many(
        model="user",
        sort_by=SortBy(field="email", direction="desc"),
        limit=2,
    )
    assert len(rows) == 2
    assert rows[0]["email"] == "u4@example.com"
    assert rows[1]["email"] == "u3@example.com"


async def test_update_returns_updated_row(adapter: CustomAdapter) -> None:
    await adapter.create(model="user", data={"email": "u@example.com"})
    updated = await adapter.update(
        model="user",
        where=(Where(field="email", value="u@example.com"),),
        update={"name": "User"},
    )
    assert updated is not None
    assert updated["name"] == "User"


async def test_update_missing_returns_none(adapter: CustomAdapter) -> None:
    result = await adapter.update(
        model="user",
        where=(Where(field="email", value="ghost@example.com"),),
        update={"name": "x"},
    )
    assert result is None


async def test_delete_and_count(adapter: CustomAdapter) -> None:
    for i in range(3):
        await adapter.create(model="user", data={"email": f"u{i}@example.com"})
    assert await adapter.count(model="user") == 3
    await adapter.delete(
        model="user",
        where=(Where(field="email", value="u1@example.com"),),
    )
    assert await adapter.count(model="user") == 2


async def test_delete_many_returns_count(adapter: CustomAdapter) -> None:
    for i in range(4):
        await adapter.create(model="user", data={"email": f"u{i}@example.com"})
    removed = await adapter.delete_many(
        model="user",
        where=(Where(field="email", value="u0@example.com", operator="ne"),),
    )
    assert removed == 3
    assert await adapter.count(model="user") == 1


# --------------------------------------------------------------------------- operators


@pytest.mark.parametrize(
    ("operator", "value", "matches"),
    [
        ("eq", "a@example.com", ["a@example.com"]),
        ("ne", "a@example.com", ["b@example.com", "c@example.com"]),
        ("in", ["a@example.com", "b@example.com"], ["a@example.com", "b@example.com"]),
        ("not_in", ["a@example.com"], ["b@example.com", "c@example.com"]),
        ("starts_with", "a", ["a@example.com"]),
        ("ends_with", ".com", ["a@example.com", "b@example.com", "c@example.com"]),
        ("contains", "@example", ["a@example.com", "b@example.com", "c@example.com"]),
    ],
)
async def test_where_operators(
    adapter: CustomAdapter,
    operator: str,
    value: object,
    matches: list[str],
) -> None:
    for email in ["a@example.com", "b@example.com", "c@example.com"]:
        await adapter.create(model="user", data={"email": email})
    rows = await adapter.find_many(
        model="user",
        where=(Where(field="email", value=value, operator=operator),),  # type: ignore[arg-type]
    )
    assert sorted(r["email"] for r in rows) == sorted(matches)


# --------------------------------------------------------------------------- consume_one


async def test_consume_one_deletes_atomically(adapter: CustomAdapter) -> None:
    if not hasattr(adapter, "consume_one"):
        pytest.skip("adapter does not implement ConsumingAdapter")
    await adapter.create(
        model="verification",
        data={"identifier": "u@example.com", "value": "token-1"},
    )
    consumed = await adapter.consume_one(  # type: ignore[attr-defined]
        model="verification",
        where=(Where(field="value", value="token-1"),),
    )
    assert consumed is not None
    assert consumed["value"] == "token-1"
    # Second consume returns None — the row is gone.
    again = await adapter.consume_one(  # type: ignore[attr-defined]
        model="verification",
        where=(Where(field="value", value="token-1"),),
    )
    assert again is None
