"""Adapter conformance suite.

Every adapter (memory, SQLAlchemy, …) must pass this identical test set. The fixture
parameterizes over registered adapter factories so adding a new adapter is a
one-line addition. Mirrors the spirit of `reference/e2e/adapter/`.

Run:  uv run pytest e2e/adapter/test_adapter_contract.py
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from kernia.types.adapter import CustomAdapter, JoinConfig, SortBy, Where
from kernia_memory_adapter import memory_adapter
from kernia_mongo import mongo_adapter
from kernia_sqlalchemy import sqlalchemy_adapter
from kernia_test_utils.containers import docker_available, mongodb_container


async def _memory() -> AsyncIterator[CustomAdapter]:
    yield memory_adapter()


async def _sqlalchemy() -> AsyncIterator[CustomAdapter]:
    yield await sqlalchemy_adapter(url="sqlite+aiosqlite:///:memory:")


async def _mongo() -> AsyncIterator[CustomAdapter]:
    if not docker_available():
        pytest.skip("Docker is not available")
    with mongodb_container() as url:
        # Each test gets its own random db so parametrize doesn't leak state.
        adapter = await mongo_adapter(
            url=url,
            db_name=f"kernia_test_{secrets.token_hex(4)}",
        )
        yield adapter


# Registry: list of (id, async factory). Add new adapters here.
ADAPTERS: list[tuple[str, Callable[[], AsyncIterator[CustomAdapter]]]] = [
    ("memory", _memory),
    ("sqlalchemy", _sqlalchemy),
    ("mongo", _mongo),
]


@pytest.fixture(params=ADAPTERS, ids=[name for name, _ in ADAPTERS])
async def adapter(request: pytest.FixtureRequest) -> AsyncIterator[CustomAdapter]:
    _, factory = request.param
    async for a in factory():
        yield a


def _supports(adapter: Any, name: str) -> bool:
    return hasattr(adapter, name)


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


# --------------------------------------------------------------------------- ilike_eq


async def test_ilike_eq_matches_case_insensitive(adapter: CustomAdapter) -> None:
    await adapter.create(model="user", data={"email": "Mixed@Example.COM"})
    found = await adapter.find_one(
        model="user",
        where=(Where(field="email", value="mixed@example.com", operator="ilike_eq"),),
    )
    assert found is not None
    assert found["email"] == "Mixed@Example.COM"


async def test_ilike_eq_does_not_match_other_strings(adapter: CustomAdapter) -> None:
    await adapter.create(model="user", data={"email": "alice@example.com"})
    found = await adapter.find_one(
        model="user",
        where=(Where(field="email", value="bob@example.com", operator="ilike_eq"),),
    )
    assert found is None


# --------------------------------------------------------------------------- joins


async def test_find_one_with_join_returns_nested_record(adapter: CustomAdapter) -> None:
    user = await adapter.create(model="user", data={"email": "j@example.com"})
    await adapter.create(
        model="session",
        data={
            "userId": user["id"],
            "token": "tok-1",
            "expiresAt": 9999999999,
        },
    )
    row = await adapter.find_one(
        model="session",
        where=(Where(field="token", value="tok-1"),),
        join=JoinConfig(model="user", on="userId", foreign_field="id", as_="user"),
    )
    assert row is not None
    assert row["user"] is not None
    assert row["user"]["email"] == "j@example.com"


async def test_find_one_with_join_missing_foreign_is_none(adapter: CustomAdapter) -> None:
    # MongoDB enforces ObjectId-style FK references via lookup; we pass through
    # whatever the caller provides and the missing-row case must surface as None.
    if adapter.__class__.__name__ == "MongoAdapter":
        pytest.skip("MongoDB does not enforce FK; missing-foreign-key tested via lookup elsewhere")
    await adapter.create(
        model="session",
        data={
            "userId": "ghost-id",
            "token": "tok-2",
            "expiresAt": 9999999999,
        },
    )
    row = await adapter.find_one(
        model="session",
        where=(Where(field="token", value="tok-2"),),
        join=JoinConfig(model="user", on="userId", foreign_field="id", as_="user"),
    )
    assert row is not None
    assert row["user"] is None


# --------------------------------------------------------------------------- transactions


async def test_transaction_commits_on_clean_exit(adapter: CustomAdapter) -> None:
    if not _supports(adapter, "transaction"):
        pytest.skip("adapter does not implement TransactionalAdapter")
    async with adapter.transaction():  # type: ignore[attr-defined]
        await adapter.create(model="user", data={"email": "tx-ok@example.com"})
    found = await adapter.find_one(
        model="user",
        where=(Where(field="email", value="tx-ok@example.com"),),
    )
    assert found is not None


async def test_transaction_rolls_back_on_exception(adapter: CustomAdapter) -> None:
    if not _supports(adapter, "transaction"):
        pytest.skip("adapter does not implement TransactionalAdapter")
    # In-memory has no real rollback — declare that explicitly so the test
    # is not silently misleading.
    if adapter.__class__.__name__ == "MemoryAdapter":
        pytest.skip("memory adapter transactions are no-ops (documented)")
    if adapter.__class__.__name__ == "MongoAdapter":
        pytest.skip("MongoAdapter transactions require replica-set deployment")
    pre = await adapter.count(model="user")
    with pytest.raises(RuntimeError):
        async with adapter.transaction():  # type: ignore[attr-defined]
            await adapter.create(model="user", data={"email": "tx-rb@example.com"})
            raise RuntimeError("force rollback")
    post = await adapter.count(model="user")
    assert post == pre
    found = await adapter.find_one(
        model="user",
        where=(Where(field="email", value="tx-rb@example.com"),),
    )
    assert found is None


# --------------------------------------------------------------------------- uuid PK


async def test_sqlalchemy_uuid_pk_mode() -> None:
    """Verify the SQLAlchemy adapter materializes a real UUID column when
    `FieldDef(name='id', type='uuid')` is requested.
    """
    import uuid as uuid_mod

    from kernia.types.adapter import FieldDef, ModelDef

    uuid_model = ModelDef(
        name="widget",
        fields=(
            FieldDef("id", "uuid", unique=True),
            FieldDef("name", "string"),
            FieldDef("createdAt", "date"),
            FieldDef("updatedAt", "date"),
        ),
    )
    adapter = await sqlalchemy_adapter(
        url="sqlite+aiosqlite:///:memory:",
        extra_models=(uuid_model,),
    )
    row = await adapter.create(model="widget", data={"name": "w1"})
    # The id should round-trip as a UUID-compatible value.
    assert isinstance(row["id"], uuid_mod.UUID) or uuid_mod.UUID(str(row["id"]))
    found = await adapter.find_one(
        model="widget",
        where=(Where(field="id", value=row["id"]),),
    )
    assert found is not None
    assert found["name"] == "w1"


# --------------------------------------------------------------------------- consume_one


async def test_consume_one_deletes_atomically(adapter: CustomAdapter) -> None:
    if not hasattr(adapter, "consume_one"):
        pytest.skip("adapter does not implement ConsumingAdapter")
    import time as _time

    await adapter.create(
        model="verification",
        data={
            "identifier": "u@example.com",
            "value": "token-1",
            "expiresAt": int(_time.time()) + 3600,
        },
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
