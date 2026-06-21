"""P0.4 — transaction boundary + after-hook ordering.

Locks the contract from `kernia.db.transaction.transaction`:

  * after-hooks run only after a clean commit;
  * after-hooks are discarded on rollback;
  * nested transactions drain once, at the outermost commit;
  * against a real (SQLAlchemy) adapter, a raised exception rolls back the writes.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.db.transaction import transaction
from kernia.db.with_hooks import get_with_hooks
from kernia.types.adapter import Where
from kernia.types.db_hooks import DatabaseHooksEntry, HookOp, ModelHooks
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter


def _user_row(**over):
    base = {
        "id": "u1",
        "email": "a@b.c",
        "emailVerified": False,
        "name": "n",
        "createdAt": 0,
        "updatedAt": 0,
    }
    base.update(over)
    return base


def _auth():
    raw = memory_adapter()
    return raw, init(KerniaOptions(database=raw, secret="x" * 32)).context


@pytest.mark.asyncio
async def test_after_hooks_run_after_commit():
    _raw, ctx = _auth()
    order: list[str] = []

    async def after(_row, _c):
        order.append("after")

    wh = get_with_hooks(
        ctx.adapter,
        ctx,
        [DatabaseHooksEntry("t", {"user": ModelHooks(create=HookOp(after=after))})],
    )
    async with ctx.transaction():
        await wh.create("user", _user_row())
        order.append("in-txn")
    order.append("post-txn")
    # after-hook deferred until the commit, then drained before control returns
    assert order == ["in-txn", "after", "post-txn"]


@pytest.mark.asyncio
async def test_after_hooks_discarded_on_rollback():
    _raw, ctx = _auth()
    ran: list[str] = []

    async def after(_row, _c):
        ran.append("after")

    wh = get_with_hooks(
        ctx.adapter,
        ctx,
        [DatabaseHooksEntry("t", {"user": ModelHooks(create=HookOp(after=after))})],
    )
    with pytest.raises(RuntimeError):
        async with ctx.transaction():
            await wh.create("user", _user_row())
            raise RuntimeError("boom")
    assert ran == []  # after-hook never fired


@pytest.mark.asyncio
async def test_nested_transactions_drain_once_at_outermost():
    _raw, ctx = _auth()
    order: list[str] = []

    async def after(_row, _c):
        order.append("after")

    wh = get_with_hooks(
        ctx.adapter,
        ctx,
        [DatabaseHooksEntry("t", {"user": ModelHooks(create=HookOp(after=after))})],
    )
    async with ctx.transaction():
        await wh.create("user", _user_row(id="u1", email="a@a.a"))
        async with ctx.transaction():  # nested — reuses outer queue
            await wh.create("user", _user_row(id="u2", email="b@b.b"))
        # still inside outer txn: nothing drained yet
        assert order == []
    assert order == ["after", "after"]


@pytest.mark.asyncio
async def test_real_sqlalchemy_rollback_is_atomic():
    sa = pytest.importorskip("kernia_sqlalchemy")
    adapter = await sa.sqlalchemy_adapter(url="sqlite+aiosqlite:///:memory:")
    try:
        with pytest.raises(RuntimeError):
            async with transaction(adapter):
                await adapter.create(model="user", data=_user_row(id="u1", email="a@a.a"))
                raise RuntimeError("boom")

        # the insert must have rolled back
        found = await adapter.find_one(model="user", where=[Where(field="id", value="u1")])
        assert found is None
    finally:
        await adapter.engine.dispose()


@pytest.mark.asyncio
async def test_real_sqlalchemy_commit_persists():
    sa = pytest.importorskip("kernia_sqlalchemy")
    adapter = await sa.sqlalchemy_adapter(url="sqlite+aiosqlite:///:memory:")
    try:
        async with transaction(adapter):
            await adapter.create(model="user", data=_user_row(id="u1", email="a@a.a"))

        found = await adapter.find_one(model="user", where=[Where(field="id", value="u1")])
        assert found is not None and found["id"] == "u1"
    finally:
        await adapter.engine.dispose()
