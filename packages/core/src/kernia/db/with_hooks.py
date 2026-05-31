"""Database-hook runtime — port of
`reference/packages/better-auth/src/db/with-hooks.ts`.

:func:`get_with_hooks` returns a :class:`WithHooks` bundle that wraps adapter writes
in the registered :class:`~better_auth.types.db_hooks.DatabaseHooks` lifecycle:

  * ``create`` / ``update`` / ``update_many`` run each registered ``before`` hook
    (abort on ``False``, shallow-merge a returned ``{"data": ...}`` patch), perform
    the write, then queue each ``after`` hook to run post-commit.
  * ``delete`` / ``delete_many`` first read the target row(s) so ``before`` /
    ``after`` delete hooks receive the entity being removed.
  * ``consume_one`` wraps an atomic single-row delete-and-return in the
    ``delete.before`` / ``delete.after`` lifecycle (first racer wins).

Unlike the transform adapter (which is part of ``adapter.create``), these helpers
are an explicit layer that the internal-adapter / plugins call when they want hook
semantics. A ``before`` hook returning ``False`` makes the helper return ``None``
without writing.

The active :class:`~better_auth.types.context.AuthContext` is passed to every hook;
``after`` hooks are deferred via
:func:`better_auth.db.hook_queue.queue_after_transaction_hook`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from better_auth.db.adapter.transform_adapter import _maybe_await
from better_auth.db.hook_queue import queue_after_transaction_hook
from better_auth.types.adapter import Record, Where
from better_auth.types.db_hooks import (
    DatabaseHooksEntry,
    HookData,
    HookOp,
    ModelHooks,
)

if TYPE_CHECKING:
    from better_auth.types.adapter import CustomAdapter
    from better_auth.types.context import AuthContext


def _patch_from_result(result: Any) -> Record | None:
    """Extract a ``{data: ...}`` patch from a before-hook result, if any."""
    if isinstance(result, HookData):
        return dict(result.data)
    if isinstance(result, Mapping) and "data" in result:
        return dict(result["data"])
    return None


def _op(hooks: ModelHooks | None, kind: str) -> HookOp | None:
    if hooks is None:
        return None
    return getattr(hooks, kind, None)


class WithHooks:
    """Hook-wrapped adapter operations bound to one :class:`AuthContext`."""

    def __init__(
        self,
        adapter: CustomAdapter,
        ctx: AuthContext | None,
        hooks_entries: Sequence[DatabaseHooksEntry],
    ) -> None:
        self._adapter = adapter
        self._ctx = ctx
        self._entries = list(hooks_entries)

    async def _run_before(self, model: str, kind: str, data: Record) -> Record | None:
        """Run before hooks. Returns the (possibly patched) data, or ``None`` to abort."""
        actual = dict(data)
        for entry in self._entries:
            op = _op(entry.hooks.get(model), kind)
            if op is None or op.before is None:
                continue
            result = await _maybe_await(op.before(actual, self._ctx))
            if result is False:
                return None
            patch = _patch_from_result(result)
            if patch is not None:
                actual = {**actual, **patch}
        return actual

    async def _queue_after(self, model: str, kind: str, record: Record) -> None:
        for entry in self._entries:
            op = _op(entry.hooks.get(model), kind)
            if op is None or op.after is None:
                continue
            after = op.after
            snapshot = record

            async def _run(after: Any = after, snapshot: Record = snapshot) -> None:
                await _maybe_await(after(snapshot, self._ctx))

            await queue_after_transaction_hook(_run)

    async def create(
        self,
        model: str,
        data: Record,
        *,
        select: Sequence[str] | None = None,
    ) -> Record | None:
        actual = await self._run_before(model, "create", data)
        if actual is None:
            return None
        created = await self._adapter.create(model=model, data=actual, select=select)
        await self._queue_after(model, "create", created)
        return created

    async def update(
        self,
        model: str,
        where: Sequence[Where],
        data: Record,
    ) -> Record | None:
        actual = await self._run_before(model, "update", data)
        if actual is None:
            return None
        updated = await self._adapter.update(model=model, where=where, update=actual)
        if updated is not None:
            await self._queue_after(model, "update", updated)
        return updated

    async def update_many(
        self,
        model: str,
        where: Sequence[Where],
        data: Record,
    ) -> int | None:
        actual = await self._run_before(model, "update", data)
        if actual is None:
            return None
        return await self._adapter.update_many(model=model, where=where, update=actual)

    async def delete(
        self,
        model: str,
        where: Sequence[Where],
    ) -> None:
        entity: Record | None = None
        try:
            rows = await self._adapter.find_many(model=model, where=where, limit=1)
            entity = rows[0] if rows else None
        except Exception:  # — best-effort pre-read, proceed regardless
            entity = None
        if entity is not None:
            for entry in self._entries:
                op = _op(entry.hooks.get(model), "delete")
                if op is None or op.before is None:
                    continue
                if await _maybe_await(op.before(entity, self._ctx)) is False:
                    return
        await self._adapter.delete(model=model, where=where)
        if entity is not None:
            await self._queue_after(model, "delete", entity)

    async def delete_many(
        self,
        model: str,
        where: Sequence[Where],
    ) -> int:
        entities: list[Record] = []
        try:
            entities = await self._adapter.find_many(model=model, where=where)
        except Exception:  # — best-effort pre-read
            entities = []
        for entity in entities:
            for entry in self._entries:
                op = _op(entry.hooks.get(model), "delete")
                if op is None or op.before is None:
                    continue
                if await _maybe_await(op.before(entity, self._ctx)) is False:
                    return 0
        deleted = await self._adapter.delete_many(model=model, where=where)
        for entity in entities:
            await self._queue_after(model, "delete", entity)
        return deleted

    async def consume_one(
        self,
        model: str,
        where: Sequence[Where],
        *,
        pre_snapshot: Record | None = None,
    ) -> Record | None:
        before_hooks = [
            entry
            for entry in self._entries
            if (op := _op(entry.hooks.get(model), "delete")) is not None
            and op.before is not None
        ]
        snapshot = pre_snapshot
        if before_hooks:
            if snapshot is None:
                try:
                    rows = await self._adapter.find_many(
                        model=model, where=where, limit=1
                    )
                    snapshot = rows[0] if rows else None
                except Exception:
                    snapshot = None
            if snapshot is not None:
                for entry in before_hooks:
                    op = _op(entry.hooks.get(model), "delete")
                    assert op is not None
                    assert op.before is not None
                    if await _maybe_await(op.before(snapshot, self._ctx)) is False:
                        return None

        consume = getattr(self._adapter, "consume_one", None)
        if consume is None:
            raise AttributeError("adapter does not support consume_one")
        consumed = await consume(model=model, where=where)
        if not consumed:
            return None
        await self._queue_after(model, "delete", consumed)
        return consumed


def get_with_hooks(
    adapter: CustomAdapter,
    ctx: AuthContext | None,
    hooks_entries: Sequence[DatabaseHooksEntry] = (),
) -> WithHooks:
    """Construct a :class:`WithHooks` bundle. Mirrors JS ``getWithHooks``."""
    return WithHooks(adapter, ctx, hooks_entries)


__all__ = ["WithHooks", "get_with_hooks"]
