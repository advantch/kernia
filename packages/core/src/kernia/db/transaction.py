"""Core transaction boundary.

Ties an adapter's :meth:`transaction` to the database after-hook queue so the
``after`` half of :class:`~kernia.types.db_hooks.DatabaseHooks` observes the
same atomicity as the writes:

  * on clean commit the queued after-hooks run **after** the adapter transaction
    commits (a hook never sees a half-written row, and its own side effects —
    emails, webhooks — never fire for a rolled-back write);
  * on rollback the queued after-hooks are discarded.

Mirrors how better-auth drains `queueAfterTransactionHook` callbacks at the
transaction boundary. Nesting is safe: an inner ``transaction`` reuses the outer
queue and commit boundary (the adapter likewise reuses the outer connection), so
after-hooks drain exactly once, at the outermost commit.

Adapters that cannot provide real atomicity (e.g. the in-memory adapter) expose a
no-op ``transaction``; the after-hook ordering guarantee still holds because it is
enforced here, in the core, not by the adapter.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from kernia.db.hook_queue import collect_after_hooks, current_after_hook_queue

if TYPE_CHECKING:
    from kernia.types.adapter import CustomAdapter


@contextlib.asynccontextmanager
async def transaction(adapter: CustomAdapter) -> AsyncIterator[None]:
    """Run a block of adapter writes atomically, draining after-hooks on commit.

    Usage::

        async with transaction(ctx.adapter):
            await ctx.with_hooks.create("organization", org)
            await ctx.with_hooks.create("member", owner)
        # both rows committed; create.after hooks have now run
    """
    adapter_txn = getattr(adapter, "transaction", None)
    if adapter_txn is None:
        raise AttributeError("adapter does not support transactions")

    # Nested transaction: the outermost boundary owns the queue + commit point.
    if current_after_hook_queue() is not None:
        async with adapter_txn():
            yield
        return

    with collect_after_hooks() as queue:
        async with adapter_txn():
            yield
        # Reached only on clean exit of the adapter transaction (commit). An
        # exception propagates out of `adapter_txn()` (rollback) and skips the
        # drain below, discarding the queued after-hooks.
    for run in queue:
        await run()


__all__ = ["transaction"]
