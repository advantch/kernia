"""After-transaction hook queue.

Mirrors `queueAfterTransactionHook` / the transaction-bound queue in
`reference/packages/better-auth/src/db/`. Database `after` hooks must not observe a
half-committed write, so when a transaction is active they are deferred until it
commits. When no transaction is active they run inline.

The active queue is held in a :class:`contextvars.ContextVar`, so it is correct
under concurrent requests and nested async tasks. :func:`collect_after_hooks`
installs a fresh queue for the duration of a block (an adapter ``transaction()``
wraps its body in it — see Phase 0.4) and returns the drained callables.
"""

from __future__ import annotations

import contextlib
from collections.abc import Awaitable, Callable, Iterator
from contextvars import ContextVar

AfterHook = Callable[[], Awaitable[None]]

_queue: ContextVar[list[AfterHook] | None] = ContextVar(
    "better_auth_after_tx_queue", default=None
)


async def queue_after_transaction_hook(fn: AfterHook) -> None:
    """Defer `fn` until the active transaction commits, or run it inline.

    If a transaction queue is active (installed via :func:`collect_after_hooks`),
    `fn` is appended to it. Otherwise `fn` runs immediately.
    """
    queue = _queue.get()
    if queue is None:
        await fn()
        return
    queue.append(fn)


def current_after_hook_queue() -> list[AfterHook] | None:
    """Return the active after-hook queue, or ``None`` when none is installed.

    A non-``None`` result means a transaction boundary is already collecting
    after-hooks (so a nested transaction must not open its own queue).
    """
    return _queue.get()


@contextlib.contextmanager
def collect_after_hooks() -> Iterator[list[AfterHook]]:
    """Install a fresh after-hook queue for the duration of the block.

    The yielded list is the live queue; after the block the caller is responsible
    for awaiting each collected hook (post-commit). The previous queue (if any) is
    restored on exit, so nesting is safe.
    """
    queue: list[AfterHook] = []
    token = _queue.set(queue)
    try:
        yield queue
    finally:
        _queue.reset(token)


__all__ = [
    "collect_after_hooks",
    "current_after_hook_queue",
    "queue_after_transaction_hook",
]
