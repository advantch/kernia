"""Database lifecycle hooks — mirrors `databaseHooks` in
`reference/packages/better-auth/src/types/auth.ts` and the runtime in
`reference/packages/better-auth/src/db/with-hooks.ts`.

These are distinct from the *endpoint* hooks in `types/hooks.py`:

  * Endpoint hooks (before/after) fire around an HTTP handler, matched by path.
  * Database hooks fire around an adapter write (create/update/delete), keyed by
    model name, and run regardless of which endpoint triggered the write.

A `before` hook receives the candidate row and the active `AuthContext` (or
``None`` when no request context is bound). It may:

  * return ``False`` to abort the operation (the write is skipped, the
    ``with_hooks`` helper returns ``None``);
  * return a mapping with a ``"data"`` key (or a :class:`HookData`) to *patch*
    the row — the patch is shallow-merged over the candidate before the write;
  * return ``None`` (or anything else) to leave the row unchanged.

An `after` hook receives the persisted row and runs post-write (queued to run
after the surrounding transaction commits, when one is active).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Union

if TYPE_CHECKING:
    from better_auth.types.context import AuthContext

Record = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HookData:
    """Explicit patch wrapper returned by a ``before`` hook.

    Equivalent to JS returning ``{ data: {...} }``. Returning a plain mapping
    with a ``"data"`` key is also accepted by the runtime.
    """

    data: Record


# A before-hook returns False (abort), a patch (HookData / {"data": ...}),
# or None / anything else (no-op). May be sync or async.
BeforeHookResult = Union[bool, HookData, Mapping[str, Any], None]
BeforeHookFn = Callable[
    ["Record", "AuthContext | None"], Awaitable[BeforeHookResult] | BeforeHookResult
]
AfterHookFn = Callable[
    ["Record", "AuthContext | None"], Awaitable[None] | None
]


@dataclass(frozen=True, slots=True)
class HookOp:
    """The before/after pair for a single operation (create | update | delete)."""

    before: BeforeHookFn | None = None
    after: AfterHookFn | None = None


@dataclass(frozen=True, slots=True)
class ModelHooks:
    """Hooks for a single model. Mirrors ``databaseHooks[model]`` in JS."""

    create: HookOp | None = None
    update: HookOp | None = None
    delete: HookOp | None = None


# Keyed by logical model name (e.g. "user", "session").
DatabaseHooks = Mapping[str, ModelHooks]


@dataclass(frozen=True, slots=True)
class DatabaseHooksEntry:
    """A single contributor's hooks, tagged with its source for diagnostics.

    Mirrors JS ``DatabaseHooksEntry = { source, hooks }``. ``source`` is the
    plugin id (or ``"core"`` / ``"options"``) that registered the hooks.
    """

    source: str
    hooks: DatabaseHooks


__all__ = [
    "AfterHookFn",
    "BeforeHookFn",
    "BeforeHookResult",
    "DatabaseHooks",
    "DatabaseHooksEntry",
    "HookData",
    "HookOp",
    "ModelHooks",
]
