"""Hook + middleware Protocols.

Mirrors the hook system in `reference/packages/better-auth/src/types/plugins.ts`:

  * `before` hooks run after the request is parsed but before the endpoint handler.
  * `after` hooks run after the handler, before the response is serialized.
  * `on_request` / `on_response` run globally for every request, regardless of route.
  * `middleware` wraps a handler call site-style.

All hooks are async. A hook may mutate the `EndpointContext` it receives.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from better_auth.types.context import EndpointContext


# A hook matches one or more paths. `match` may be a literal path, a glob ("/sign-in/*"),
# or a callable that inspects the context.
HookMatcher = str | Callable[[EndpointContext], bool]


@dataclass(frozen=True, slots=True)
class BeforeHook:
    """Runs before the endpoint handler. May raise `APIError` to short-circuit."""

    match: HookMatcher
    handler: Callable[[EndpointContext], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class AfterHook:
    """Runs after the endpoint handler. Receives the handler return value as `result`."""

    match: HookMatcher
    handler: Callable[[EndpointContext, object], Awaitable[object | None]]


@dataclass(frozen=True, slots=True)
class PluginHooks:
    """Collection of hooks a plugin contributes."""

    before: Sequence[BeforeHook] = ()
    after: Sequence[AfterHook] = ()


class Middleware(Protocol):
    """A middleware wraps a handler. Mirrors better-auth's `use` array.

    Implementations must call `call_next` to continue the chain. The middleware may
    inspect/modify `ctx` or the return value, or replace the chain entirely.
    """

    async def __call__(
        self,
        ctx: EndpointContext,
        call_next: Callable[[EndpointContext], Awaitable[object]],
    ) -> object: ...


RequestHook = Callable[[EndpointContext], Awaitable[None]]
ResponseHook = Callable[[EndpointContext, object], Awaitable[None]]
