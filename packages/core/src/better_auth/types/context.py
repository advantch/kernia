"""Context types — `AuthContext` and `EndpointContext`.

Mirrors `reference/packages/better-auth/src/types/context.ts` and the context plumbed
into endpoint handlers via `createAuthEndpoint`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from better_auth.api.router import Router
    from better_auth.db.with_hooks import WithHooks
    from better_auth.types.adapter import CustomAdapter, ModelDef
    from better_auth.types.db_hooks import DatabaseHooksEntry
    from better_auth.types.init_options import BetterAuthOptions


@dataclass
class AuthContext:
    """Process-wide auth context, built once at startup and passed to every plugin.

    Mirrors the shape returned by `init()` in better-auth: contains the resolved
    options, the adapter handle, the logger, and the registered plugins. Plugins
    receive this in their own `init` hook and may extend it.
    """

    options: BetterAuthOptions
    adapter: CustomAdapter
    base_url: str
    secret: str
    plugins: list[Any] = field(default_factory=list)
    # Plugins may park their own state here under their plugin id as the key.
    plugin_state: MutableMapping[str, Any] = field(default_factory=dict)
    # The router, assigned by `init()` after construction so plugins (e.g.
    # open-api) can introspect the registered endpoints during their `init` hook.
    router: Router | None = None
    # Optional ephemeral key/value backend (Redis, in-memory, …).
    secondary_storage: Any | None = None
    # Optional rate-limit store; `init()` synthesizes an in-memory store when
    # rate-limit is enabled and no explicit store is supplied.
    rate_limit_store: Any | None = None
    # Resolved table set (core + plugin tables/extends + user additionalFields),
    # keyed by logical model name. Populated by `init()` via `resolve_tables`.
    tables: dict[str, ModelDef] = field(default_factory=dict)
    # Database lifecycle hooks contributed by options + plugins, in registration
    # order. Consumed by the `with_hooks` runtime.
    database_hooks: list[DatabaseHooksEntry] = field(default_factory=list)
    # Hook-wrapped adapter operations (create/update/delete/consume with the
    # `database_hooks` lifecycle applied). Assigned by `init()`.
    with_hooks: WithHooks | None = None
    # Lazy plugin-init bookkeeping. `init()` runs plugin `init` callbacks eagerly
    # when no event loop is running; when one is (e.g. an async framework's
    # startup), the work is deferred and the router awaits `ensure_initialized()`
    # before the first dispatch. See `ensure_initialized`.
    _init_done: bool = field(default=False, repr=False, compare=False)
    _init_lock: Any = field(default=None, repr=False, compare=False)

    def transaction(self) -> Any:
        """Atomic write boundary: ``async with ctx.transaction(): ...``.

        Runs the block under the adapter's transaction and drains database
        ``after`` hooks only after a clean commit (discarding them on rollback).
        See :func:`better_auth.db.transaction.transaction`.
        """
        from better_auth.db.transaction import transaction

        return transaction(self.adapter)

    async def ensure_initialized(self) -> None:
        """Run every plugin's `init` callback exactly once, applying its result.

        Mirrors better-auth's lazily-resolved `$context`: a plugin's `init` may
        mutate this context directly and/or return an
        :class:`~better_auth.types.plugin.InitResult` whose ``options_patch`` /
        ``context_patch`` are merged here. Idempotent and concurrency-safe — the
        first caller runs the inits; racers await the same completion.
        """
        if self._init_done:
            return
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            if self._init_done:
                return
            for plugin in self.plugins:
                plugin_init = getattr(plugin, "init", None)
                if plugin_init is None:
                    continue
                result = await plugin_init(self)
                if result is not None:
                    self._apply_init_result(result)
            self._init_done = True

    def _apply_init_result(self, result: Any) -> None:
        """Merge an `InitResult`'s option/context patches onto this context."""
        options_patch = getattr(result, "options_patch", None) or {}
        for key, value in options_patch.items():
            if hasattr(self.options, key):
                setattr(self.options, key, value)
            else:
                self.options.advanced[key] = value
        context_patch = getattr(result, "context_patch", None) or {}
        for key, value in context_patch.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                self.plugin_state[key] = value


@dataclass
class Session:
    """Active session row. Field names mirror the `session` model in better-auth."""

    id: str
    user_id: str
    expires_at: int  # unix seconds
    token: str
    ip_address: str | None = None
    user_agent: str | None = None
    impersonated_by: str | None = None


@dataclass
class User:
    """Active user row. Field names mirror the `user` model."""

    id: str
    email: str
    email_verified: bool = False
    name: str | None = None
    image: str | None = None
    created_at: int = 0
    updated_at: int = 0


class RequestLike(Protocol):
    """The subset of an ASGI/HTTP request the core depends on."""

    method: str
    path: str
    headers: Mapping[str, str]
    query: Mapping[str, str | list[str]]
    cookies: Mapping[str, str]

    async def json(self) -> Any: ...

    async def body(self) -> bytes: ...


@dataclass
class EndpointContext:
    """Per-request context handed to every endpoint handler.

    Mirrors what better-auth passes into a handler defined via `createAuthEndpoint`.
    """

    request: RequestLike
    auth: AuthContext
    session: Session | None = None
    user: User | None = None
    # Decoded body (Pydantic-validated if the endpoint declared a body model).
    body: Any = None
    # Cookies the handler wants set on the response.
    set_cookies: list[tuple[str, str, Any]] = field(default_factory=list)
    # Headers the handler wants on the response.
    response_headers: dict[str, str] = field(default_factory=dict)
    # Path parameters captured from `:param` segments in the route template.
    path_params: dict[str, str] = field(default_factory=dict)
