"""Plugin contract — mirrors `KerniaPlugin` in
`reference/packages/better-auth/src/types/plugins.ts`.

A plugin is the unit of extension. Plugins contribute endpoints, schema, hooks,
middlewares, rate-limit rules, and custom error codes. The core composes them at
startup.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.context import AuthContext
from kernia.types.db_hooks import DatabaseHooks
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import (
    Middleware,
    PluginHooks,
    RequestHook,
    ResponseHook,
)


@dataclass(frozen=True, slots=True)
class PluginSchema:
    """Schema a plugin contributes to the database layer.

    `tables` are new tables the plugin needs (e.g. `two_factor`).
    `extend` is a map of existing-model-name to extra fields (e.g. adding `phone` to
    the `user` table).
    """

    tables: Sequence[ModelDef] = ()
    extend: Mapping[str, Sequence[FieldDef]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """Mirrors better-auth's per-endpoint rate-limit declaration."""

    path: str  # may be a glob
    window: int  # seconds
    max: int


@dataclass(frozen=True, slots=True)
class InitResult:
    """Return value of a plugin's `init` callback.

    A plugin may mutate the running `AuthContext` via this return value. None of the
    fields are required; omit what you don't extend.
    """

    options_patch: Mapping[str, Any] = field(default_factory=dict)
    context_patch: Mapping[str, Any] = field(default_factory=dict)


PluginInit = Callable[[AuthContext], Awaitable[InitResult | None]]


@runtime_checkable
class KerniaPlugin(Protocol):
    """The plugin contract.

    Field semantics mirror better-auth's TypeScript interface:

      * `id`            — unique within an `AuthContext`
      * `schema`        — DB additions the plugin needs
      * `endpoints`     — routes contributed by this plugin
      * `middlewares`   — global middlewares (per-endpoint use `EndpointOptions.use`)
      * `hooks`         — before/after endpoint lifecycle hooks
      * `database_hooks`— before/after DB-write hooks (model -> create/update/delete)
      * `on_request`    — runs globally for every request
      * `on_response`   — runs globally for every response
      * `rate_limit`    — per-path rate-limit rules
      * `error_codes`   — extra error codes this plugin can raise
      * `init`          — called once at startup; may patch context/options
    """

    id: str

    # Optional fields — declare what your plugin needs, omit the rest.
    version: str | None
    schema: PluginSchema | None
    endpoints: Sequence[AuthEndpoint] | None
    middlewares: Sequence[Middleware] | None
    hooks: PluginHooks | None
    database_hooks: DatabaseHooks | None
    on_request: RequestHook | None
    on_response: ResponseHook | None
    rate_limit: Sequence[RateLimitRule] | None
    error_codes: Mapping[str, str] | None
    init: PluginInit | None
