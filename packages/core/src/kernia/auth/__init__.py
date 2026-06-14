"""Top-level `init` function — entry point for building an auth context.

Mirrors `betterAuth()` in `reference/packages/better-auth/src/auth.ts`. Accepts a
`KerniaOptions`, composes the registered plugins, materializes the schema, and
returns a `BetterAuth` handle that exposes the ASGI router and helpers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from kernia.api.router import Router
from kernia.db.adapter.transform_adapter import TransformAdapter
from kernia.db.schema.resolve import resolve_tables
from kernia.db.with_hooks import get_with_hooks
from kernia.error import ErrorRegistry
from kernia.types.context import AuthContext
from kernia.types.db_hooks import DatabaseHooksEntry
from kernia.types.endpoint import AuthEndpoint
from kernia.types.init_options import KerniaOptions


@dataclass
class Kernia:
    """The handle returned by `init()`.

    - `router` is the ASGI-aware route table.
    - `context` is the resolved `AuthContext`, shared with all plugins.
    - `errors` is the merged error-code registry.
    """

    context: AuthContext
    router: Router
    errors: ErrorRegistry


def init(options: KerniaOptions) -> Kernia:
    """Build a `BetterAuth` handle from options.

    Steps:
      1. Validate required options.
      2. Build `AuthContext`.
      3. Register core routes (always on).
      4. For each plugin: stamp + register endpoints, merge error codes, run init
         hook synchronously (via event loop if needed).
    """
    if not options.secret:
        raise ValueError("KerniaOptions.secret is required")
    if options.database is None:
        raise ValueError("KerniaOptions.database is required")

    # Synthesize an in-memory rate-limit store when one isn't supplied — keeps
    # the no-config path well-behaved without forcing a Redis dependency.
    rate_limit_store = options.rate_limit_store
    if rate_limit_store is None and options.rate_limit.enabled:
        from kernia.auth.rate_limit import InMemoryRateLimitStore

        rate_limit_store = InMemoryRateLimitStore()

    # Resolve the full table set (core + plugin tables/extends + user
    # additionalFields), then wrap the raw adapter so every read/write flows
    # through the schema-driven transform layer (defaults, on_update,
    # transform.input/output, field-name mapping).
    # Per-model overrides (modelName / field renames / additionalFields) for the
    # core tables, mirroring better-auth's `getAuthTables` reading
    # `options.{user,session,account,verification}`.
    model_overrides = {
        "user": options.user,
        "session": options.session,
        "account": options.account,
        "verification": options.verification,
    }
    tables = resolve_tables(
        options.plugins,
        additional_fields=options.additional_fields,
        model_overrides=model_overrides,
        secondary_storage=options.secondary_storage is not None,
        store_session_in_database=options.session.store_session_in_database,
        store_verification_in_database=options.verification.store_in_database,
        rate_limit_database=options.rate_limit.storage == "database",
    )
    adapter = TransformAdapter(options.database, tables)

    # Collect database lifecycle hooks: user options first, then each plugin in
    # registration order. Mirrors how better-auth assembles `databaseHooks`.
    database_hooks: list[DatabaseHooksEntry] = []
    if options.database_hooks:
        database_hooks.append(DatabaseHooksEntry(source="options", hooks=options.database_hooks))
    for plugin in options.plugins:
        plugin_hooks = getattr(plugin, "database_hooks", None)
        if plugin_hooks:
            database_hooks.append(DatabaseHooksEntry(source=plugin.id, hooks=plugin_hooks))

    ctx = AuthContext(
        options=options,
        adapter=adapter,
        base_url=options.base_url,
        secret=options.secret,
        plugins=list(options.plugins),
        secondary_storage=options.secondary_storage,
        rate_limit_store=rate_limit_store,
        tables=tables,
        database_hooks=database_hooks,
    )
    ctx.with_hooks = get_with_hooks(adapter, ctx, database_hooks)
    router = Router(auth=ctx)
    # Expose the router on the context so plugins (e.g. open-api) can introspect
    # the full set of registered endpoints during their own `init` hook.
    ctx.router = router
    errors = ErrorRegistry()

    # 1. Core routes are always registered.
    from kernia.api.routes import core_routes

    core_stamped = [_stamp(ep, owner="core") for ep in core_routes()]
    router.register(core_stamped)

    # 2. Plugin endpoints + error codes.
    for plugin in options.plugins:
        if plugin.endpoints:
            router.register([_stamp(ep, owner=plugin.id) for ep in plugin.endpoints])
        if plugin.error_codes:
            errors.extend(plugin.error_codes, plugin_id=plugin.id)

    # 3. Plugin init callbacks. When no event loop is running we run them eagerly
    # so a fully-initialized handle is returned (preserving synchronous call
    # sites). When called inside a running loop we cannot block, so the work is
    # deferred: `Router._handle_http` awaits `ctx.ensure_initialized()` before the
    # first dispatch. `ensure_initialized` is idempotent, so the eager call here
    # makes the router's await a no-op. This replaces the previous
    # fire-and-forget `create_task`, which dropped `InitResult` patches and raced
    # the first request.
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(ctx.ensure_initialized())

    # The resolved table set lives on `ctx.tables`; migration codegen reuses the
    # same merge via `db.schema.resolve.resolve_tables`.
    return Kernia(context=ctx, router=router, errors=errors)


def _stamp(ep: AuthEndpoint, *, owner: str) -> AuthEndpoint:
    return AuthEndpoint(path=ep.path, options=ep.options, handler=ep.handler, owner=owner)
