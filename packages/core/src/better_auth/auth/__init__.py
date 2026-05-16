"""Top-level `init` function — entry point for building an auth context.

Mirrors `betterAuth()` in `reference/packages/better-auth/src/auth.ts`. Accepts a
`BetterAuthOptions`, composes the registered plugins, materializes the schema, and
returns a `BetterAuth` handle that exposes the ASGI router and helpers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from better_auth.api.router import Router
from better_auth.db.schema import CORE_MODELS
from better_auth.error import ErrorRegistry
from better_auth.types.context import AuthContext
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.init_options import BetterAuthOptions


@dataclass
class BetterAuth:
    """The handle returned by `init()`.

    - `router` is the ASGI-aware route table.
    - `context` is the resolved `AuthContext`, shared with all plugins.
    - `errors` is the merged error-code registry.
    """

    context: AuthContext
    router: Router
    errors: ErrorRegistry


def init(options: BetterAuthOptions) -> BetterAuth:
    """Build a `BetterAuth` handle from options.

    Steps:
      1. Validate required options.
      2. Build `AuthContext`.
      3. Register core routes (always on).
      4. For each plugin: stamp + register endpoints, merge error codes, run init
         hook synchronously (via event loop if needed).
    """
    if not options.secret:
        raise ValueError("BetterAuthOptions.secret is required")
    if options.database is None:  # type: ignore[unreachable]
        raise ValueError("BetterAuthOptions.database is required")

    ctx = AuthContext(
        options=options,
        adapter=options.database,
        base_url=options.base_url,
        secret=options.secret,
        plugins=list(options.plugins),
    )
    router = Router(auth=ctx)
    errors = ErrorRegistry()

    # 1. Core routes are always registered.
    from better_auth.api.routes import core_routes

    core_stamped = [_stamp(ep, owner="core") for ep in core_routes()]
    router.register(core_stamped)

    # 2. Plugin endpoints + error codes.
    for plugin in options.plugins:
        if plugin.endpoints:
            router.register([_stamp(ep, owner=plugin.id) for ep in plugin.endpoints])
        if plugin.error_codes:
            errors.extend(plugin.error_codes, plugin_id=plugin.id)

    # 3. Plugin init hooks (synchronous via event loop — kept simple; plugins that
    # need a running loop already are handled by the first ASGI request).
    for plugin in options.plugins:
        plugin_init = getattr(plugin, "init", None)
        if plugin_init is None:
            continue
        try:
            asyncio.get_running_loop()
            # We're already inside a loop — schedule and fire-and-forget.
            asyncio.create_task(plugin_init(ctx))
        except RuntimeError:
            asyncio.run(plugin_init(ctx))

    # Core schema is always present (CORE_MODELS).  Plugin schema is collected via
    # `db.migrations.resolve_full_schema` when generating migrations.
    _ = CORE_MODELS

    return BetterAuth(context=ctx, router=router, errors=errors)


def _stamp(ep: AuthEndpoint, *, owner: str) -> AuthEndpoint:
    return AuthEndpoint(path=ep.path, options=ep.options, handler=ep.handler, owner=owner)
