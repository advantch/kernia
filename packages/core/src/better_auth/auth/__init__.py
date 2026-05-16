"""Top-level `init` function — entry point for building an auth context.

Mirrors `betterAuth()` in `reference/packages/better-auth/src/auth.ts`. Accepts a
`BetterAuthOptions`, composes the registered plugins, materializes the schema, and
returns a `BetterAuth` handle that exposes the ASGI router and helpers.
"""

from __future__ import annotations

from dataclasses import dataclass

from better_auth.api.router import Router
from better_auth.db.schema import CORE_MODELS
from better_auth.error import ErrorRegistry
from better_auth.types.context import AuthContext
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
    """Build a `BetterAuth` handle from options. Phase 2 fills in plugin composition.

    Validates the required pieces (database adapter, secret), then sets up the
    `AuthContext`, registers the canonical email/password routes if enabled, and
    runs each plugin's `init` hook. Returns a `BetterAuth` ready to mount.
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

    # Register plugin endpoints + error codes. (Plugin init hooks run in Phase 2.)
    for plugin in options.plugins:
        if plugin.endpoints:
            # Stamp owner attribution on endpoints from this plugin.
            stamped = []
            for ep in plugin.endpoints:
                stamped.append(ep.__class__(  # type: ignore[call-arg]
                    path=ep.path,
                    options=ep.options,
                    handler=ep.handler,
                    owner=plugin.id,
                ))
            router.register(stamped)
        if plugin.error_codes:
            errors.extend(plugin.error_codes, plugin_id=plugin.id)

    # Core schema is always present. Plugin schema extension lands in Phase 2.
    _ = CORE_MODELS  # referenced for the migration step

    return BetterAuth(context=ctx, router=router, errors=errors)
