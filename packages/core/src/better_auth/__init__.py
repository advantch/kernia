"""better_auth — Python port of better-auth.

The public surface mirrors `packages/better-auth/src/index.ts` from the reference repo
(pinned at `reference/` to tag v1.6.11).

This package is the framework-agnostic core. Framework adapters (FastAPI, Starlette,
Django) live in sibling packages.
"""

from better_auth.types.adapter import CustomAdapter, Where
from better_auth.types.context import AuthContext, EndpointContext
from better_auth.types.cookie import CookieAttributes, CookieDef
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.hooks import AfterHook, BeforeHook, PluginHooks
from better_auth.types.init_options import BetterAuthOptions
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema

__version__ = "0.0.0"

__all__ = [
    "AfterHook",
    "AuthContext",
    "AuthEndpoint",
    "BeforeHook",
    "BetterAuthOptions",
    "BetterAuthPlugin",
    "CookieAttributes",
    "CookieDef",
    "CustomAdapter",
    "EndpointContext",
    "EndpointOptions",
    "PluginHooks",
    "PluginSchema",
    "Where",
    "__version__",
]
