"""kernia — Python implementation compatible with Better Auth.

The public surface mirrors `packages/better-auth/src/index.ts` from the reference repo
(pinned at `reference/` to tag v1.6.11).

This package is the framework-agnostic core. Framework adapters (FastAPI, Starlette,
Django) live in sibling packages.
"""

from kernia.types.adapter import CustomAdapter, Where
from kernia.types.context import AuthContext, EndpointContext
from kernia.types.cookie import CookieAttributes, CookieDef
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.hooks import AfterHook, BeforeHook, PluginHooks
from kernia.types.init_options import KerniaOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema

__version__ = "0.0.0"

__all__ = [
    "AfterHook",
    "AuthContext",
    "AuthEndpoint",
    "BeforeHook",
    "KerniaOptions",
    "KerniaPlugin",
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
