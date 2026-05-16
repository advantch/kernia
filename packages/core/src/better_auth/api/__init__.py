"""HTTP surface — endpoint factory, router, middleware chain.

Mirrors `reference/packages/better-auth/src/api/`.
"""

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.api.router import Router

__all__ = ["Router", "create_auth_endpoint"]
