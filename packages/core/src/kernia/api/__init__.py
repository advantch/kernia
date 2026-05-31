"""HTTP surface — endpoint factory, router, middleware chain.

Mirrors `reference/packages/better-auth/src/api/`.
"""

from kernia.api.endpoint import create_auth_endpoint
from kernia.api.router import Router

__all__ = ["Router", "create_auth_endpoint"]
