"""`create_auth_endpoint` factory.

Mirrors `createAuthEndpoint` in `reference/packages/better-auth/src/api/call.ts`.

This file is the public seam for endpoint construction. Plugins build endpoints by
calling this factory; the router consumes the resulting `AuthEndpoint` values.
"""

from __future__ import annotations

from better_auth.types.endpoint import (
    AuthEndpoint,
    EndpointHandler,
    EndpointOptions,
)


def create_auth_endpoint(
    path: str,
    options: EndpointOptions,
    handler: EndpointHandler,
) -> AuthEndpoint:
    """Build an `AuthEndpoint` value.

    Validates `path` is non-empty and starts with `/`. Owner attribution is filled in
    later by the plugin registration step.
    """
    if not path or not path.startswith("/"):
        raise ValueError(f"Endpoint path must start with '/': {path!r}")
    return AuthEndpoint(path=path, options=options, handler=handler, owner=None)
