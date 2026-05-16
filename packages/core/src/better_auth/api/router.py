"""ASGI router for auth endpoints.

Mirrors the dispatch logic in `reference/packages/better-auth/src/api/index.ts`. Holds
a registry of `AuthEndpoint` values keyed by `(method, path)`, runs the hook chain,
and produces a JSON response. The implementation lives in Phase 2; this file declares
the shape so consumers can import the public name.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

from better_auth.types.context import AuthContext
from better_auth.types.endpoint import AuthEndpoint


@dataclass
class Router:
    """In-memory route table for the auth surface.

    `mount` returns an ASGI application that the user mounts at `options.base_path`.
    Integration packages (FastAPI, Starlette) wrap this with their own routing model.
    """

    auth: AuthContext
    _endpoints: dict[tuple[str, str], AuthEndpoint] = field(default_factory=dict)

    def register(self, endpoints: Iterable[AuthEndpoint]) -> None:
        """Register endpoints. Raises on collision (path, method)."""
        for ep in endpoints:
            key = (ep.options.method, ep.path)
            if key in self._endpoints:
                existing = self._endpoints[key]
                raise ValueError(
                    f"Endpoint collision at {ep.options.method} {ep.path}: "
                    f"{existing.owner!r} vs {ep.owner!r}"
                )
            self._endpoints[key] = ep

    def lookup(self, method: str, path: str) -> AuthEndpoint | None:
        return self._endpoints.get((method, path))

    def mount(self) -> Callable[..., Awaitable[None]]:
        """Return the ASGI callable. Implemented in Phase 2."""
        raise NotImplementedError("Router.mount is implemented in Phase 2")
