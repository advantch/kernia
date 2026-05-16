"""Endpoint contract — mirrors `createAuthEndpoint` in
`reference/packages/better-auth/src/api/call.ts`.

Plugins contribute endpoints by constructing `AuthEndpoint` values via
`better_auth.api.endpoint.create_auth_endpoint`. The router composes these into the
public auth surface.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


@dataclass(frozen=True, slots=True)
class EndpointOptions:
    """Configuration declared at endpoint definition time.

    Mirrors the options object accepted by `createAuthEndpoint`:
      - `method`            HTTP method
      - `body`              Pydantic model class for request body (None = no body)
      - `query`             Pydantic model class for query params
      - `requires_session`  if True, the router rejects with 401 before invoking handler
      - `use`               middlewares scoped to this endpoint
      - `metadata`          arbitrary plugin metadata (e.g. OpenAPI tags)
    """

    method: HttpMethod
    body: type | None = None
    query: type | None = None
    requires_session: bool = False
    use: tuple[Any, ...] = ()  # middlewares; Middleware Protocol lives in hooks.py
    metadata: dict[str, Any] = field(default_factory=dict)


from better_auth.types.context import EndpointContext  # noqa: E402

EndpointHandler = Callable[[EndpointContext], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class AuthEndpoint:
    """A registered endpoint. Produced by `create_auth_endpoint`.

    `path` is the route relative to the auth mount point (e.g. `/sign-in/email`).
    The handler returns either a serializable dict or a `Response` object built via
    `better_auth.api.responses`.
    """

    path: str
    options: EndpointOptions
    handler: EndpointHandler
    # The plugin id that contributed this endpoint (set automatically by registration).
    owner: str | None = None
