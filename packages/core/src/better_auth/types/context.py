"""Context types — `AuthContext` and `EndpointContext`.

Mirrors `reference/packages/better-auth/src/types/context.ts` and the context plumbed
into endpoint handlers via `createAuthEndpoint`.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from better_auth.api.router import Router
    from better_auth.types.adapter import CustomAdapter
    from better_auth.types.init_options import BetterAuthOptions


@dataclass
class AuthContext:
    """Process-wide auth context, built once at startup and passed to every plugin.

    Mirrors the shape returned by `init()` in better-auth: contains the resolved
    options, the adapter handle, the logger, and the registered plugins. Plugins
    receive this in their own `init` hook and may extend it.
    """

    options: BetterAuthOptions
    adapter: CustomAdapter
    base_url: str
    secret: str
    plugins: list[Any] = field(default_factory=list)
    # Plugins may park their own state here under their plugin id as the key.
    plugin_state: MutableMapping[str, Any] = field(default_factory=dict)
    # The router, assigned by `init()` after construction so plugins (e.g.
    # open-api) can introspect the registered endpoints during their `init` hook.
    router: Router | None = None
    # Optional ephemeral key/value backend (Redis, in-memory, …).
    secondary_storage: Any | None = None
    # Optional rate-limit store; `init()` synthesizes an in-memory store when
    # rate-limit is enabled and no explicit store is supplied.
    rate_limit_store: Any | None = None


@dataclass
class Session:
    """Active session row. Field names mirror the `session` model in better-auth."""

    id: str
    user_id: str
    expires_at: int  # unix seconds
    token: str
    ip_address: str | None = None
    user_agent: str | None = None
    impersonated_by: str | None = None


@dataclass
class User:
    """Active user row. Field names mirror the `user` model."""

    id: str
    email: str
    email_verified: bool = False
    name: str | None = None
    image: str | None = None
    created_at: int = 0
    updated_at: int = 0


class RequestLike(Protocol):
    """The subset of an ASGI/HTTP request the core depends on."""

    method: str
    path: str
    headers: Mapping[str, str]
    query: Mapping[str, str | list[str]]
    cookies: Mapping[str, str]

    async def json(self) -> Any: ...

    async def body(self) -> bytes: ...


@dataclass
class EndpointContext:
    """Per-request context handed to every endpoint handler.

    Mirrors what better-auth passes into a handler defined via `createAuthEndpoint`.
    """

    request: RequestLike
    auth: AuthContext
    session: Session | None = None
    user: User | None = None
    # Decoded body (Pydantic-validated if the endpoint declared a body model).
    body: Any = None
    # Cookies the handler wants set on the response.
    set_cookies: list[tuple[str, str, Any]] = field(default_factory=list)
    # Headers the handler wants on the response.
    response_headers: dict[str, str] = field(default_factory=dict)
    # Path parameters captured from `:param` segments in the route template.
    path_params: dict[str, str] = field(default_factory=dict)
