"""Custom-session plugin construction.

Lets the application replace the core session storage with a custom implementation
(e.g. Redis, a JWE-encoded stateless session, or a sharded SQL table). The provider
is installed via `auth.plugin_state["session_provider"]` during the plugin's
`init` hook, after which `kernia.context.create_session` /
`revoke_session` and the router's `_attach_session` delegate to it.

Mirrors `reference/packages/better-auth/src/plugins/custom-session/`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from kernia.types.context import AuthContext
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import (
    KerniaPlugin,
    InitResult,
    PluginSchema,
    RateLimitRule,
)


@runtime_checkable
class SessionProvider(Protocol):
    """Contract a custom session backend must satisfy.

    Each method returns a session record (dict) with at least `id`, `userId`,
    `token`, `expiresAt`. `get_session` may return None for unknown tokens.
    """

    async def create_session(
        self,
        *,
        user_id: str,
        token: str,
        expires_at: int,
        ip_address: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]: ...

    async def get_session(self, *, token: str) -> dict[str, Any] | None: ...

    async def delete_session(self, *, token: str) -> None: ...


@dataclass(frozen=True, slots=True)
class _CustomSessionPlugin:
    id: str = "custom-session"
    version: str | None = None
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = ()
    error_codes: Mapping[str, str] = field(default_factory=dict)
    init: Any = None


def with_custom_session(provider: SessionProvider) -> KerniaPlugin:
    """Build a plugin that installs `provider` as the session backend."""

    async def init(ctx: AuthContext) -> InitResult | None:
        ctx.plugin_state["session_provider"] = provider
        return None

    return _CustomSessionPlugin(init=init)  # type: ignore[return-value]
