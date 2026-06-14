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

from kernia.types.context import AuthContext, EndpointContext
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import AfterHook, PluginHooks
from kernia.types.plugin import (
    InitResult,
    KerniaPlugin,
    PluginSchema,
    RateLimitRule,
)

# The custom-session transform: receives ``{"user": ..., "session": ...}`` and
# the endpoint context, returns the replacement get-session payload. Mirrors the
# ``fn`` argument of upstream ``customSession(fn, options?, config?)``.
CustomSessionFn = Callable[[dict[str, Any], EndpointContext], Awaitable[dict[str, Any] | None]]


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


@dataclass(frozen=True, slots=True)
class _TransformCustomSessionPlugin:
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


def custom_session(
    fn: CustomSessionFn,
    *,
    should_mutate_list_device_sessions: bool = False,
) -> KerniaPlugin:
    """Override the ``/get-session`` response with a custom shape.

    Mirrors upstream ``customSession(fn, options?, config?)``: ``fn`` receives the
    resolved ``{"user", "session"}`` and returns the replacement payload, letting
    the application enrich or reshape the session response (e.g. add derived
    fields). When ``should_mutate_list_device_sessions`` is set and the
    multi-session plugin is installed, the same transform is applied to every
    entry returned by ``/multi-session/list-device-sessions``.

    Unlike :func:`with_custom_session` (a Python-only session *storage* backend),
    this does not change where sessions are persisted — it only transforms the
    response, matching the JS plugin's behavior.
    """

    async def get_session_after(ctx: EndpointContext, result: object) -> object | None:
        # ``/get-session`` returns None when unauthenticated; mirror upstream and
        # leave the null response untouched.
        if not isinstance(result, dict):
            return None
        user = result.get("user")
        if user is None:
            return None
        session = result.get("session")
        return await fn({"user": user, "session": session}, ctx)

    after_hooks: list[AfterHook] = [AfterHook(match="/get-session", handler=get_session_after)]

    if should_mutate_list_device_sessions:

        async def list_after(ctx: EndpointContext, result: object) -> object | None:
            # The Python multi-session endpoint wraps entries as
            # ``{"sessions": [...]}``; apply ``fn`` to each entry in place.
            if not isinstance(result, dict):
                return None
            sessions = result.get("sessions")
            if not isinstance(sessions, list):
                return None
            transformed = [
                await fn(
                    {"user": entry.get("user"), "session": entry},
                    ctx,
                )
                for entry in sessions
            ]
            return {**result, "sessions": transformed}

        # The Python multi-session plugin exposes the device-session list at
        # ``/multi-session/list`` (upstream: ``/multi-session/list-device-sessions``).
        after_hooks.append(AfterHook(match="/multi-session/list", handler=list_after))

    return _TransformCustomSessionPlugin(  # type: ignore[return-value]
        hooks=PluginHooks(after=tuple(after_hooks))
    )
