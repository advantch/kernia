"""Bearer plugin — accepts session tokens via `Authorization: Bearer <token>`.

The bearer token is the same shape as the value in the `better-auth.session_token`
cookie: `<session.token>.<hmac-sha256>`. On every request we look for an
`Authorization` header; if present and there is no session cookie, we verify the
HMAC against the configured secret and attach the session to the request.

Mirrors `reference/packages/better-auth/src/plugins/bearer/index.ts`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.cookies import verify
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext, Session
from kernia.types.cookie import SESSION_TOKEN_COOKIE
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


_BEARER_SCHEME = "bearer "


@dataclass(frozen=True, slots=True)
class BearerOptions:
    require_signature: bool = True


def _make_on_request(opts: BearerOptions):
    async def on_request(ctx: EndpointContext) -> None:
        # If a session is already attached (via cookie), do nothing.
        if ctx.session is not None:
            return
        # Don't override an explicit session cookie.
        if ctx.request.cookies.get(SESSION_TOKEN_COOKIE):
            return
        auth_header = ctx.request.headers.get("authorization") or ctx.request.headers.get(
            "Authorization"
        )
        if not auth_header:
            return
        if auth_header[: len(_BEARER_SCHEME)].lower() != _BEARER_SCHEME:
            return
        bearer_token = auth_header[len(_BEARER_SCHEME):].strip()
        if not bearer_token:
            return

        if "." in bearer_token:
            # Signed cookie shape: <value>.<sig>. Verify the HMAC.
            session_token = verify(bearer_token, secret=ctx.auth.secret)
            if not session_token:
                return
        else:
            # Raw token. Only accept if signature requirement is off.
            if opts.require_signature:
                return
            session_token = bearer_token

        row = await ctx.auth.adapter.find_one(
            model="session",
            where=(Where(field="token", value=session_token),),
        )
        if not row:
            return
        ctx.session = Session(
            id=row["id"],
            user_id=row["userId"],
            expires_at=int(row["expiresAt"]),
            token=row["token"],
            ip_address=row.get("ipAddress"),
            user_agent=row.get("userAgent"),
        )

    return on_request


@dataclass(frozen=True, slots=True)
class _BearerPlugin:
    id: str = "bearer"
    version: str | None = None
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: Any = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = ()
    error_codes: Mapping[str, str] = field(default_factory=dict)
    init: None = None


def bearer(*, require_signature: bool = True) -> KerniaPlugin:
    opts = BearerOptions(require_signature=require_signature)
    return _BearerPlugin(on_request=_make_on_request(opts))  # type: ignore[return-value]
