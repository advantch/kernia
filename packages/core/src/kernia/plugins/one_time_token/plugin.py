"""One-time-token plugin construction.

Mirrors `reference/packages/better-auth/src/plugins/one-time-token/index.ts`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.plugins.one_time_token import routes
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

ONE_TIME_TOKEN_ERROR_CODES: Mapping[str, str] = {
    "ONE_TIME_TOKEN_INVALID": "One-time token is invalid or has already been used.",
    "ONE_TIME_TOKEN_EXPIRED": "One-time token has expired.",
}


def _new_session_token_from_cookies(ctx: EndpointContext) -> str | None:
    """Return the session token of a freshly-set session cookie, if any."""
    for name, value, attrs in ctx.set_cookies:
        if name != SESSION_TOKEN_COOKIE:
            continue
        if not value or getattr(attrs, "max_age", None) == 0:
            return None
        return _verify_cookie(value, secret=ctx.auth.secret)
    return None


def _make_after_hook(opts: OneTimeTokenOptions) -> AfterHook:
    async def _handler(ctx: EndpointContext, result: object) -> None:
        if not opts.set_ott_header_on_new_session:
            return
        session_token = _new_session_token_from_cookies(ctx)
        if not session_token:
            return
        session_row = await ctx.auth.adapter.find_one(
            model="session", where=(Where(field="token", value=session_token),)
        )
        if not session_row:
            return
        user_row = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=session_row["userId"]),)
        )
        payload = {
            "session": {
                "token": session_token,
                "id": session_row.get("id"),
                "userId": session_row["userId"],
            },
            "user": user_row or {"id": session_row["userId"]},
        }
        token = await generate_token_for_session(opts, ctx, payload)
        exposed = ctx.response_headers.get("Access-Control-Expose-Headers", "")
        names = [h.strip() for h in exposed.split(",") if h.strip()]
        if "set-ott" not in names:
            names.append("set-ott")
        ctx.response_headers["set-ott"] = token
        ctx.response_headers["Access-Control-Expose-Headers"] = ", ".join(names)

    return AfterHook(match=lambda _ctx: True, handler=_handler)


@dataclass(frozen=True, slots=True)
class _OneTimeTokenPlugin:
    id: str = "one-time-token"
    version: str | None = None
    schema: PluginSchema | None = None  # reuses core verification table
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/one-time-token/generate", window=60, max=10),
        RateLimitRule(path="/one-time-token/verify", window=60, max=10),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(ONE_TIME_TOKEN_ERROR_CODES)
    )
    init: None = None


def one_time_token() -> KerniaPlugin:
    """Construct the one-time-token plugin."""
    opts = OneTimeTokenOptions(
        expires_in=expires_in,
        disable_client_request=disable_client_request,
        generate_token=generate_token,
        disable_set_session_cookie=disable_set_session_cookie,
        store_token=store_token,
        set_ott_header_on_new_session=set_ott_header_on_new_session,
    )
    return _OneTimeTokenPlugin(
        endpoints=routes.build_endpoints(opts),
        hooks=PluginHooks(after=(_make_after_hook(opts),)),
    )  # type: ignore[return-value]
