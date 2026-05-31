"""Last-login-method plugin.

When the user signs in successfully, sets a cookie naming the auth method
(`email`, `google`, `github`, etc.). The sign-in page reads this on the next
visit to highlight the most-recently used button. Optionally persists the method
on the user row (`storeInDatabase`).

Mirrors `reference/packages/better-auth/src/plugins/last-login-method/index.ts`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.types.cookie import SESSION_TOKEN_COOKIE, CookieAttributes
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

# Matches upstream: `better-auth.last_used_login_method`.
DEFAULT_COOKIE_NAME = "better-auth.last_used_login_method"
DEFAULT_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


CustomResolveMethod = Callable[[EndpointContext], "str | None"]


@dataclass(frozen=True, slots=True)
class LastLoginMethodOptions:
    cookie_name: str = DEFAULT_COOKIE_NAME
    max_age: int = DEFAULT_MAX_AGE
    custom_resolve_method: CustomResolveMethod | None = None
    store_in_database: bool = False


def _default_resolve_method(ctx: EndpointContext) -> str | None:
    path = ctx.request.path if ctx.request is not None else None
    if not path:
        return None
    # OAuth callbacks: /callback/:id or /oauth2/callback/:providerId
    if path.startswith("/callback/") or path.startswith("/oauth2/callback/"):
        params = ctx.path_params or {}
        return params.get("id") or params.get("providerId") or (path.rsplit("/", 1)[-1] or None)
    if path == "/sign-in/email" or path == "/sign-up/email":
        return "email"
    if "siwe" in path:
        return "siwe"
    if "/passkey/verify-authentication" in path:
        return "passkey"
    if path.startswith("/magic-link/verify"):
        return "magic-link"
    return None


def _resolve_method(opts: LastLoginMethodOptions, ctx: EndpointContext) -> str | None:
    if opts.custom_resolve_method is not None:
        result = opts.custom_resolve_method(ctx)
        if result is not None:
            return result
    return _default_resolve_method(ctx)


def _emitted_session_token(ctx: EndpointContext, secret: str) -> str | None:
    for name, value, _attrs in ctx.set_cookies:
        if name == SESSION_TOKEN_COOKIE and value:
            return _verify_cookie(value, secret=secret)
    return None


def _make_on_response(opts: LastLoginMethodOptions):
    async def on_response(ctx: EndpointContext, result: object) -> None:
        method = _resolve_method(opts, ctx)
        if not method:
            return
        # Only act if the request established a session (emitted the session cookie).
        session_token = _emitted_session_token(ctx, ctx.auth.secret)
        if session_token is None:
            return

        attrs = CookieAttributes(
            path="/",
            max_age=opts.max_age,
            http_only=False,  # readable by client JS, like the TS plugin
            secure=ctx.auth.base_url.startswith("https"),
            same_site="lax",
        )
        ctx.set_cookies.append((opts.cookie_name, method, attrs))

        if opts.store_in_database:
            session_row = await ctx.auth.adapter.find_one(
                model="session", where=(Where(field="token", value=session_token),)
            )
            if session_row and session_row.get("userId"):
                try:
                    await ctx.auth.adapter.update(
                        model="user",
                        where=(Where(field="id", value=session_row["userId"]),),
                        update={"lastLoginMethod": method},
                    )
                except Exception:  # pragma: no cover - mirror upstream's logged-and-ignore
                    pass

    return on_response


_LAST_LOGIN_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("lastLoginMethod", "string", required=False, input=False),
)


@dataclass(frozen=True, slots=True)
class _LastLoginMethodPlugin:
    id: str = "last-login-method"
    version: str | None = None
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: Any = None
    rate_limit: tuple[RateLimitRule, ...] = ()
    error_codes: Mapping[str, str] = field(default_factory=dict)
    init: None = None


def last_login_method(
    *,
    cookie_name: str = DEFAULT_COOKIE_NAME,
    max_age: int = DEFAULT_MAX_AGE,
) -> KerniaPlugin:
    opts = LastLoginMethodOptions(cookie_name=cookie_name, max_age=max_age)
    return _LastLoginMethodPlugin(on_response=_make_on_response(opts))  # type: ignore[return-value]
