"""Last-login-method plugin.

When the user signs in successfully, sets a cookie naming the auth method
(`email`, `google`, `github`, etc.). The sign-in page reads this on the next
visit to highlight the most-recently used button.

Mirrors `reference/packages/better-auth/src/plugins/last-login-method/index.ts`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.types.cookie import SESSION_TOKEN_COOKIE, CookieAttributes
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


DEFAULT_COOKIE_NAME = "better-auth.last_login_method"
DEFAULT_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


@dataclass(frozen=True, slots=True)
class LastLoginMethodOptions:
    cookie_name: str = DEFAULT_COOKIE_NAME
    max_age: int = DEFAULT_MAX_AGE


def _resolve_method(path: str) -> str | None:
    if not path:
        return None
    if path.startswith("/callback/"):
        return path.rsplit("/", 1)[-1] or None
    if path.startswith("/oauth2/callback/"):
        return path.rsplit("/", 1)[-1] or None
    if path == "/sign-in/email" or path == "/sign-up/email":
        return "email"
    if "siwe" in path:
        return "siwe"
    if "/passkey/verify-authentication" in path:
        return "passkey"
    if path.startswith("/magic-link/verify"):
        return "magic-link"
    return None


def _make_on_response(opts: LastLoginMethodOptions):
    async def on_response(ctx: EndpointContext, result: object) -> None:
        method = _resolve_method(ctx.request.path)
        if not method:
            return
        # Only set the cookie if the request established a session (i.e. emitted
        # the session_token cookie in ctx.set_cookies). This filters out failed
        # sign-in attempts that never made it to a Set-Cookie line.
        emitted_session = any(
            name == SESSION_TOKEN_COOKIE and value
            for name, value, _ in ctx.set_cookies
        )
        if not emitted_session:
            return
        attrs = CookieAttributes(
            path="/",
            max_age=opts.max_age,
            http_only=False,  # readable by client JS, like the TS plugin
            secure=ctx.auth.base_url.startswith("https"),
            same_site="lax",
        )
        ctx.set_cookies.append((opts.cookie_name, method, attrs))

    return on_response


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
