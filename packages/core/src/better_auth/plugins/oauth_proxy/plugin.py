"""OAuth proxy plugin construction.

The intended use case is a single-page app calling our server. The SPA never
sees the OAuth client_secret. Flow:

  1. SPA → POST /oauth-proxy/authorize {provider}
     Server returns {url, state} — SPA opens `url` (e.g. in a popup).
  2. Provider redirects to /oauth-proxy/callback?code=...&state=...
     Server validates state, exchanges the code, creates a session, and returns
     the user + session JSON. (Or 302s to a configured `callback_url`.)

Each provider is registered at plugin construction time as an `OAuthProvider`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl

from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import create_session
from better_auth.error import APIError
from better_auth.oauth2 import pkce_verifier
from better_auth.oauth2.link_account import handle_oauth_user_info
from better_auth.oauth2.state import generate_state, parse_state
from better_auth.social_providers._base import OAuthProvider
from better_auth.types.context import AuthContext, EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


@dataclass(frozen=True, slots=True)
class OAuthProxyOptions:
    """Configuration for the OAuth proxy plugin.

    `providers` is a mapping of provider id → `OAuthProvider`. `redirect_uri` is
    the public-facing URL that the OAuth provider will redirect to — it must
    point at `/oauth-proxy/callback` on the server.
    """

    providers: Mapping[str, OAuthProvider]
    redirect_uri: str
    success_callback_url: str | None = None
    trusted_providers: tuple[str, ...] = ()
    disable_sign_up: bool = False


class AuthorizeBody(BaseModel):
    provider: str
    callback_url: str | None = None


async def _authorize(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: AuthorizeBody = ctx.body
    provider = opts.providers.get(body.provider)
    if provider is None:
        raise APIError(400, "INVALID_REQUEST", message=f"unknown provider: {body.provider}")
    verifier = pkce_verifier()
    state = generate_state(
        secret=ctx.auth.secret,
        callback_url=body.callback_url or opts.success_callback_url or "/",
        provider_id=body.provider,
        code_verifier=verifier,
    )
    url = await provider.authorize(
        redirect_uri=opts.redirect_uri,
        state=state,
        code_verifier=verifier,
        nonce=None,
    )
    return {"url": url, "state": state}


async def _callback(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    qs = ctx.request.query
    code = _q(qs, "code")
    state = _q(qs, "state")
    if not code or not state:
        raise APIError(400, "INVALID_REQUEST", message="code/state required")
    try:
        state_data = parse_state(state, secret=ctx.auth.secret)
    except ValueError as e:
        raise APIError(400, "INVALID_REQUEST", message=str(e)) from None

    provider_id = state_data["providerId"]
    provider = opts.providers.get(provider_id)
    if provider is None:
        raise APIError(400, "INVALID_REQUEST", message=f"unknown provider: {provider_id}")
    code_verifier = state_data.get("codeVerifier")
    tokens = await provider.validate_token(
        code=code,
        redirect_uri=opts.redirect_uri,
        code_verifier=code_verifier,
    )
    profile = await provider.user_profile(tokens=tokens)
    user, _account = await handle_oauth_user_info(
        ctx.auth,
        provider_id=provider_id,
        profile=profile,
        tokens=tokens,
        disable_sign_up=opts.disable_sign_up,
        trusted_providers=opts.trusted_providers or (provider_id,),
    )
    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return {
        "user": {"id": user["id"], "email": user["email"], "name": user.get("name")},
        "session": {"id": session.id, "expiresAt": session.expires_at},
        "callbackURL": state_data.get("callbackURL"),
    }


def _q(qs: Mapping[str, Any], key: str) -> str | None:
    v = qs.get(key)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _options(auth: AuthContext) -> OAuthProxyOptions:
    for p in auth.plugins:
        if getattr(p, "id", None) == "oauth-proxy":
            embedded = getattr(p, "opts", None)
            if isinstance(embedded, OAuthProxyOptions):
                return embedded
    raise APIError(500, "INTERNAL", message="oauth-proxy plugin not configured")


AUTHORIZE = create_auth_endpoint(
    "/oauth-proxy/authorize",
    EndpointOptions(method="POST", body=AuthorizeBody),
    _authorize,
)

CALLBACK = create_auth_endpoint(
    "/oauth-proxy/callback",
    EndpointOptions(method="GET"),
    _callback,
)


@dataclass(frozen=True, slots=True)
class _OAuthProxyPlugin:
    opts: OAuthProxyOptions
    id: str = "oauth-proxy"
    version: str | None = None
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: (AUTHORIZE, CALLBACK))
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = field(
        default_factory=lambda: (
            RateLimitRule(path="/oauth-proxy/authorize", window=60, max=30),
        )
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: {})
    init: None = None


def oauth_proxy(options: OAuthProxyOptions) -> BetterAuthPlugin:
    """Construct the OAuth proxy plugin."""
    return _OAuthProxyPlugin(opts=options)  # type: ignore[return-value]


__all__ = ["oauth_proxy", "OAuthProxyOptions"]
