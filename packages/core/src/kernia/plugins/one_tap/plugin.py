"""Google One Tap plugin construction.

The client side gets an id_token directly from Google. We:
  1. Verify it against Google's JWKS (configurable for tests/MockIdP).
  2. Resolve / create the user via the shared `handle_oauth_user_info`.
  3. Create a session and set the session cookie.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.error import APIError
from kernia.oauth2 import verify_id_token
from kernia.oauth2.link_account import handle_oauth_user_info
from kernia.social_providers._base import OAuthUserProfile
from kernia.types.context import AuthContext, EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUER = "https://accounts.google.com"


@dataclass(frozen=True, slots=True)
class OneTapOptions:
    """Configuration for the One Tap plugin.

    `client_id` is the Google OAuth client ID issued by GCP. `provider_id` is the
    `account.providerId` written to the DB (default "google" so it aligns with
    the regular social Google provider).

    For tests, `jwks_url` and `issuer` can be overridden to point at a `MockIdP`.
    """

    client_id: str
    provider_id: str = "google"
    jwks_url: str = GOOGLE_JWKS_URL
    issuer: str | tuple[str, ...] = GOOGLE_ISSUER
    disable_sign_up: bool = False
    trusted_provider: bool = True  # treat email_verified as authoritative


class OneTapVerifyBody(BaseModel):
    id_token: str


async def _verify(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: OneTapVerifyBody = ctx.body
    # Accept either a single issuer string or a tuple — try each.
    issuers: tuple[str, ...] = (
        (opts.issuer,) if isinstance(opts.issuer, str) else tuple(opts.issuer)
    )
    last_error: Exception | None = None
    claims: Mapping[str, Any] | None = None
    http_client = ctx.auth.options.advanced.get("http_client")
    for iss in issuers:
        try:
            claims = await verify_id_token(
                id_token=body.id_token,
                jwks_url=opts.jwks_url,
                audience=opts.client_id,
                issuer=iss,
                http_client=http_client,
            )
            break
        except ValueError as e:
            last_error = e
    if claims is None:
        raise APIError(400, "INVALID_REQUEST", message=f"invalid id_token: {last_error}")

    email = claims.get("email")
    if not isinstance(email, str):
        raise APIError(400, "INVALID_REQUEST", message="id_token missing email")
    profile = OAuthUserProfile(
        id=str(claims["sub"]),
        email=email,
        email_verified=bool(claims.get("email_verified", False)),
        name=claims.get("name"),
        image=claims.get("picture"),
        raw=dict(claims),
    )

    trusted = (opts.provider_id,) if opts.trusted_provider else ()
    user, _account = await handle_oauth_user_info(
        ctx.auth,
        provider_id=opts.provider_id,
        profile=profile,
        tokens={"id_token": body.id_token},
        disable_sign_up=opts.disable_sign_up,
        trusted_providers=trusted,
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
    }


def _options(auth: AuthContext) -> OneTapOptions:
    for p in auth.plugins:
        if getattr(p, "id", None) == "one-tap":
            embedded = getattr(p, "opts", None)
            if isinstance(embedded, OneTapOptions):
                return embedded
    raise APIError(500, "INTERNAL", message="one-tap plugin not configured")


VERIFY = create_auth_endpoint(
    "/one-tap/verify",
    EndpointOptions(method="POST", body=OneTapVerifyBody),
    _verify,
)


ONE_TAP_ERROR_CODES: Mapping[str, str] = {}


@dataclass(frozen=True, slots=True)
class _OneTapPlugin:
    opts: OneTapOptions
    id: str = "one-tap"
    version: str | None = None
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: (VERIFY,))
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = field(
        default_factory=lambda: (RateLimitRule(path="/one-tap/verify", window=60, max=20),)
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: dict(ONE_TAP_ERROR_CODES))
    init: None = None


def one_tap(options: OneTapOptions) -> KerniaPlugin:
    """Construct the Google One Tap plugin."""
    return _OneTapPlugin(opts=options)  # type: ignore[return-value]


__all__ = ["one_tap", "OneTapOptions"]
