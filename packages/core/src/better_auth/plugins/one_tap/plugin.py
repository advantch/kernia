"""Google One Tap plugin construction.

The client side gets an id_token directly from Google. We:
  1. Verify it against Google's JWKS (configurable for tests/MockIdP).
  2. Resolve / create the user, applying the implicit-account-linking security
     gate from GHSA-g38m-r43w-p2q7 when an existing local user has no Google
     account yet.
  3. Create a session and set the session cookie.

Mirrors `reference/packages/better-auth/src/plugins/one-tap/index.ts`. The
canonical endpoint is `POST /one-tap/callback`; `POST /one-tap/verify` is kept as
a backwards-compatible alias.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import create_session
from better_auth.error import APIError
from better_auth.oauth2 import verify_id_token
from better_auth.types.adapter import Where
from better_auth.types.context import AuthContext, EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUER = "https://accounts.google.com"


@dataclass(frozen=True, slots=True)
class OneTapOptions:
    """Configuration for the One Tap plugin.

    `client_id` is the Google OAuth client ID. When omitted the plugin falls back
    to the `socialProviders.google` client id. `disable_implicit_linking` and
    `require_local_email_verified` mirror the `account.accountLinking` flags from
    upstream (the Python core options model does not yet expose them, so they live
    on the plugin instead).
    """

    client_id: str | None = None
    provider_id: str = "google"
    jwks_url: str = GOOGLE_JWKS_URL
    issuer: str | tuple[str, ...] = GOOGLE_ISSUER
    disable_sign_up: bool = False
    trusted_provider: bool = True  # treat email_verified as authoritative
    disable_implicit_linking: bool = False
    require_local_email_verified: bool = True


class OneTapCallbackBody(BaseModel):
    # Upstream wire field is `idToken`; the harness also maps snake_case bodies.
    id_token: str = Field(validation_alias="idToken")

    model_config = {"populate_by_name": True}


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("true", "1", "yes")
    return bool(v)


async def _verify_token(opts: OneTapOptions, ctx: EndpointContext, id_token: str) -> Mapping[str, Any]:
    audience = opts.client_id
    if audience is None:
        google = ctx.auth.options.social_providers.get("google")
        audience = getattr(google, "client_id", None) if google is not None else None
    issuers: tuple[str, ...] = (
        (opts.issuer,) if isinstance(opts.issuer, str) else tuple(opts.issuer)
    )
    http_client = ctx.auth.options.advanced.get("http_client")
    last_error: Exception | None = None
    for iss in issuers:
        try:
            return await verify_id_token(
                id_token=id_token,
                jwks_url=opts.jwks_url,
                audience=audience,
                issuer=iss,
                http_client=http_client,
            )
        except ValueError as e:
            last_error = e
    raise APIError(400, "BAD_REQUEST", message=f"invalid id token: {last_error}")


def _make_callback(opts: OneTapOptions):
    async def _callback(ctx: EndpointContext) -> dict[str, object]:
        body: OneTapCallbackBody = ctx.body
        claims = await _verify_token(opts, ctx, body.id_token)

        raw_email = claims.get("email")
        if not raw_email:
            return {"error": "Email not available in token"}
        email = str(raw_email).lower()
        sub = str(claims.get("sub"))
        provider_email_verified = _to_bool(claims.get("email_verified", False))
        now = int(time.time())

        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="email", value=email),)
        )

        if not user:
            if opts.disable_sign_up:
                raise APIError(502, "BAD_GATEWAY", message="User not found")
            user = await ctx.auth.adapter.create(
                model="user",
                data={
                    "email": email,
                    "emailVerified": provider_email_verified,
                    "name": claims.get("name"),
                    "image": claims.get("picture"),
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
            await ctx.auth.adapter.create(
                model="account",
                data={
                    "userId": user["id"],
                    "providerId": opts.provider_id,
                    "accountId": sub,
                    "idToken": body.id_token,
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
        else:
            account = await ctx.auth.adapter.find_one(
                model="account",
                where=(
                    Where(field="providerId", value=opts.provider_id),
                    Where(field="accountId", value=sub),
                ),
            )
            if not account:
                linking = ctx.auth.options.account.account_linking
                require_local = opts.require_local_email_verified
                # Mirror upstream's "enabled !== false" default-allow semantics:
                # implicit linking is permitted unless explicitly disabled on the
                # plugin (disable_implicit_linking). The security gate is the
                # email-verified + trusted/provider-verified check below.
                should_link = (
                    not opts.disable_implicit_linking
                    and (not require_local or bool(user.get("emailVerified")))
                    and (
                        opts.provider_id in linking.trusted_providers
                        or (opts.trusted_provider and provider_email_verified)
                    )
                )
                if should_link:
                    await ctx.auth.adapter.create(
                        model="account",
                        data={
                            "userId": user["id"],
                            "providerId": opts.provider_id,
                            "accountId": sub,
                            "scope": "openid,profile,email",
                            "idToken": body.id_token,
                            "createdAt": now,
                            "updatedAt": now,
                        },
                    )
                else:
                    raise APIError(
                        401,
                        "UNAUTHORIZED",
                        message=(
                            "Google identity cannot be linked: implicit account-linking is "
                            "disabled, the local email is not verified, or the Google "
                            "email_verified claim is false and Google is not a trusted provider"
                        ),
                    )

        session, cookies = await create_session(
            ctx.auth,
            user_id=user["id"],
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        ctx.set_cookies.extend(cookies)
        return {
            "token": session.token,
            "user": {"id": user["id"], "email": user["email"], "name": user.get("name")},
            "session": {"id": session.id, "expiresAt": session.expires_at},
        }

    return _callback


def _options(auth: AuthContext) -> OneTapOptions:
    for p in auth.plugins:
        if getattr(p, "id", None) == "one-tap":
            embedded = getattr(p, "opts", None)
            if isinstance(embedded, OneTapOptions):
                return embedded
    raise APIError(500, "INTERNAL", message="one-tap plugin not configured")


ONE_TAP_ERROR_CODES: Mapping[str, str] = {}


@dataclass(frozen=True, slots=True)
class _OneTapPlugin:
    opts: OneTapOptions
    id: str = "one-tap"
    version: str | None = None
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/one-tap/callback", window=60, max=20),
        RateLimitRule(path="/one-tap/verify", window=60, max=20),
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: dict(ONE_TAP_ERROR_CODES))
    init: None = None


def one_tap(options: OneTapOptions | None = None) -> BetterAuthPlugin:
    """Construct the Google One Tap plugin."""
    opts = options or OneTapOptions()
    callback = _make_callback(opts)
    endpoints = (
        create_auth_endpoint(
            "/one-tap/callback",
            EndpointOptions(method="POST", body=OneTapCallbackBody),
            callback,
        ),
        create_auth_endpoint(
            "/one-tap/verify",
            EndpointOptions(method="POST", body=OneTapCallbackBody),
            callback,
        ),
    )
    return _OneTapPlugin(opts=opts, endpoints=endpoints)  # type: ignore[return-value]


__all__ = ["one_tap", "OneTapOptions"]
