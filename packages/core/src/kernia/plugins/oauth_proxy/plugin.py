"""OAuth proxy plugin construction.

This plugin serves two distinct flows:

1. The upstream *passthrough* receiving endpoint, `GET /oauth-proxy-callback`.
   Mirrors `reference/packages/better-auth/src/plugins/oauth-proxy/index.ts`. A
   production (or preview) instance hands an *encrypted profile payload* to a
   preview instance via the `profile` query parameter; this endpoint decrypts it,
   validates required fields + freshness (``maxAge``), resolves/creates the
   user + session, sets the session cookie, and 302s to the final callback URL.
   On any failure it redirects to an error URL with ``?error=<code>``.

   NOTE: the *sending* side of the upstream design (the before/after hooks on
   ``/sign-in/social`` and ``/callback/:id`` that rewrite the OAuth ``state`` into
   an encrypted package and 302 the production callback to a preview) is **not**
   ported here. The Python core social flow signs (does not encrypt) its state,
   returns ``{url, redirect}``, and runs ``/callback/:provider`` as a single
   handler that exchanges the code + creates a session inline — there is no
   ``before`` hook seam on ``/callback/:id`` that can short-circuit with a
   redirect, and ``parse_state`` would reject an encrypted state package. Wiring
   that up requires core changes that are out of scope for this plugin, so those
   upstream tests are intentionally not ported (see the test module).

2. A self-contained SPA helper flow (Python-only extension): the SPA never sees
   the OAuth client_secret. ``POST /oauth-proxy/authorize`` returns an authorize
   URL + state; the provider redirects to ``GET /oauth-proxy/callback`` which
   exchanges the code, creates a session, and returns the user + session JSON.
   This flow requires ``providers`` to be configured.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.api.request import RedirectResponse
from kernia.context import create_session
from kernia.error import APIError
from kernia.oauth2 import pkce_verifier
from kernia.oauth2.link_account import handle_oauth_user_info
from kernia.oauth2.state import generate_state, parse_state
from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.types.context import AuthContext, EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

DEFAULT_MAX_AGE = 60  # seconds; matches upstream default


@dataclass(frozen=True, slots=True)
class OAuthProxyOptions:
    """Configuration for the OAuth proxy plugin.

    `max_age` is the maximum age (seconds) of an encrypted passthrough payload,
    matching upstream. `secret` is a dedicated encryption secret used **instead
    of** the global app secret for proxy encrypt/decrypt; when omitted the global
    secret is used. `providers` / `redirect_uri` configure the optional SPA helper
    flow only (they are not needed for the upstream passthrough endpoint).
    """

    providers: Mapping[str, OAuthProvider] | None = None
    redirect_uri: str | None = None
    success_callback_url: str | None = None
    trusted_providers: tuple[str, ...] = ()
    disable_sign_up: bool = False
    max_age: int = DEFAULT_MAX_AGE
    secret: str | None = None


# --------------------------------------------------------------------------------------
# Symmetric encryption (secret-keyed, reversible). Mirrors the core two-factor
# `_symmetric_encrypt`/`_symmetric_decrypt` scheme so the same primitive is used
# across the codebase without importing private helpers.
# --------------------------------------------------------------------------------------


def symmetric_encrypt(secret: str, data: str) -> str:
    key = hashlib.sha256(secret.encode()).digest()
    raw = data.encode()
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return base64.urlsafe_b64encode(out).rstrip(b"=").decode("ascii")


def symmetric_decrypt(secret: str, data: str) -> str:
    key = hashlib.sha256(secret.encode()).digest()
    padded = data + "=" * (-len(data) % 4)
    raw = base64.urlsafe_b64decode(padded)
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return out.decode()


# --------------------------------------------------------------------------------------
# Passthrough receiving endpoint: GET /oauth-proxy-callback
# --------------------------------------------------------------------------------------


def _strip_trailing_slash(url: str | None) -> str:
    if not url:
        return ""
    return url.rstrip("/")


def _redirect_on_error(error_url: str, error: str) -> RedirectResponse:
    sep = "&" if "?" in error_url else "?"
    return RedirectResponse(location=f"{error_url}{sep}error={error}")


def _encryption_key(opts: OAuthProxyOptions, ctx: EndpointContext) -> str:
    return opts.secret or ctx.auth.secret


async def _proxy_callback(ctx: EndpointContext) -> RedirectResponse:
    opts = _options(ctx.auth)
    base_url = _strip_trailing_slash(ctx.auth.base_url)
    default_error_url = f"{base_url}/api/auth/error"

    encrypted_profile = _q(ctx.request.query, "profile")
    if not encrypted_profile:
        return _redirect_on_error(default_error_url, "missing_profile")

    try:
        decrypted_payload = symmetric_decrypt(_encryption_key(opts, ctx), encrypted_profile)
    except Exception:
        return _redirect_on_error(default_error_url, "invalid_profile")

    try:
        payload = json.loads(decrypted_payload)
    except Exception:
        return _redirect_on_error(default_error_url, "invalid_payload")

    # Validate required payload fields (timestamp must be numeric).
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("timestamp"), int | float)
        or isinstance(payload.get("timestamp"), bool)
        or not payload.get("userInfo")
        or not payload.get("account")
        or not payload.get("callbackURL")
    ):
        return _redirect_on_error(default_error_url, "invalid_payload")

    error_url = payload.get("errorURL") or default_error_url

    # Freshness check. Allow up to 10s of future skew (matches upstream).
    now_ms = time.time() * 1000
    age = (now_ms - float(payload["timestamp"])) / 1000
    if age > opts.max_age or age < -10:
        return _redirect_on_error(error_url, "payload_expired")

    user_info = payload["userInfo"]
    account = payload["account"]
    profile = OAuthUserProfile(
        id=str(user_info.get("id")),
        email=user_info.get("email"),
        email_verified=bool(user_info.get("emailVerified", False)),
        name=user_info.get("name"),
        image=user_info.get("image"),
        raw=dict(user_info),
    )
    provider_id = str(account.get("providerId"))
    tokens: dict[str, Any] = {
        "access_token": account.get("accessToken"),
        "refresh_token": account.get("refreshToken"),
        "id_token": account.get("idToken"),
        "scope": account.get("scope"),
    }
    try:
        user, _ = await handle_oauth_user_info(
            ctx.auth,
            provider_id=provider_id,
            profile=profile,
            tokens=tokens,
            disable_sign_up=bool(payload.get("disableSignUp")),
            trusted_providers=opts.trusted_providers or (provider_id,),
        )
    except APIError:
        return _redirect_on_error(error_url, "user_creation_failed")

    _session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return RedirectResponse(location=payload["callbackURL"])


# --------------------------------------------------------------------------------------
# SPA helper flow (Python-only extension)
# --------------------------------------------------------------------------------------


class AuthorizeBody(BaseModel):
    provider: str
    callback_url: str | None = None


async def _authorize(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: AuthorizeBody = ctx.body
    providers = opts.providers or {}
    provider = providers.get(body.provider)
    if provider is None:
        raise APIError(400, "INVALID_REQUEST", message=f"unknown provider: {body.provider}")
    if not opts.redirect_uri:
        raise APIError(500, "INTERNAL", message="oauth-proxy redirect_uri not configured")
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
    providers = opts.providers or {}
    provider = providers.get(provider_id)
    if provider is None:
        raise APIError(400, "INVALID_REQUEST", message=f"unknown provider: {provider_id}")
    if not opts.redirect_uri:
        raise APIError(500, "INTERNAL", message="oauth-proxy redirect_uri not configured")
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


PROXY_CALLBACK = create_auth_endpoint(
    "/oauth-proxy-callback",
    EndpointOptions(method="GET"),
    _proxy_callback,
)

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
    endpoints: tuple[AuthEndpoint, ...] = field(
        default_factory=lambda: (PROXY_CALLBACK, AUTHORIZE, CALLBACK)
    )
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = field(
        default_factory=lambda: (RateLimitRule(path="/oauth-proxy/authorize", window=60, max=30),)
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: {})
    init: None = None


def oauth_proxy(options: OAuthProxyOptions | None = None) -> KerniaPlugin:
    """Construct the OAuth proxy plugin."""
    return _OAuthProxyPlugin(opts=options or OAuthProxyOptions())  # type: ignore[return-value]


__all__ = ["OAuthProxyOptions", "oauth_proxy", "symmetric_decrypt", "symmetric_encrypt"]
