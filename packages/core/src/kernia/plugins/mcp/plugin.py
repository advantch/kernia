"""MCP plugin construction.

The MCP plugin exposes:
  * POST /mcp/authorize {clientId, scope, resource} →
        {access_token, token_type, expires_in, resource}
  * GET /.well-known/oauth-authorization-server → MCP discovery doc

It re-uses the OIDC provider plugin's `oauthClient` registry for client lookup
and the JWT plugin's active key for signing the access token. Tokens include
the OAuth 2 Resource Indicator (RFC 8707) as the `aud` claim.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.plugins.jwt.plugin import issue_jwt, verify_local_jwt
from kernia.types.adapter import Where
from kernia.types.context import AuthContext, EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


@dataclass(frozen=True, slots=True)
class MCPOptions:
    """Configuration for the MCP plugin.

    `issuer` is the OAuth2/OIDC issuer (typically your auth base URL). `access_token_ttl`
    defaults to 1 day because MCP tokens are typically longer-lived than browser
    access tokens.
    """

    issuer: str
    access_token_ttl: int = 60 * 60 * 24  # 24h
    supported_scopes: tuple[str, ...] = ("openid", "profile", "email", "mcp:read", "mcp:write")


class MCPAuthorizeBody(BaseModel):
    client_id: str
    scope: str = ""
    resource: str | None = None
    user_id: str | None = None  # if not provided, falls back to ctx.session.user_id


# ----- handlers -----


async def _authorize(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: MCPAuthorizeBody = ctx.body
    client = await ctx.auth.adapter.find_one(
        model="oauthClient",
        where=(Where(field="clientId", value=body.client_id),),
    )
    if client is None:
        raise APIError(400, "INVALID_REQUEST", message="unknown client")

    user_id = body.user_id
    if user_id is None:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        user_id = ctx.session.user_id

    scopes = [s for s in body.scope.split() if s]
    allowed = set((client.get("allowedScopes") or "").split(","))
    invalid = [s for s in scopes if s not in allowed and s not in opts.supported_scopes]
    if invalid:
        raise APIError(400, "INVALID_REQUEST", message=f"scope not allowed: {invalid}")

    audience = body.resource or body.client_id
    payload: dict[str, Any] = {
        "sub": user_id,
        "iss": opts.issuer,
        "aud": audience,
        "client_id": body.client_id,
        "scope": " ".join(scopes),
        "jti": secrets.token_urlsafe(16),
    }
    if body.resource:
        # RFC 8707 resource indicator — also emitted as a top-level claim.
        payload["resource"] = body.resource
    token, kid = await issue_jwt(ctx.auth, payload=payload, ttl=opts.access_token_ttl)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": opts.access_token_ttl,
        "scope": " ".join(scopes),
        "resource": body.resource,
        "kid": kid,
    }


async def _well_known(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    base = opts.issuer.rstrip("/")
    return {
        "issuer": opts.issuer,
        "authorization_endpoint": f"{base}/mcp/authorize",
        "token_endpoint": f"{base}/mcp/authorize",
        "jwks_uri": f"{base}/jwks",
        "scopes_supported": list(opts.supported_scopes),
        "response_types_supported": ["token"],
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:mcp"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": [],
        "id_token_signing_alg_values_supported": ["ES256", "RS256", "EdDSA"],
        "resource_indicators_supported": True,
        "subject_types_supported": ["public"],
    }


def _options(auth: AuthContext) -> MCPOptions:
    for p in auth.plugins:
        if getattr(p, "id", None) == "mcp":
            embedded = getattr(p, "opts", None)
            if isinstance(embedded, MCPOptions):
                return embedded
    raise APIError(500, "INTERNAL", message="mcp plugin not configured")


# ----- helper exposed for callers -----


async def introspect_mcp_token(
    auth: AuthContext, token: str, *, expected_resource: str | None = None
) -> Mapping[str, Any]:
    """Verify an MCP access token against the local JWKS. Returns the claims.

    Raises `ValueError` if the token is invalid, expired, or has a mismatched
    `aud`/`resource` claim.
    """
    opts = _options(auth)
    claims = await verify_local_jwt(auth, token, issuer=opts.issuer)
    if expected_resource is not None:
        aud = claims.get("aud")
        if aud != expected_resource and not (
            isinstance(aud, list) and expected_resource in aud
        ):
            raise ValueError("resource mismatch")
    return claims


# ----- endpoints -----


AUTHORIZE = create_auth_endpoint(
    "/mcp/authorize",
    EndpointOptions(method="POST", body=MCPAuthorizeBody),
    _authorize,
)
WELL_KNOWN = create_auth_endpoint(
    "/.well-known/oauth-authorization-server",
    EndpointOptions(method="GET"),
    _well_known,
)


@dataclass(frozen=True, slots=True)
class _MCPPlugin:
    opts: MCPOptions
    id: str = "mcp"
    version: str | None = None
    schema: PluginSchema | None = None  # re-uses oidc-provider's tables
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: (AUTHORIZE, WELL_KNOWN))
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = field(
        default_factory=lambda: (RateLimitRule(path="/mcp/authorize", window=60, max=30),)
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: {})
    init: None = None


def mcp(options: MCPOptions) -> KerniaPlugin:
    """Construct the MCP plugin."""
    return _MCPPlugin(opts=options)  # type: ignore[return-value]


__all__ = ["mcp", "MCPOptions", "introspect_mcp_token"]
