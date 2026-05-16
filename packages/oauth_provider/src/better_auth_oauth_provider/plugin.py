"""OIDC / OAuth2 provider plugin construction.

Endpoints:
  * GET  /oauth2/authorize     — start an authorization-code flow
  * POST /oauth2/token         — exchange code / refresh for tokens
  * GET  /oauth2/userinfo      — Bearer access_token → claims
  * POST /oauth2/revoke        — RFC 7009
  * POST /oauth2/introspect    — RFC 7662
  * GET  /.well-known/openid-configuration — discovery
  * POST /oauth2/register      — RFC 7591 dynamic registration (gated)

Tokens are signed with the active JWK from the `jwt` plugin (shared key material).
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.oauth2 import pkce_challenge
from better_auth.plugins.jwt.plugin import issue_jwt, verify_local_jwt
from better_auth.types.adapter import FieldDef, ModelDef, Where
from better_auth.types.context import AuthContext, EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


# ----- schema -----

OAUTH_CLIENT_MODEL = ModelDef(
    name="oauthClient",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("clientId", "string", unique=True),
        FieldDef("clientSecret", "string", required=False),
        FieldDef("name", "string", required=False),
        FieldDef("redirectUris", "text"),
        FieldDef("allowedScopes", "text"),
        FieldDef("requirePKCE", "boolean", default=False),
        FieldDef("tokenEndpointAuthMethod", "string", default="client_secret_basic"),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


OAUTH_AUTHORIZATION_CODE_MODEL = ModelDef(
    name="oauthAuthorizationCode",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("code", "string", unique=True),
        FieldDef("clientId", "string"),
        FieldDef("userId", "string"),
        FieldDef("redirectUri", "string"),
        FieldDef("scope", "string"),
        FieldDef("codeChallenge", "string", required=False),
        FieldDef("codeChallengeMethod", "string", required=False),
        FieldDef("nonce", "string", required=False),
        FieldDef("expiresAt", "date"),
    ),
)


OAUTH_REFRESH_TOKEN_MODEL = ModelDef(
    name="oauthRefreshToken",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("token", "string", unique=True),
        FieldDef("clientId", "string"),
        FieldDef("userId", "string"),
        FieldDef("scope", "string"),
        FieldDef("expiresAt", "date"),
    ),
)


OAUTH_CONSENT_MODEL = ModelDef(
    name="oauthConsent",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string"),
        FieldDef("clientId", "string"),
        FieldDef("scope", "string"),
        FieldDef("createdAt", "date"),
    ),
)


@dataclass(frozen=True, slots=True)
class OAuthProviderOptions:
    issuer: str
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 30 * 24 * 3600
    code_ttl: int = 600
    supported_scopes: tuple[str, ...] = ("openid", "profile", "email", "offline_access")
    enable_dynamic_registration: bool = False
    require_pkce_for_public: bool = True


@dataclass(frozen=True, slots=True)
class OAuthClient:
    """Plain-data representation of a registered client."""

    client_id: str
    client_secret: str | None
    name: str | None
    redirect_uris: tuple[str, ...]
    allowed_scopes: tuple[str, ...]
    require_pkce: bool
    token_endpoint_auth_method: str

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "OAuthClient":
        return cls(
            client_id=row["clientId"],
            client_secret=row.get("clientSecret") or None,
            name=row.get("name"),
            redirect_uris=tuple((row.get("redirectUris") or "").split(",")),
            allowed_scopes=tuple((row.get("allowedScopes") or "").split(",")),
            require_pkce=bool(row.get("requirePKCE")),
            token_endpoint_auth_method=row.get("tokenEndpointAuthMethod")
            or "client_secret_basic",
        )


# ----- request bodies -----


class RegisterBody(BaseModel):
    name: str
    redirect_uris: list[str]
    allowed_scopes: list[str] = ["openid", "profile", "email"]
    require_pkce: bool = False
    token_endpoint_auth_method: str = "client_secret_basic"


class TokenBody(BaseModel):
    grant_type: str
    code: str | None = None
    redirect_uri: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    refresh_token: str | None = None
    scope: str | None = None
    code_verifier: str | None = None


class RevokeBody(BaseModel):
    token: str
    token_type_hint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class IntrospectBody(BaseModel):
    token: str
    token_type_hint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


# ----- helpers -----


def _options(auth: AuthContext) -> OAuthProviderOptions:
    for p in auth.plugins:
        if getattr(p, "id", None) == "oauth-provider":
            embedded = getattr(p, "opts", None)
            if isinstance(embedded, OAuthProviderOptions):
                return embedded
    raise APIError(500, "INTERNAL", message="oauth-provider plugin not configured")


async def _load_client(auth: AuthContext, client_id: str) -> OAuthClient:
    row = await auth.adapter.find_one(
        model="oauthClient",
        where=(Where(field="clientId", value=client_id),),
    )
    if row is None:
        raise APIError(401, "INVALID_REQUEST", message="unknown client")
    return OAuthClient.from_row(row)


def _q(qs: Mapping[str, Any], key: str) -> str | None:
    v = qs.get(key)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _client_auth(ctx: EndpointContext) -> tuple[str | None, str | None]:
    """Extract client_id/client_secret from Authorization: Basic OR body."""
    body = ctx.body
    client_id = getattr(body, "client_id", None)
    client_secret = getattr(body, "client_secret", None)
    if client_id and client_secret:
        return client_id, client_secret
    auth_header = ctx.request.headers.get("authorization", "")
    if auth_header.startswith("Basic "):
        import base64

        try:
            decoded = base64.b64decode(auth_header[len("Basic "):]).decode("utf-8")
        except Exception:
            return client_id, client_secret
        if ":" in decoded:
            cid, _, csec = decoded.partition(":")
            return cid or client_id, csec or client_secret
    return client_id, client_secret


# ----- handlers -----


async def _authorize(ctx: EndpointContext) -> dict[str, object]:
    """Authorization endpoint.

    Returns JSON describing the result of the request. A real browser flow would
    require a logged-in session and a consent step; we keep the contract simple:

      * If `ctx.session` is None → 401 (caller should show login)
      * Else → record the code and return the redirect URL
    """
    opts = _options(ctx.auth)
    qs = ctx.request.query
    response_type = _q(qs, "response_type") or "code"
    client_id = _q(qs, "client_id")
    redirect_uri = _q(qs, "redirect_uri")
    scope = _q(qs, "scope") or "openid"
    state = _q(qs, "state")
    code_challenge = _q(qs, "code_challenge")
    code_challenge_method = _q(qs, "code_challenge_method")
    nonce = _q(qs, "nonce")

    if response_type != "code":
        raise APIError(400, "INVALID_REQUEST", message="unsupported response_type")
    if not client_id or not redirect_uri:
        raise APIError(400, "INVALID_REQUEST")
    client = await _load_client(ctx.auth, client_id)
    if redirect_uri not in client.redirect_uris:
        raise APIError(400, "INVALID_REQUEST", message="redirect_uri not registered")
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED", message="login required")
    if client.require_pkce and not code_challenge:
        raise APIError(400, "INVALID_REQUEST", message="PKCE required")
    requested_scopes = [s for s in scope.split() if s]
    disallowed = set(requested_scopes) - set(client.allowed_scopes) - set(opts.supported_scopes)
    if disallowed:
        raise APIError(400, "INVALID_REQUEST", message=f"scope not allowed: {sorted(disallowed)}")

    code = secrets.token_urlsafe(32)
    now = int(time.time())
    await ctx.auth.adapter.create(
        model="oauthAuthorizationCode",
        data={
            "code": code,
            "clientId": client_id,
            "userId": ctx.session.user_id,
            "redirectUri": redirect_uri,
            "scope": " ".join(requested_scopes),
            "codeChallenge": code_challenge,
            "codeChallengeMethod": code_challenge_method or ("S256" if code_challenge else None),
            "nonce": nonce,
            "expiresAt": now + opts.code_ttl,
        },
    )
    # Remember consent (sticky)
    existing_consent = await ctx.auth.adapter.find_one(
        model="oauthConsent",
        where=(
            Where(field="userId", value=ctx.session.user_id),
            Where(field="clientId", value=client_id),
        ),
    )
    if existing_consent is None:
        await ctx.auth.adapter.create(
            model="oauthConsent",
            data={
                "userId": ctx.session.user_id,
                "clientId": client_id,
                "scope": " ".join(requested_scopes),
                "createdAt": now,
            },
        )

    params: dict[str, str] = {"code": code}
    if state:
        params["state"] = state
    redirect = f"{redirect_uri}?{urlencode(params)}"
    return {"redirect": redirect, "code": code, "state": state}


async def _token(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: TokenBody = ctx.body
    client_id, client_secret = _client_auth(ctx)
    if not client_id:
        raise APIError(401, "INVALID_REQUEST", message="client_id required")
    client = await _load_client(ctx.auth, client_id)

    # Auth: confidential clients require secret; public clients can omit if PKCE present.
    is_public = client.token_endpoint_auth_method == "none"
    if not is_public:
        if not client_secret or not client.client_secret or not secrets.compare_digest(
            client.client_secret, client_secret
        ):
            raise APIError(401, "INVALID_REQUEST", message="invalid client credentials")

    grant = body.grant_type
    now = int(time.time())

    if grant == "authorization_code":
        if not body.code or not body.redirect_uri:
            raise APIError(400, "INVALID_REQUEST", message="code+redirect_uri required")
        consume_one = getattr(ctx.auth.adapter, "consume_one", None)
        where = (Where(field="code", value=body.code),)
        if consume_one is None:
            record = await ctx.auth.adapter.find_one(
                model="oauthAuthorizationCode", where=where
            )
            if record:
                await ctx.auth.adapter.delete(model="oauthAuthorizationCode", where=where)
        else:
            record = await consume_one(model="oauthAuthorizationCode", where=where)
        if not record:
            raise APIError(400, "INVALID_REQUEST", message="invalid_grant")
        if int(record.get("expiresAt", 0)) < now:
            raise APIError(400, "INVALID_REQUEST", message="code expired")
        if record.get("clientId") != client_id:
            raise APIError(400, "INVALID_REQUEST", message="client mismatch")
        if record.get("redirectUri") != body.redirect_uri:
            raise APIError(400, "INVALID_REQUEST", message="redirect_uri mismatch")
        challenge = record.get("codeChallenge")
        if challenge:
            if not body.code_verifier:
                raise APIError(400, "INVALID_REQUEST", message="code_verifier required")
            method = record.get("codeChallengeMethod") or "S256"
            computed = (
                pkce_challenge(body.code_verifier) if method == "S256" else body.code_verifier
            )
            if computed != challenge:
                raise APIError(400, "INVALID_REQUEST", message="invalid_grant: PKCE")
        elif client.require_pkce or (is_public and opts.require_pkce_for_public):
            raise APIError(400, "INVALID_REQUEST", message="PKCE required")

        scope = record.get("scope") or ""
        user_id = record["userId"]
        return await _issue_tokens(
            ctx,
            opts,
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            nonce=record.get("nonce"),
        )

    if grant == "refresh_token":
        if not body.refresh_token:
            raise APIError(400, "INVALID_REQUEST", message="refresh_token required")
        row = await ctx.auth.adapter.find_one(
            model="oauthRefreshToken",
            where=(Where(field="token", value=body.refresh_token),),
        )
        if not row:
            raise APIError(400, "INVALID_REQUEST", message="invalid_grant")
        if row.get("clientId") != client_id:
            raise APIError(400, "INVALID_REQUEST", message="client mismatch")
        if int(row.get("expiresAt", 0)) < now:
            raise APIError(400, "INVALID_REQUEST", message="refresh token expired")
        # Rotate the refresh token
        await ctx.auth.adapter.delete(
            model="oauthRefreshToken",
            where=(Where(field="token", value=body.refresh_token),),
        )
        return await _issue_tokens(
            ctx,
            opts,
            client_id=client_id,
            user_id=row["userId"],
            scope=row.get("scope") or "",
        )

    if grant == "client_credentials":
        # Issue an access token bound to the client itself (no user).
        return await _issue_tokens(
            ctx,
            opts,
            client_id=client_id,
            user_id=f"client:{client_id}",
            scope=body.scope or "",
            include_id_token=False,
        )

    raise APIError(400, "INVALID_REQUEST", message="unsupported_grant_type")


async def _issue_tokens(
    ctx: EndpointContext,
    opts: OAuthProviderOptions,
    *,
    client_id: str,
    user_id: str,
    scope: str,
    nonce: str | None = None,
    include_id_token: bool = True,
) -> dict[str, object]:
    now = int(time.time())
    access_token, _kid = await issue_jwt(
        ctx.auth,
        payload={
            "sub": user_id,
            "aud": client_id,
            "iss": opts.issuer,
            "scope": scope,
            "jti": secrets.token_urlsafe(16),
        },
        ttl=opts.access_token_ttl,
    )
    out: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": opts.access_token_ttl,
        "scope": scope,
    }
    scopes = set(scope.split())
    if "offline_access" in scopes:
        refresh = secrets.token_urlsafe(48)
        await ctx.auth.adapter.create(
            model="oauthRefreshToken",
            data={
                "token": refresh,
                "clientId": client_id,
                "userId": user_id,
                "scope": scope,
                "expiresAt": now + opts.refresh_token_ttl,
            },
        )
        out["refresh_token"] = refresh
    if include_id_token and "openid" in scopes:
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=user_id),)
        )
        payload: dict[str, Any] = {
            "sub": user_id,
            "aud": client_id,
            "iss": opts.issuer,
        }
        if nonce:
            payload["nonce"] = nonce
        if user:
            if "email" in scopes and user.get("email"):
                payload["email"] = user["email"]
                payload["email_verified"] = bool(user.get("emailVerified", False))
            if "profile" in scopes and user.get("name"):
                payload["name"] = user["name"]
        id_token, _kid = await issue_jwt(ctx.auth, payload=payload, ttl=opts.access_token_ttl)
        out["id_token"] = id_token
    return out


async def _userinfo(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    auth_header = ctx.request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise APIError(401, "UNAUTHORIZED")
    token = auth_header[len("Bearer "):]
    try:
        claims = await verify_local_jwt(ctx.auth, token, issuer=opts.issuer)
    except ValueError as e:
        raise APIError(401, "UNAUTHORIZED", message=str(e)) from None
    sub = claims.get("sub")
    if not isinstance(sub, str):
        raise APIError(401, "UNAUTHORIZED")
    if sub.startswith("client:"):
        return {"sub": sub}
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=sub),)
    )
    if user is None:
        raise APIError(404, "USER_NOT_FOUND")
    out: dict[str, object] = {"sub": sub}
    scopes = set(str(claims.get("scope", "")).split())
    if "email" in scopes:
        out["email"] = user.get("email")
        out["email_verified"] = bool(user.get("emailVerified"))
    if "profile" in scopes:
        if user.get("name"):
            out["name"] = user["name"]
        if user.get("image"):
            out["picture"] = user["image"]
    return out


async def _revoke(ctx: EndpointContext) -> dict[str, object]:
    body: RevokeBody = ctx.body
    # Try refresh-token store
    await ctx.auth.adapter.delete_many(
        model="oauthRefreshToken",
        where=(Where(field="token", value=body.token),),
    )
    # RFC 7009: respond 200 regardless
    return {}


async def _introspect(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: IntrospectBody = ctx.body
    # Try as JWT access token
    try:
        claims = await verify_local_jwt(ctx.auth, body.token, issuer=opts.issuer)
        return {
            "active": True,
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
            "iss": claims.get("iss"),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "scope": claims.get("scope"),
            "token_type": "Bearer",
        }
    except ValueError:
        pass
    # Try as refresh token
    row = await ctx.auth.adapter.find_one(
        model="oauthRefreshToken",
        where=(Where(field="token", value=body.token),),
    )
    if row and int(row.get("expiresAt", 0)) > int(time.time()):
        return {
            "active": True,
            "sub": row.get("userId"),
            "client_id": row.get("clientId"),
            "scope": row.get("scope"),
            "exp": row.get("expiresAt"),
            "token_type": "refresh_token",
        }
    return {"active": False}


async def _discovery(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    base = opts.issuer.rstrip("/")
    return {
        "issuer": opts.issuer,
        "authorization_endpoint": f"{base}/oauth2/authorize",
        "token_endpoint": f"{base}/oauth2/token",
        "userinfo_endpoint": f"{base}/oauth2/userinfo",
        "jwks_uri": f"{base}/jwks",
        "revocation_endpoint": f"{base}/oauth2/revoke",
        "introspection_endpoint": f"{base}/oauth2/introspect",
        "registration_endpoint": f"{base}/oauth2/register"
        if opts.enable_dynamic_registration
        else None,
        "scopes_supported": list(opts.supported_scopes),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "id_token_signing_alg_values_supported": ["ES256", "RS256", "EdDSA"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "subject_types_supported": ["public"],
    }


async def _register(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    if not opts.enable_dynamic_registration:
        raise APIError(404, "NOT_FOUND")
    body: RegisterBody = ctx.body
    client_id = secrets.token_urlsafe(16)
    client_secret = (
        "" if body.token_endpoint_auth_method == "none" else secrets.token_urlsafe(32)
    )
    now = int(time.time())
    row = await ctx.auth.adapter.create(
        model="oauthClient",
        data={
            "clientId": client_id,
            "clientSecret": client_secret,
            "name": body.name,
            "redirectUris": ",".join(body.redirect_uris),
            "allowedScopes": ",".join(body.allowed_scopes),
            "requirePKCE": body.require_pkce,
            "tokenEndpointAuthMethod": body.token_endpoint_auth_method,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uris": body.redirect_uris,
        "allowed_scopes": body.allowed_scopes,
        "token_endpoint_auth_method": body.token_endpoint_auth_method,
        "client_name": body.name,
    }


# ----- endpoints -----


AUTHORIZE = create_auth_endpoint(
    "/oauth2/authorize",
    EndpointOptions(method="GET"),
    _authorize,
)
TOKEN = create_auth_endpoint(
    "/oauth2/token",
    EndpointOptions(method="POST", body=TokenBody),
    _token,
)
USERINFO = create_auth_endpoint(
    "/oauth2/userinfo",
    EndpointOptions(method="GET"),
    _userinfo,
)
REVOKE = create_auth_endpoint(
    "/oauth2/revoke",
    EndpointOptions(method="POST", body=RevokeBody),
    _revoke,
)
INTROSPECT = create_auth_endpoint(
    "/oauth2/introspect",
    EndpointOptions(method="POST", body=IntrospectBody),
    _introspect,
)
DISCOVERY = create_auth_endpoint(
    "/.well-known/openid-configuration",
    EndpointOptions(method="GET"),
    _discovery,
)
REGISTER = create_auth_endpoint(
    "/oauth2/register",
    EndpointOptions(method="POST", body=RegisterBody),
    _register,
)


_ENDPOINTS: tuple[AuthEndpoint, ...] = (
    AUTHORIZE,
    TOKEN,
    USERINFO,
    REVOKE,
    INTROSPECT,
    DISCOVERY,
    REGISTER,
)


@dataclass(frozen=True, slots=True)
class _OAuthProviderPlugin:
    opts: OAuthProviderOptions
    id: str = "oauth-provider"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(
            tables=(
                OAUTH_CLIENT_MODEL,
                OAUTH_AUTHORIZATION_CODE_MODEL,
                OAUTH_REFRESH_TOKEN_MODEL,
                OAUTH_CONSENT_MODEL,
            )
        )
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: _ENDPOINTS)
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = field(
        default_factory=lambda: (
            RateLimitRule(path="/oauth2/token", window=60, max=120),
            RateLimitRule(path="/oauth2/register", window=300, max=10),
        )
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: {})
    init: None = None


def oauth_provider(options: OAuthProviderOptions) -> BetterAuthPlugin:
    """Construct the OIDC/OAuth2 provider plugin."""
    return _OAuthProviderPlugin(opts=options)  # type: ignore[return-value]


async def create_client(
    auth: AuthContext,
    *,
    name: str,
    redirect_uris: Sequence[str],
    allowed_scopes: Sequence[str] = ("openid", "profile", "email"),
    require_pkce: bool = False,
    token_endpoint_auth_method: str = "client_secret_basic",
) -> OAuthClient:
    """Helper: register a client programmatically (no /register endpoint required)."""
    client_id = secrets.token_urlsafe(16)
    client_secret = "" if token_endpoint_auth_method == "none" else secrets.token_urlsafe(32)
    now = int(time.time())
    await auth.adapter.create(
        model="oauthClient",
        data={
            "clientId": client_id,
            "clientSecret": client_secret,
            "name": name,
            "redirectUris": ",".join(redirect_uris),
            "allowedScopes": ",".join(allowed_scopes),
            "requirePKCE": require_pkce,
            "tokenEndpointAuthMethod": token_endpoint_auth_method,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return OAuthClient(
        client_id=client_id,
        client_secret=client_secret or None,
        name=name,
        redirect_uris=tuple(redirect_uris),
        allowed_scopes=tuple(allowed_scopes),
        require_pkce=require_pkce,
        token_endpoint_auth_method=token_endpoint_auth_method,
    )


__all__ = [
    "oauth_provider",
    "OAuthProviderOptions",
    "OAuthClient",
    "create_client",
]
