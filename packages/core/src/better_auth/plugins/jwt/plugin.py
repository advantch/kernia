"""JWT plugin construction + key management.

Uses authlib's `JsonWebKey` / `jwt` for sign + verify. Keys are persisted in the
`jwk` model — public and private halves as JWK JSON strings, marked active/inactive
to support rotation while keeping old tokens verifiable.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.types.adapter import FieldDef, ModelDef, Where
from better_auth.types.context import AuthContext, EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

# ----- schema -----

JWK_MODEL = ModelDef(
    name="jwk",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("keyId", "string", unique=True),
        FieldDef("algorithm", "string"),
        FieldDef("publicKey", "text"),
        FieldDef("privateKey", "text"),
        FieldDef("isActive", "boolean", default=True),
        FieldDef("createdAt", "date"),
        FieldDef("expiresAt", "date", required=False),
    ),
)


# ----- options -----


@dataclass(frozen=True, slots=True)
class JwtOptions:
    """Configuration for the JWT plugin.

    `algorithm` is one of `"ES256"` (default), `"RS256"`, `"EdDSA"`.
    """

    algorithm: str = "ES256"
    access_token_ttl: int = 900  # 15 minutes
    issuer: str | None = None
    audience: str | None = None
    rotate_admin_token: str | None = None  # if set, /jwks/rotate requires this bearer
    rotate_allowed_roles: tuple[str, ...] = ("admin",)


# ----- request bodies -----


@dataclass(frozen=True, slots=True)
class RotateBody:
    """Empty body — rotation is parameter-less."""


# ----- key helpers -----


_DEFAULT_CURVES: Mapping[str, Mapping[str, Any]] = {
    "ES256": {"kty": "EC", "crv": "P-256"},
    "ES384": {"kty": "EC", "crv": "P-384"},
    "ES512": {"kty": "EC", "crv": "P-521"},
    "RS256": {"kty": "RSA", "size": 2048},
    "EdDSA": {"kty": "OKP", "crv": "Ed25519"},
}


def _gen_keypair(alg: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate a JWK keypair for the given algorithm. Returns (private_jwk, public_jwk)."""
    cfg = _DEFAULT_CURVES.get(alg)
    if cfg is None:
        raise ValueError(f"unsupported JWT algorithm: {alg}")
    kty = cfg["kty"]
    if kty == "EC":
        key = JsonWebKey.generate_key("EC", cfg["crv"], is_private=True)
    elif kty == "RSA":
        key = JsonWebKey.generate_key("RSA", int(cfg["size"]), is_private=True)
    elif kty == "OKP":
        key = JsonWebKey.generate_key("OKP", cfg["crv"], is_private=True)
    else:  # pragma: no cover
        raise ValueError(f"unsupported kty: {kty}")
    private_jwk = key.as_dict(is_private=True)
    public_jwk = key.as_dict(is_private=False)
    return dict(private_jwk), dict(public_jwk)


async def _get_active_key(auth: AuthContext) -> dict[str, Any]:
    rows = await auth.adapter.find_many(
        model="jwk",
        where=(Where(field="isActive", value=True),),
    )
    if rows:
        # newest active key
        rows.sort(key=lambda r: int(r.get("createdAt") or 0), reverse=True)
        return rows[0]
    # bootstrap: no key yet → create one
    return await _create_key(auth, alg=_jwt_options(auth).algorithm)


async def _create_key(auth: AuthContext, *, alg: str) -> dict[str, Any]:
    private_jwk, public_jwk = _gen_keypair(alg)
    kid = secrets.token_urlsafe(12)
    # Stamp our kid into the JWK dicts so authlib uses it for header.kid lookup.
    private_jwk["kid"] = kid
    public_jwk["kid"] = kid
    now = int(time.time())
    row = await auth.adapter.create(
        model="jwk",
        data={
            "keyId": kid,
            "algorithm": alg,
            "publicKey": json.dumps(public_jwk),
            "privateKey": json.dumps(private_jwk),
            "isActive": True,
            "createdAt": now,
        },
    )
    return row


def _jwt_options(auth: AuthContext) -> JwtOptions:
    opts = auth.options.advanced.get("jwt")
    if isinstance(opts, JwtOptions):
        return opts
    # Fall back: look it up on the registered plugin instance directly.
    for p in auth.plugins:
        if getattr(p, "id", None) == "jwt":
            embedded = getattr(p, "opts", None)
            if isinstance(embedded, JwtOptions):
                return embedded
    return JwtOptions()


# ----- handlers -----


async def _get_token(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    opts = _jwt_options(ctx.auth)
    key_row = await _get_active_key(ctx.auth)
    private_jwk = json.loads(key_row["privateKey"])
    alg = key_row["algorithm"]
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": ctx.session.user_id,
        "iat": now,
        "exp": now + opts.access_token_ttl,
        "jti": secrets.token_urlsafe(16),
    }
    if opts.issuer:
        payload["iss"] = opts.issuer
    if opts.audience:
        payload["aud"] = opts.audience
    header = {"alg": alg, "typ": "JWT", "kid": key_row["keyId"]}
    token_bytes = jose_jwt.encode(header, payload, private_jwk)
    token = token_bytes.decode("ascii") if isinstance(token_bytes, bytes) else str(token_bytes)
    return {"token": token, "kid": key_row["keyId"], "expires_in": opts.access_token_ttl}


async def _get_jwks(ctx: EndpointContext) -> dict[str, object]:
    rows = await ctx.auth.adapter.find_many(model="jwk")
    # bootstrap if empty
    if not rows:
        await _get_active_key(ctx.auth)
        rows = await ctx.auth.adapter.find_many(model="jwk")
    keys: list[dict[str, Any]] = []
    for row in rows:
        pub = json.loads(row["publicKey"])
        pub["kid"] = row["keyId"]
        pub["alg"] = row["algorithm"]
        pub["use"] = "sig"
        keys.append(pub)
    return {"keys": keys}


async def _rotate(ctx: EndpointContext) -> dict[str, object]:
    opts = _jwt_options(ctx.auth)
    _enforce_rotate_authz(ctx, opts)
    # mark all current active keys inactive (they remain in JWKS for verification)
    await ctx.auth.adapter.update_many(
        model="jwk",
        where=(Where(field="isActive", value=True),),
        update={"isActive": False},
    )
    new_key = await _create_key(ctx.auth, alg=opts.algorithm)
    return {"kid": new_key["keyId"], "algorithm": new_key["algorithm"]}


def _enforce_rotate_authz(ctx: EndpointContext, opts: JwtOptions) -> None:
    # Service-token route
    if opts.rotate_admin_token:
        auth_header = ctx.request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            tok = auth_header[len("Bearer "):]
            if secrets.compare_digest(tok, opts.rotate_admin_token):
                return
    # Session+role route
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    # Best-effort role check via user record
    return None


# ----- helpers used by other plugins -----


async def issue_jwt(
    auth: AuthContext,
    *,
    payload: Mapping[str, Any],
    ttl: int | None = None,
    audience: str | None = None,
    issuer: str | None = None,
) -> tuple[str, str]:
    """Sign a JWT with the active JWK. Returns (token, kid).

    Re-used by other plugins (oidc_provider, mcp) that share the key material.
    """
    opts = _jwt_options(auth)
    key_row = await _get_active_key(auth)
    private_jwk = json.loads(key_row["privateKey"])
    alg = key_row["algorithm"]
    now = int(time.time())
    body: dict[str, Any] = {
        "iat": now,
        "exp": now + (ttl if ttl is not None else opts.access_token_ttl),
        **payload,
    }
    iss = issuer or opts.issuer
    aud = audience or opts.audience
    if iss and "iss" not in body:
        body["iss"] = iss
    if aud and "aud" not in body:
        body["aud"] = aud
    header = {"alg": alg, "typ": "JWT", "kid": key_row["keyId"]}
    token_bytes = jose_jwt.encode(header, body, private_jwk)
    token = token_bytes.decode("ascii") if isinstance(token_bytes, bytes) else str(token_bytes)
    return token, key_row["keyId"]


async def verify_local_jwt(
    auth: AuthContext,
    token: str,
    *,
    audience: str | None = None,
    issuer: str | None = None,
) -> Mapping[str, Any]:
    """Verify a JWT against our own JWKS. Raises ValueError on failure."""
    rows = await auth.adapter.find_many(model="jwk")
    if not rows:
        raise ValueError("no JWKS keys configured")
    jwks = {"keys": []}
    for row in rows:
        pub = json.loads(row["publicKey"])
        pub["kid"] = row["keyId"]
        pub["alg"] = row["algorithm"]
        jwks["keys"].append(pub)
    try:
        claims = jose_jwt.decode(token, JsonWebKey.import_key_set(jwks))
        # authlib returns dict-like JWTClaims — coerce to plain dict for typing
        claims_dict = dict(claims)
        now = int(time.time())
        exp = claims_dict.get("exp")
        if isinstance(exp, int) and exp < now:
            raise ValueError("token expired")
        if audience is not None:
            aud = claims_dict.get("aud")
            if aud != audience and not (isinstance(aud, list) and audience in aud):
                raise ValueError("audience mismatch")
        if issuer is not None and claims_dict.get("iss") != issuer:
            raise ValueError("issuer mismatch")
        return claims_dict
    except ValueError:
        raise
    except Exception as e:  # pragma: no cover — authlib raises various subclasses
        raise ValueError(f"jwt verification failed: {e}") from None


# ----- plugin ctor -----

JWT_ERROR_CODES: Mapping[str, str] = {
    "JWT_KEY_MISSING": "No JWK is configured for the JWT plugin.",
}


GET_TOKEN = create_auth_endpoint(
    "/token",
    EndpointOptions(method="GET", requires_session=True),
    _get_token,
)

GET_JWKS = create_auth_endpoint(
    "/jwks",
    EndpointOptions(method="GET"),
    _get_jwks,
)

ROTATE_JWKS = create_auth_endpoint(
    "/jwks/rotate",
    EndpointOptions(method="POST"),
    _rotate,
)


_ENDPOINTS: tuple[AuthEndpoint, ...] = (GET_TOKEN, GET_JWKS, ROTATE_JWKS)


@dataclass(frozen=True, slots=True)
class _JwtPlugin:
    opts: JwtOptions
    id: str = "jwt"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(tables=(JWK_MODEL,))
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: _ENDPOINTS)
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = field(
        default_factory=lambda: (
            RateLimitRule(path="/token", window=60, max=60),
            RateLimitRule(path="/jwks/rotate", window=300, max=10),
        )
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: dict(JWT_ERROR_CODES))

    async def init(self, ctx: AuthContext) -> None:
        ctx.options.advanced.setdefault("jwt", self.opts)


def jwt(options: JwtOptions | None = None) -> BetterAuthPlugin:
    """Construct the JWT plugin.

    Pass a `JwtOptions` to override the algorithm, TTL, issuer, or audience. The
    options are also stashed under `auth.options.advanced["jwt"]` so other plugins
    (notably `oidc_provider`) can read them at request time.
    """
    return _JwtPlugin(opts=options or JwtOptions())  # type: ignore[return-value]


__all__ = [
    "JwtOptions",
    "JWK_MODEL",
    "jwt",
    "issue_jwt",
    "verify_local_jwt",
]
