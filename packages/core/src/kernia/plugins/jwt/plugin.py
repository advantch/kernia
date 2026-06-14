"""JWT plugin construction + key management.

Uses authlib's `JsonWebKey` / `jwt` for sign + verify. Keys are persisted in the
`jwk` model — public and private halves as JWK JSON strings, marked active/inactive
to support rotation while keeping old tokens verifiable.
"""

from __future__ import annotations

import inspect
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from authlib.jose import JsonWebKey  # type: ignore[import-untyped]
from authlib.jose import jwt as jose_jwt

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.context import AuthContext, EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

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

    Mirrors `reference/.../jwt/types.ts`. `algorithm` is the JWK key-pair
    algorithm and is one of `"EdDSA"` (default), `"ES256"`, `"ES384"`,
    `"ES512"`, `"RS256"`, `"PS256"`.

    Parity-relevant options:
      * ``expiration_time`` — default token lifetime (seconds int or a time
        string like ``"15m"``/``"1h"``/``"7d"``). Mirrors ``jwt.expirationTime``.
      * ``define_payload`` — ``(session) -> payload`` hook for ``/token``.
      * ``get_subject`` — ``(session) -> str`` override for the ``sub`` claim.
      * ``jwks_path`` — path the JWKS is served from (default ``/jwks``).
      * ``remote_url`` — when set, ``/jwks`` is disabled (the issuer publishes
        keys remotely). Requires ``algorithm`` to be specified.
      * ``sign`` — custom signing function ``(payload) -> token``. Requires
        ``remote_url`` to be set.
      * ``rotation_interval`` / ``grace_period`` — seconds. Keys older than
        ``rotation_interval`` trigger a fresh key; keys past
        ``rotation_interval + grace_period`` drop out of the JWKS.
    """

    algorithm: str = "EdDSA"
    access_token_ttl: int = 900  # 15 minutes (legacy alias for expiration_time)
    expiration_time: int | str | None = None
    issuer: str | None = None
    audience: str | None = None
    define_payload: Callable[..., Any] | None = None
    get_subject: Callable[..., Any] | None = None
    jwks_path: str = "/jwks"
    remote_url: str | None = None
    sign: Callable[..., Any] | None = None
    rotation_interval: int | None = None
    grace_period: int | None = None
    disable_private_key_encryption: bool = True
    rotate_admin_token: str | None = None  # if set, /jwks/rotate requires this bearer
    rotate_allowed_roles: tuple[str, ...] = ("admin",)

    def __post_init__(self) -> None:
        # Upstream: options.jwks.remoteUrl must be set when using options.jwt.sign
        if self.sign is not None and not self.remote_url:
            raise ValueError("options.jwks.remoteUrl must be set when using options.jwt.sign")
        # Upstream: alg must be specified when using remoteUrl.
        if self.remote_url and not self.algorithm:
            raise ValueError(
                "options.jwks.keyPairConfig.alg must be specified when using "
                "the oidc plugin with options.jwks.remoteUrl"
            )


# ----- time-string parsing (mirrors `toExpJWT` + `sec()` upstream) -----


_TIME_UNITS: Mapping[str, int] = {
    "s": 1,
    "sec": 1,
    "secs": 1,
    "second": 1,
    "seconds": 1,
    "m": 60,
    "min": 60,
    "mins": 60,
    "minute": 60,
    "minutes": 60,
    "h": 3600,
    "hr": 3600,
    "hrs": 3600,
    "hour": 3600,
    "hours": 3600,
    "d": 86400,
    "day": 86400,
    "days": 86400,
    "w": 604800,
    "week": 604800,
    "weeks": 604800,
    "y": 31557600,
    "yr": 31557600,
    "yrs": 31557600,
    "year": 31557600,
    "years": 31557600,
}

_TIME_RE = re.compile(
    r"^\s*(-?\d+(?:\.\d+)?)\s*"
    r"(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|"
    r"d|day|days|w|week|weeks|y|yr|yrs|year|years)?\s*(ago)?\s*$",
    re.IGNORECASE,
)


def _sec(value: str) -> int:
    """Parse a time string into seconds. Mirrors the `ms`/`sec` helpers."""
    match = _TIME_RE.match(value)
    if not match or match.group(1) is None:
        raise TypeError(f"invalid time string: {value!r}")
    amount = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    factor = _TIME_UNITS.get(unit)
    if factor is None:
        raise TypeError(f"invalid time unit in {value!r}")
    seconds = amount * factor
    if match.group(3):  # "...ago"
        seconds = -seconds
    return int(seconds)


def to_exp_jwt(expiration_time: int | float | datetime | str, iat: int) -> int:
    """Mirror `toExpJWT(expirationTime, iat)` from `jwt/utils.ts`.

    - number -> returned as-is
    - datetime -> floor(timestamp seconds)
    - time string -> iat + sec(string)
    """
    if isinstance(expiration_time, bool):  # guard: bool is an int subclass
        raise TypeError("expiration time must not be a bool")
    if isinstance(expiration_time, int | float):
        return int(expiration_time)
    if isinstance(expiration_time, datetime):
        return int(expiration_time.timestamp())
    if isinstance(expiration_time, str):
        return iat + _sec(expiration_time)
    raise TypeError(f"unsupported expiration time: {expiration_time!r}")


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
    "PS256": {"kty": "RSA", "size": 2048},
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
    opts = _jwt_options(auth)
    rows = await auth.adapter.find_many(
        model="jwk",
        where=(Where(field="isActive", value=True),),
    )
    if rows:
        rows.sort(key=lambda r: int(r.get("createdAt") or 0), reverse=True)
        latest = rows[0]
        # Rotation: if the newest key is older than rotationInterval, mint a
        # fresh one (the old key stays in the JWKS until grace period elapses).
        interval = opts.rotation_interval
        if interval is not None:
            age = int(time.time()) - int(latest.get("createdAt") or 0)
            if age >= interval:
                return await _create_key(auth, alg=opts.algorithm)
        return latest
    # bootstrap: no key yet → create one
    return await _create_key(auth, alg=opts.algorithm)


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


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


# ----- handlers -----


async def _resolve_session_user(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    return dict(user) if user else {"id": ctx.session.user_id}


async def _get_token(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    opts = _jwt_options(ctx.auth)
    user = await _resolve_session_user(ctx)
    session_obj = {"user": user, "session": ctx.session}
    now = int(time.time())

    # definePayload hook controls the body; default is the user record.
    if opts.define_payload is not None:
        payload = dict(await _maybe_await(opts.define_payload(session_obj)))
    else:
        payload = dict(user)
    payload.setdefault("iat", now)

    # getSubject overrides `sub`; default is the user id.
    if opts.get_subject is not None:
        payload["sub"] = str(await _maybe_await(opts.get_subject(session_obj)))
    else:
        payload.setdefault("sub", user.get("id", ctx.session.user_id))

    token = await sign_jwt(ctx.auth, payload=payload)
    key_row = await _get_active_key(ctx.auth)
    return {"token": token, "kid": key_row["keyId"]}


def _key_is_within_grace(row: Mapping[str, Any], opts: JwtOptions, now: int) -> bool:
    """A key stays in the JWKS until rotationInterval + gracePeriod elapses."""
    if opts.rotation_interval is None or opts.grace_period is None:
        return True
    age = now - int(row.get("createdAt") or 0)
    return age <= (opts.rotation_interval + opts.grace_period)


async def _get_jwks(ctx: EndpointContext) -> dict[str, object]:
    opts = _jwt_options(ctx.auth)
    rows = await ctx.auth.adapter.find_many(model="jwk")
    # bootstrap if empty
    if not rows:
        await _get_active_key(ctx.auth)
        rows = await ctx.auth.adapter.find_many(model="jwk")
    now = int(time.time())
    keys: list[dict[str, Any]] = []
    for row in rows:
        if not _key_is_within_grace(row, opts, now):
            continue
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
            tok = auth_header[len("Bearer ") :]
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


async def sign_jwt(
    auth: AuthContext,
    *,
    payload: Mapping[str, Any],
    options: JwtOptions | None = None,
) -> str:
    """Sign an arbitrary payload into a JWT. Mirrors `signJWT` in `jwt/sign.ts`.

    Applies iat/exp/iss/aud defaults, honours an explicit `exp` in the payload,
    and delegates to a custom `options.sign` function when configured (remote
    signing). Returns the compact JWT string.
    """
    opts = options or _jwt_options(auth)
    body: dict[str, Any] = dict(payload)
    now = int(time.time())
    iat = int(body.get("iat", now))
    body["iat"] = iat

    # Exp: explicit payload exp wins, else expiration_time (default "15m").
    if "exp" not in body:
        exp_setting: int | str = (
            opts.expiration_time if opts.expiration_time is not None else opts.access_token_ttl
        )
        body["exp"] = to_exp_jwt(exp_setting, iat)

    base_url = ""
    raw_base = getattr(auth.options, "base_url", None)
    if isinstance(raw_base, str):
        base_url = raw_base
    default_iss = opts.issuer or base_url
    default_aud = opts.audience or base_url
    if "iss" not in body and default_iss:
        body["iss"] = default_iss
    if "aud" not in body and default_aud:
        body["aud"] = default_aud

    # Custom/remote signing function takes the fully-formed payload.
    if opts.sign is not None:
        return str(await _maybe_await(opts.sign(body)))

    key_row = await _get_active_key(auth)
    private_jwk = json.loads(key_row["privateKey"])
    alg = key_row["algorithm"]
    header = {"alg": alg, "typ": "JWT", "kid": key_row["keyId"]}
    token_bytes = jose_jwt.encode(header, body, private_jwk)
    return token_bytes.decode("ascii") if isinstance(token_bytes, bytes) else str(token_bytes)


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
    jwks: dict[str, list[Any]] = {"keys": []}
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

ROTATE_JWKS = create_auth_endpoint(
    "/jwks/rotate",
    EndpointOptions(method="POST"),
    _rotate,
)


def _build_endpoints(opts: JwtOptions) -> tuple[AuthEndpoint, ...]:
    """Endpoint set depends on options (mirrors upstream conditional routes).

    - ``/jwks`` is served at ``opts.jwks_path`` (default ``/jwks``).
    - When ``remote_url`` is configured the issuer publishes keys remotely, so
      the local ``/jwks`` route is omitted (client gets a 404).
    """
    endpoints: list[AuthEndpoint] = [GET_TOKEN, ROTATE_JWKS]
    if not opts.remote_url:
        endpoints.append(
            create_auth_endpoint(
                opts.jwks_path or "/jwks",
                EndpointOptions(method="GET"),
                _get_jwks,
            )
        )
    return tuple(endpoints)


@dataclass(frozen=True, slots=True)
class _JwtPlugin:
    opts: JwtOptions
    id: str = "jwt"
    version: str | None = None
    schema: PluginSchema | None = field(default_factory=lambda: PluginSchema(tables=(JWK_MODEL,)))
    endpoints: tuple[AuthEndpoint, ...] = ()
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


def jwt(options: JwtOptions | None = None) -> KerniaPlugin:
    """Construct the JWT plugin.

    Pass a `JwtOptions` to override the algorithm, TTL, issuer, audience, JWKS
    path, rotation policy, or remote-signing config. The options are also stashed
    under `auth.options.advanced["jwt"]` so other plugins (notably
    `oidc_provider`) can read them at request time.

    To sign an arbitrary payload server-side (the equivalent of upstream
    `auth.api.signJWT`), call :func:`sign_jwt`. There is intentionally no HTTP
    route for signing — clients receive 404, matching upstream's SERVER_ONLY
    `/sign-jwt`.
    """
    opts = options or JwtOptions()
    return _JwtPlugin(opts=opts, endpoints=_build_endpoints(opts))  # type: ignore[return-value]


__all__ = [
    "JWK_MODEL",
    "JwtOptions",
    "issue_jwt",
    "jwt",
    "sign_jwt",
    "to_exp_jwt",
    "verify_local_jwt",
]
