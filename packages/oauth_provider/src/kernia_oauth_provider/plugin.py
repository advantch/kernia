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

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.oauth2 import pkce_challenge
from kernia.plugins.jwt.plugin import issue_jwt, verify_local_jwt
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.context import AuthContext, EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


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
        FieldDef("requirePKCE", "boolean", default=True),
        FieldDef("tokenEndpointAuthMethod", "string", default="client_secret_basic"),
        FieldDef("subjectType", "string", required=False),
        # Administratively disabled clients are rejected at every credentialed
        # endpoint (token/introspect/revoke) with `invalid_client`, mirroring
        # upstream's `disabled` flag on `oauthApplication`.
        FieldDef("disabled", "boolean", default=False, required=False),
        # RP-initiated logout (OIDC `end_session_endpoint`). `enableEndSession`
        # is a privileged flag — only settable when a client is created by an
        # admin, never through dynamic registration — that opts a client into
        # the `sid` id_token claim and the end-session endpoint.
        # `postLogoutRedirectUris` (CSV) whitelists `post_logout_redirect_uri`.
        FieldDef("enableEndSession", "boolean", default=False, required=False),
        FieldDef("postLogoutRedirectUris", "text", required=False),
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
        # The authenticating user's session id, captured at authorize time so
        # the issued id_token can carry an `sid` claim (RP-initiated logout).
        FieldDef("sessionId", "string", required=False),
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
        # The issuing session id, surfaced as the `sid` introspection claim
        # (validated against a live session) and carried across rotation.
        FieldDef("sessionId", "string", required=False),
        FieldDef("expiresAt", "date"),
        # RFC 9700 §4.14 reuse detection: rotated tokens are marked revoked
        # (not deleted) so a later replay of a consumed token is detectable and
        # tears down the whole family. `None` means live.
        FieldDef("revoked", "date", required=False),
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


# Opaque access tokens. Upstream issues opaque (reference) access tokens by
# default and only mints a self-contained JWT when an audience/`resource` is
# present; this port defaults to JWTs (``jwt_access_token=True``) but supports
# the opaque model when that option is disabled, so introspection / userinfo /
# revocation can be exercised against reference tokens too. Per upstream's
# schema doc, access tokens are created at issuance, read at introspection, and
# destroyed at revoke — never updated.
OAUTH_ACCESS_TOKEN_MODEL = ModelDef(
    name="oauthAccessToken",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("token", "string", unique=True),
        FieldDef("clientId", "string"),
        FieldDef("userId", "string", required=False),
        # The subject as presented to the client (pairwise-resolved); kept so
        # introspection/userinfo agree with the id_token without re-deriving it.
        FieldDef("azp", "string", required=False),
        FieldDef("scope", "string"),
        # The issuing session id, surfaced as the `sid` introspection claim
        # (validated against a live session at introspection time).
        FieldDef("sessionId", "string", required=False),
        FieldDef("expiresAt", "date"),
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
    # How client secrets are kept at rest. "hashed" (default, mirrors upstream
    # `storeClientSecret: "hashed"`) stores only a SHA-256 digest so a DB leak
    # never exposes usable secrets. "plain" keeps the legacy behaviour.
    store_client_secret: str = "hashed"
    # How refresh tokens are kept at rest. "hashed" (default, mirrors upstream
    # `storeTokens: "hashed"`) means the raw token never lands in the DB.
    store_tokens: str = "hashed"
    # Access-token format. When True (this port's default) the access token is a
    # self-contained EdDSA JWT verified statelessly. When False the server mints
    # an opaque reference token persisted in `oauthAccessToken` and validated by
    # DB lookup — mirroring upstream's default opaque-token model. Introspection,
    # userinfo and revocation transparently accept either format.
    jwt_access_token: bool = True
    # Optional fixed prefixes for opaque tokens (mirror upstream
    # `accessTokenPrefix` / `refreshTokenPrefix`). Stored hashed, so the prefix
    # is only visible on the wire — it aids token-type heuristics for clients.
    opaque_access_token_prefix: str = ""
    refresh_token_prefix: str = ""
    # Secret used to compute pairwise subject identifiers (HMAC-SHA256).
    # When set (min 32 chars), clients with `subject_type: "pairwise"` receive
    # unique, unlinkable `sub` values per sector identifier.
    # @see https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
    pairwise_secret: str | None = None
    # Overwrite advertised `scopes_supported` / `claims_supported` in metadata.
    advertised_scopes_supported: tuple[str, ...] | None = None
    advertised_claims_supported: tuple[str, ...] | None = None
    # Grant types supported by the token endpoint.
    grant_types: tuple[str, ...] = (
        "authorization_code",
        "client_credentials",
        "refresh_token",
    )
    # Per-endpoint rate-limit overrides (mirror upstream `rateLimit`). Keys are
    # endpoint names (``token``, ``authorize``, ``introspect``, ``revoke``,
    # ``register``, ``userinfo``); each value is either ``{"window": int,
    # "max": int}`` to override the default, or ``False`` to disable the rule
    # for that endpoint entirely. Unspecified endpoints keep their defaults.
    rate_limit: Mapping[str, Mapping[str, int] | bool] | None = None

    def __post_init__(self) -> None:
        # Mirror upstream `BetterAuthError("pairwiseSecret must be at least 32
        # characters long for adequate HMAC-SHA256 security")`.
        if self.pairwise_secret is not None and len(self.pairwise_secret) < 32:
            raise ValueError(
                "pairwiseSecret must be at least 32 characters long for "
                "adequate HMAC-SHA256 security"
            )
        # Mirror upstream: every advertised scope must be a supported scope.
        if self.advertised_scopes_supported is not None:
            for scope in self.advertised_scopes_supported:
                if scope not in self.supported_scopes:
                    raise ValueError(
                        f"advertisedMetadata.scopes_supported {scope} not found "
                        f"in scopes"
                    )


# PKCE requirement reasons (mirror upstream `PKCERequirementErrors`).
PKCE_PUBLIC_CLIENT = "pkce is required for public clients"
PKCE_OFFLINE_ACCESS = "pkce is required when requesting offline_access scope"
PKCE_CLIENT_REQUIRE = "pkce is required for this client"


def _pkce_required(client: OAuthClient, requested_scopes: Sequence[str]) -> str | None:
    """Return a non-None reason string when PKCE is mandatory for this request.

    Mirrors upstream `isPKCERequired`:
      * public clients (token_endpoint_auth_method == "none") always require PKCE,
      * any request that asks for `offline_access` requires PKCE,
      * confidential clients require PKCE unless `require_pkce` was explicitly
        disabled (upstream default is `requirePKCE ?? true`).
    """
    is_public = client.token_endpoint_auth_method == "none"
    if is_public:
        return PKCE_PUBLIC_CLIENT
    if "offline_access" in requested_scopes:
        return PKCE_OFFLINE_ACCESS
    if client.require_pkce:
        return PKCE_CLIENT_REQUIRE
    return None


def _oauth_error(
    status: int, error: str, description: str | None = None
) -> APIError:
    """Build an APIError carrying the OAuth `{error, error_description}` envelope
    in its `data` payload, mirroring upstream's `new APIError(status, {error, ...})`.
    """
    data: dict[str, object] = {"error": error}
    if description is not None:
        data["error_description"] = description
    code = "UNAUTHORIZED" if status == 401 else "INVALID_REQUEST"
    return APIError(status, code, message=description or error, data=data)


def _sha256_b64url(value: str) -> str:
    """SHA-256 → unpadded base64url. Matches `@better-auth/utils` `createHash`."""
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _store_secret(method: str, secret: str) -> str:
    """Transform a freshly-minted secret/token into its at-rest representation."""
    if method == "hashed":
        return _sha256_b64url(secret)
    return secret


def _verify_secret(method: str, presented: str, stored: str) -> bool:
    """Constant-time check of a presented secret against its stored form."""
    candidate = _sha256_b64url(presented) if method == "hashed" else presented
    return hmac.compare_digest(candidate, stored)


def _hmac_sha256_b64url(value: str, secret: str) -> str:
    """HMAC-SHA256 → unpadded base64url. Mirrors `@better-auth/crypto` `makeSignature`."""
    mac = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).rstrip(b"=").decode("ascii")


def _sector_identifier(client: OAuthClient) -> str:
    """Extract the sector identifier (host) from a client's first redirect URI.

    @see https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
    """
    if not client.redirect_uris or not client.redirect_uris[0]:
        raise ValueError("Client has no redirect URIs for sector identifier")
    from urllib.parse import urlsplit

    return urlsplit(client.redirect_uris[0]).netloc


def _resolve_sub(
    user_id: str, client: OAuthClient, opts: OAuthProviderOptions
) -> str:
    """Return the subject identifier for a user+client pair.

    Uses a pairwise (sector-scoped HMAC) identifier when the client opts in and
    a `pairwise_secret` is configured; otherwise returns the raw user id.
    """
    if client.subject_type == "pairwise" and opts.pairwise_secret:
        sector = _sector_identifier(client)
        return _hmac_sha256_b64url(f"{sector}.{user_id}", opts.pairwise_secret)
    return user_id


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
    subject_type: str | None = None
    disabled: bool = False
    enable_end_session: bool = False
    post_logout_redirect_uris: tuple[str, ...] = ()

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> OAuthClient:
        post_logout = row.get("postLogoutRedirectUris")
        return cls(
            client_id=row["clientId"],
            client_secret=row.get("clientSecret") or None,
            name=row.get("name"),
            redirect_uris=tuple((row.get("redirectUris") or "").split(",")),
            allowed_scopes=tuple((row.get("allowedScopes") or "").split(",")),
            # Upstream default is `requirePKCE ?? true`: absent means required.
            require_pkce=(
                True if row.get("requirePKCE") is None else bool(row.get("requirePKCE"))
            ),
            token_endpoint_auth_method=row.get("tokenEndpointAuthMethod")
            or "client_secret_basic",
            subject_type=row.get("subjectType") or None,
            disabled=bool(row.get("disabled")),
            enable_end_session=bool(row.get("enableEndSession")),
            post_logout_redirect_uris=tuple(
                u for u in (post_logout or "").split(",") if u
            ),
        )


# ----- request bodies -----


class RegisterBody(BaseModel):
    name: str
    redirect_uris: list[str]
    allowed_scopes: list[str] = ["openid", "profile", "email"]
    require_pkce: bool = True
    token_endpoint_auth_method: str = "client_secret_basic"
    subject_type: str | None = None
    response_types: list[str] | None = None
    type: str | None = None
    post_logout_redirect_uris: list[str] | None = None
    # Privileged: a self-registering client may NOT grant itself consent-skip.
    # Accepted into the model only so it can be explicitly rejected (RFC 7591
    # §2: the server controls which metadata a client may set).
    skip_consent: bool | None = None


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
            # RFC 6749 §2.3.1: a client must not present two distinct
            # identities. If the body also carries a client_id it must match the
            # one in the Authorization header, otherwise authentication fails.
            if cid and client_id and cid != client_id:
                raise _oauth_error(
                    401,
                    "invalid_client",
                    "client_id mismatch between Authorization header and request body",
                )
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
    requested_scopes = [s for s in scope.split() if s]
    # PKCE gate (mirrors upstream `isPKCERequired`): public clients, the
    # offline_access scope, and confidential clients with require_pkce all
    # mandate a code_challenge. The error_description carries the precise reason.
    pkce_reason = _pkce_required(client, requested_scopes)
    if pkce_reason and not code_challenge:
        raise _oauth_error(400, "invalid_request", pkce_reason)
    if code_challenge_method and code_challenge_method != "S256":
        raise _oauth_error(
            400,
            "invalid_request",
            "invalid code_challenge method, only S256 is supported",
        )
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
            "sessionId": ctx.session.id,
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

    # RFC 9207: advertise the issuer in the authorization response so the
    # client can detect mix-up attacks. The metadata sets
    # `authorization_response_iss_parameter_supported: true`, so we must emit it.
    params: dict[str, str] = {"code": code, "iss": opts.issuer}
    if state:
        params["state"] = state
    redirect = f"{redirect_uri}?{urlencode(params)}"
    return {"redirect": redirect, "code": code, "state": state}


async def _token(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: TokenBody = ctx.body
    client_id, client_secret = _client_auth(ctx)
    if not client_id:
        raise _oauth_error(401, "invalid_client", "client_id required")
    try:
        client = await _load_client(ctx.auth, client_id)
    except APIError as exc:
        # An unknown client is a client-authentication failure (RFC 6749 §5.2).
        raise _oauth_error(401, "invalid_client", "unknown client") from exc

    # Administratively disabled clients cannot obtain or exchange tokens.
    if client.disabled:
        raise _oauth_error(401, "invalid_client", "client is disabled")

    # Auth: confidential clients require secret; public clients can omit if PKCE present.
    is_public = client.token_endpoint_auth_method == "none"
    if not is_public:
        if (
            not client_secret
            or not client.client_secret
            or not _verify_secret(
                opts.store_client_secret, client_secret, client.client_secret
            )
        ):
            raise _oauth_error(401, "invalid_client", "invalid client credentials")

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
        scope = record.get("scope") or ""
        requested_scopes = [s for s in scope.split() if s]
        challenge = record.get("codeChallenge")
        pkce_used_in_auth = bool(challenge)
        pkce_used_in_token = bool(body.code_verifier)
        # Mirror upstream consistency checks (token.ts):
        #   * PKCE required for this request but no verifier -> invalid_request
        #   * verifier without a prior challenge -> invalid_request
        #   * challenge without a verifier -> invalid_request
        #   * mismatched verifier -> "code verification failed"
        pkce_reason = _pkce_required(client, requested_scopes)
        if pkce_reason and not pkce_used_in_token:
            raise _oauth_error(401, "invalid_request", PKCE_CLIENT_REQUIRE)
        if pkce_used_in_auth and not pkce_used_in_token:
            raise _oauth_error(
                401,
                "invalid_request",
                "code_verifier required because PKCE was used in authorization",
            )
        if pkce_used_in_token and not pkce_used_in_auth:
            raise _oauth_error(
                401,
                "invalid_request",
                "code_verifier provided but PKCE was not used in authorization",
            )
        if pkce_used_in_auth and pkce_used_in_token:
            method = record.get("codeChallengeMethod") or "S256"
            computed = (
                pkce_challenge(body.code_verifier)
                if method == "S256"
                else body.code_verifier
            )
            if computed != challenge:
                raise _oauth_error(401, "invalid_request", "code verification failed")

        user_id = record["userId"]
        return await _issue_tokens(
            ctx,
            opts,
            client=client,
            user_id=user_id,
            scope=scope,
            nonce=record.get("nonce"),
            session_id=record.get("sessionId"),
        )

    if grant == "refresh_token":
        if not body.refresh_token:
            raise APIError(400, "INVALID_REQUEST", message="refresh_token required")
        stored_token = _store_secret(opts.store_tokens, body.refresh_token)
        row = await ctx.auth.adapter.find_one(
            model="oauthRefreshToken",
            where=(Where(field="token", value=stored_token),),
        )
        if not row:
            raise APIError(400, "INVALID_REQUEST", message="invalid_grant")
        if row.get("clientId") != client_id:
            raise APIError(400, "INVALID_REQUEST", message="client mismatch")
        # RFC 9700 §4.14 reuse detection: replaying a token that was already
        # rotated tears down the entire (client, user) family and rejects.
        if row.get("revoked"):
            await _invalidate_refresh_family(
                ctx, client_id=client_id, user_id=row["userId"]
            )
            raise APIError(400, "INVALID_REQUEST", message="invalid_grant")
        if int(row.get("expiresAt", 0)) < now:
            raise APIError(400, "INVALID_REQUEST", message="refresh token expired")
        # Scope handling: a `scope` param may narrow (subset of) the original
        # grant, but may never widen it (RFC 6749 §6).
        granted_scope = row.get("scope") or ""
        granted_scopes = [s for s in granted_scope.split() if s]
        if body.scope is not None:
            requested_scopes = [s for s in body.scope.split() if s]
            if set(requested_scopes) - set(granted_scopes):
                raise _oauth_error(
                    400, "invalid_scope", "requested scope exceeds original grant"
                )
            new_scope = " ".join(requested_scopes)
        else:
            new_scope = granted_scope
        # Rotate: mark the presented token revoked (kept for replay detection),
        # then mint a fresh one in the same family.
        await ctx.auth.adapter.update(
            model="oauthRefreshToken",
            where=(Where(field="token", value=stored_token),),
            update={"revoked": now},
        )
        return await _issue_tokens(
            ctx,
            opts,
            client=client,
            user_id=row["userId"],
            scope=new_scope,
            session_id=row.get("sessionId"),
        )

    if grant == "client_credentials":
        # Machine-to-machine: a confidential client authenticating as itself.
        # Upstream rejects public clients and OIDC/identity scopes here, since
        # there is no end user to represent.
        if is_public or not client_secret:
            raise _oauth_error(
                401,
                "invalid_client",
                "client_credentials requires client authentication",
            )
        requested = {s for s in (body.scope or "").split() if s}
        oidc_scopes = {"openid", "profile", "email", "offline_access"}
        forbidden = requested & oidc_scopes
        if forbidden:
            raise _oauth_error(
                400,
                "invalid_scope",
                f"scope not allowed for client_credentials: {sorted(forbidden)}",
            )
        # Issue an access token bound to the client itself (no user).
        return await _issue_tokens(
            ctx,
            opts,
            client=client,
            user_id=f"client:{client_id}",
            scope=body.scope or "",
            include_id_token=False,
        )

    raise _oauth_error(
        400, "unsupported_grant_type", f"unsupported grant_type {grant}"
    )


async def _invalidate_refresh_family(
    ctx: EndpointContext, *, client_id: str, user_id: str
) -> None:
    """Tear down every refresh token for a (client, user) pair (RFC 9700 §4.14)."""
    await ctx.auth.adapter.delete_many(
        model="oauthRefreshToken",
        where=(
            Where(field="clientId", value=client_id),
            Where(field="userId", value=user_id),
        ),
    )


async def _issue_tokens(
    ctx: EndpointContext,
    opts: OAuthProviderOptions,
    *,
    client: OAuthClient,
    user_id: str,
    scope: str,
    nonce: str | None = None,
    include_id_token: bool = True,
    session_id: str | None = None,
) -> dict[str, object]:
    now = int(time.time())
    client_id = client.client_id
    # The JWT access token's `sub` stays the *real* user id so that /userinfo and
    # /introspect can look the account up. The pairwise (sector-scoped) subject
    # is applied only to the id_token and at the introspection presentation
    # layer. Client-credential tokens carry their synthetic `client:` id.
    # Mirrors upstream `resolveSubjectIdentifier` placement (utils + introspect).
    pairwise_sub = (
        user_id if user_id.startswith("client:") else _resolve_sub(user_id, client, opts)
    )
    # `azp` records the client so introspection can recompute the pairwise sub.
    if opts.jwt_access_token:
        access_payload: dict[str, Any] = {
            "sub": user_id,
            "azp": client_id,
            "aud": client_id,
            "iss": opts.issuer,
            "scope": scope,
            "jti": secrets.token_urlsafe(16),
        }
        # The access token always carries the issuing session id (when there is
        # an end user). Introspection surfaces it as `sid` after validating the
        # session is still live — independent of the admin-only
        # `enable_end_session` flag, which only governs the id_token's `sid`.
        if session_id:
            access_payload["sid"] = session_id
        access_token, _kid = await issue_jwt(
            ctx.auth,
            payload=access_payload,
            ttl=opts.access_token_ttl,
        )
    else:
        # Opaque reference token, persisted hashed in `oauthAccessToken`. The
        # row carries the real user id (for lookup) plus `azp` so introspection
        # / userinfo can present the pairwise subject without re-deriving it.
        access_token = opts.opaque_access_token_prefix + secrets.token_urlsafe(48)
        await ctx.auth.adapter.create(
            model="oauthAccessToken",
            data={
                "token": _store_secret(opts.store_tokens, access_token),
                "clientId": client_id,
                "userId": user_id,
                "azp": client_id,
                "scope": scope,
                "sessionId": session_id,
                "expiresAt": now + opts.access_token_ttl,
            },
        )
    out: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": opts.access_token_ttl,
        "scope": scope,
    }
    scopes = set(scope.split())
    if "offline_access" in scopes:
        refresh = opts.refresh_token_prefix + secrets.token_urlsafe(48)
        await ctx.auth.adapter.create(
            model="oauthRefreshToken",
            data={
                "token": _store_secret(opts.store_tokens, refresh),
                "clientId": client_id,
                "userId": user_id,
                "scope": scope,
                "sessionId": session_id,
                "expiresAt": now + opts.refresh_token_ttl,
                "revoked": None,
            },
        )
        out["refresh_token"] = refresh
    if include_id_token and "openid" in scopes:
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=user_id),)
        )
        payload: dict[str, Any] = {
            "sub": pairwise_sub,
            "aud": client_id,
            "iss": opts.issuer,
        }
        if nonce:
            payload["nonce"] = nonce
        # OIDC RP-initiated logout: only clients explicitly opted in (admin-set
        # `enable_end_session`) receive the `sid` (session id) claim, which the
        # end-session endpoint later uses to terminate the right session.
        if client.enable_end_session and session_id:
            payload["sid"] = session_id
        if user:
            payload.update(_user_normal_claims(user, scopes))
        id_token, _kid = await issue_jwt(ctx.auth, payload=payload, ttl=opts.access_token_ttl)
        out["id_token"] = id_token
    return out


async def _userinfo(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    auth_header = ctx.request.headers.get("authorization", "")
    # Upstream accepts either "Bearer <token>" or a bare token, and reports a
    # missing/empty value as invalid_request / "authorization header not found".
    token = auth_header[len("Bearer "):] if auth_header.startswith("Bearer ") else auth_header
    if not token:
        raise _oauth_error(401, "invalid_request", "authorization header not found")
    try:
        claims: Mapping[str, Any] = await verify_local_jwt(
            ctx.auth, token, issuer=opts.issuer
        )
    except ValueError as jwt_err:
        # Fall back to the opaque-token table; an unknown/expired token is 401.
        row = await _lookup_opaque_access_token(ctx, opts, token)
        if row is None:
            raise APIError(401, "UNAUTHORIZED", message=str(jwt_err)) from None
        claims = {
            "sub": row.get("userId"),
            "azp": row.get("azp") or row.get("clientId"),
            "scope": row.get("scope", ""),
        }
    scopes = set(str(claims.get("scope", "")).split())
    # OIDC: userinfo requires the openid scope (invalid_scope, 400).
    if "openid" not in scopes:
        raise _oauth_error(400, "invalid_scope", "Missing required scope")
    sub = claims.get("sub")
    if not isinstance(sub, str):
        raise _oauth_error(400, "invalid_request", "user not found")
    if sub.startswith("client:"):
        return {"sub": sub}
    # The access token `sub` is the real user id (for lookup). The response
    # `sub` is the pairwise identifier resolved from the issuing client (`azp`),
    # so /userinfo agrees with the id_token for pairwise clients.
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=sub),)
    )
    if user is None:
        raise APIError(404, "USER_NOT_FOUND")
    response_sub = sub
    azp = claims.get("azp")
    if isinstance(azp, str) and azp:
        client = await _load_client(ctx.auth, azp)
        response_sub = _resolve_sub(sub, client, opts)
    out: dict[str, object] = {"sub": response_sub}
    out.update(_user_normal_claims(user, scopes))
    return out


def _user_normal_claims(
    user: Mapping[str, Any], scopes: set[str]
) -> dict[str, object]:
    """Build profile/email claims (mirrors upstream `userNormalClaims`).

    Splits `name` into `given_name`/`family_name` when more than one part.
    @see https://openid.net/specs/openid-connect-core-1_0.html#NormalClaims
    """
    out: dict[str, object] = {}
    if "profile" in scopes:
        name = (user.get("name") or "").strip()
        if name:
            out["name"] = name
            parts = [p for p in name.split(" ") if p]
            if len(parts) > 1:
                out["given_name"] = " ".join(parts[:-1])
                out["family_name"] = parts[-1]
        if user.get("image"):
            out["picture"] = user["image"]
    if "email" in scopes:
        if user.get("email"):
            out["email"] = user["email"]
        out["email_verified"] = bool(user.get("emailVerified", False))
    return out


async def _revoke(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: RevokeBody = ctx.body
    # RFC 7009 §2.1: the revocation endpoint MUST authenticate the caller.
    client_id, client_secret = _client_auth(ctx)
    if not client_id:
        raise _oauth_error(401, "invalid_client", "missing required credentials")
    client = await _load_client(ctx.auth, client_id)
    is_public = client.token_endpoint_auth_method == "none"
    if not is_public:
        if (
            not client_secret
            or not client.client_secret
            or not _verify_secret(
                opts.store_client_secret, client_secret, client.client_secret
            )
        ):
            raise _oauth_error(401, "invalid_client", "invalid client credentials")
    hint = body.token_type_hint
    # Classify the presented token so a token_type_hint mismatch is rejected
    # (mirrors upstream revoke: a hint that contradicts the token -> 400).
    is_jwt = await _is_access_token(ctx, opts, body.token)
    if hint == "access_token" and not is_jwt:
        raise _oauth_error(400, "unsupported_token_type", "token type mismatch")
    if hint == "refresh_token" and is_jwt:
        raise _oauth_error(400, "unsupported_token_type", "token type mismatch")
    # Only revoke tokens that belong to the authenticated client (RFC 7009 §2.1).
    stored = _store_secret(opts.store_tokens, body.token)
    await ctx.auth.adapter.delete_many(
        model="oauthRefreshToken",
        where=(
            Where(field="token", value=stored),
            Where(field="clientId", value=client_id),
        ),
    )
    # Opaque access tokens live in their own table; revoke those too (a JWT
    # access token has no row, so this is a harmless no-op for the JWT model).
    await ctx.auth.adapter.delete_many(
        model="oauthAccessToken",
        where=(
            Where(field="token", value=stored),
            Where(field="clientId", value=client_id),
        ),
    )
    # RFC 7009: respond 200 regardless of whether the token existed.
    return {}


async def _lookup_opaque_access_token(
    ctx: EndpointContext, opts: OAuthProviderOptions, token: str
) -> Mapping[str, Any] | None:
    """Return the live `oauthAccessToken` row for an opaque token, or None.

    A row is "live" only when present and unexpired; expired rows are treated as
    absent (the introspection/userinfo callers report them inactive/unauthorized).
    """
    row = await ctx.auth.adapter.find_one(
        model="oauthAccessToken",
        where=(Where(field="token", value=_store_secret(opts.store_tokens, token)),),
    )
    if row is None:
        return None
    if int(row.get("expiresAt", 0)) <= int(time.time()):
        return None
    return row


async def _is_access_token(
    ctx: EndpointContext, opts: OAuthProviderOptions, token: str
) -> bool:
    """True when `token` is an access token issued by this server.

    Recognises both the self-contained JWT format and the opaque reference
    format (a live row in `oauthAccessToken`).
    """
    try:
        await verify_local_jwt(ctx.auth, token, issuer=opts.issuer)
        return True
    except ValueError:
        pass
    return await _lookup_opaque_access_token(ctx, opts, token) is not None


async def _live_session_id(ctx: EndpointContext, sid: Any) -> str | None:
    """Return `sid` only if it names a session that still exists and is unexpired.

    Mirrors upstream introspection, which drops the `sid` claim when the backing
    session has been terminated (e.g. the user signed out) or expired.
    """
    if not isinstance(sid, str) or not sid:
        return None
    session = await ctx.auth.adapter.find_one(
        model="session", where=(Where(field="id", value=sid),)
    )
    if not session:
        return None
    expires_at = session.get("expiresAt")
    if isinstance(expires_at, (int | float)) and expires_at < int(time.time()):
        return None
    if isinstance(expires_at, datetime) and expires_at < datetime.now(
        expires_at.tzinfo
    ):
        return None
    return sid


async def _introspect(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    body: IntrospectBody = ctx.body
    # RFC 7662 §2.1: the introspection endpoint MUST authenticate the caller.
    client_id, client_secret = _client_auth(ctx)
    if not client_id or not client_secret:
        raise _oauth_error(401, "invalid_client", "missing required credentials")
    client = await _load_client(ctx.auth, client_id)
    if (
        not client.client_secret
        or not _verify_secret(
            opts.store_client_secret, client_secret, client.client_secret
        )
    ):
        raise _oauth_error(401, "invalid_client", "invalid client credentials")
    hint = body.token_type_hint
    # Try as JWT access token (skipped when the caller pins token_type_hint to
    # refresh_token, mirroring upstream's hint-aware lookup).
    if hint != "refresh_token":
        try:
            claims = await verify_local_jwt(ctx.auth, body.token, issuer=opts.issuer)
            token_sub = claims.get("sub")
            # Resolve the pairwise sub at the presentation layer (mirrors upstream
            # `resolveIntrospectionSub`): the token carries the real user id, but
            # the response presents the sector-scoped identifier for the client.
            if isinstance(token_sub, str) and not token_sub.startswith("client:"):
                token_sub = _resolve_sub(token_sub, client, opts)
            out: dict[str, object] = {
                "active": True,
                "sub": token_sub,
                "client_id": claims.get("azp") or claims.get("aud"),
                "aud": claims.get("aud"),
                "iss": claims.get("iss"),
                "exp": claims.get("exp"),
                "iat": claims.get("iat"),
                "scope": claims.get("scope"),
                "token_type": "Bearer",
            }
            sid = await _live_session_id(ctx, claims.get("sid"))
            if sid:
                out["sid"] = sid
            return out
        except ValueError:
            pass
        # Opaque access-token lookup (same hint gating as the JWT path).
        row = await _lookup_opaque_access_token(ctx, opts, body.token)
        if row is not None:
            sub = row.get("userId")
            if isinstance(sub, str) and not sub.startswith("client:"):
                sub = _resolve_sub(sub, client, opts)
            opaque_out: dict[str, object] = {
                "active": True,
                "sub": sub,
                "client_id": row.get("azp") or row.get("clientId"),
                "aud": row.get("clientId"),
                "iss": opts.issuer,
                "exp": row.get("expiresAt"),
                "scope": row.get("scope"),
                "token_type": "Bearer",
            }
            sid = await _live_session_id(ctx, row.get("sessionId"))
            if sid:
                opaque_out["sid"] = sid
            return opaque_out
    # Refresh-token lookup is skipped when the caller pinned the hint to
    # access_token (a refresh token presented as an access token is inactive),
    # or when a JWT access token was presented under a refresh_token hint.
    refresh_token_jwt_mismatch = hint == "refresh_token" and await _is_access_token(
        ctx, opts, body.token
    )
    if hint != "access_token" and not refresh_token_jwt_mismatch:
        # Try as refresh token (stored hashed → hash the presented value).
        row = await ctx.auth.adapter.find_one(
            model="oauthRefreshToken",
            where=(
                Where(field="token", value=_store_secret(opts.store_tokens, body.token)),
            ),
        )
        if (
            row
            and not row.get("revoked")
            and int(row.get("expiresAt", 0)) > int(time.time())
        ):
            refresh_out: dict[str, object] = {
                "active": True,
                "sub": row.get("userId"),
                "client_id": row.get("clientId"),
                "iss": opts.issuer,
                "scope": row.get("scope"),
                "exp": row.get("expiresAt"),
                "token_type": "refresh_token",
            }
            sid = await _live_session_id(ctx, row.get("sessionId"))
            if sid:
                refresh_out["sid"] = sid
            return refresh_out
    return {"active": False}


_BASE_CLAIMS = (
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "sid",
    "scope",
    "azp",
    "email",
    "email_verified",
    "name",
    "picture",
    "family_name",
    "given_name",
)


def _metadata(opts: OAuthProviderOptions, *, openid: bool) -> dict[str, object]:
    """Build the authorization-server (RFC 8414) or OIDC discovery document.

    Mirrors upstream `authServerMetadata` / `oidcServerMetadata` field-for-field.
    """
    base = opts.issuer.rstrip("/")
    grant_types = list(opts.grant_types)
    response_types = ["code"] if "authorization_code" in grant_types else []
    # Public clients are advertised only when dynamic registration of secretless
    # clients is permitted; mirror upstream by prepending "none".
    auth_methods: list[str] = ["client_secret_basic", "client_secret_post"]
    doc: dict[str, object] = {
        "issuer": opts.issuer,
        "authorization_endpoint": f"{base}/oauth2/authorize",
        "token_endpoint": f"{base}/oauth2/token",
        "jwks_uri": f"{base}/jwks",
        "registration_endpoint": f"{base}/oauth2/register",
        "introspection_endpoint": f"{base}/oauth2/introspect",
        "revocation_endpoint": f"{base}/oauth2/revoke",
        "scopes_supported": list(
            opts.advertised_scopes_supported or opts.supported_scopes
        ),
        "response_types_supported": response_types,
        "response_modes_supported": ["query"],
        "grant_types_supported": grant_types,
        "token_endpoint_auth_methods_supported": auth_methods,
        "introspection_endpoint_auth_methods_supported": list(auth_methods),
        "revocation_endpoint_auth_methods_supported": list(auth_methods),
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
    }
    if openid:
        # OIDC discovery (OpenID-Connect-Discovery) adds the identity layer.
        doc["claims_supported"] = list(
            opts.advertised_claims_supported or _BASE_CLAIMS
        )
        doc["userinfo_endpoint"] = f"{base}/oauth2/userinfo"
        doc["subject_types_supported"] = (
            ["public", "pairwise"] if opts.pairwise_secret else ["public"]
        )
        doc["id_token_signing_alg_values_supported"] = ["EdDSA"]
        doc["end_session_endpoint"] = f"{base}/oauth2/end-session"
        doc["acr_values_supported"] = ["urn:mace:incommon:iap:bronze"]
        doc["prompt_values_supported"] = [
            "login",
            "consent",
            "create",
            "select_account",
            "none",
        ]
    return doc


async def _discovery(ctx: EndpointContext) -> dict[str, object]:
    """OpenID Connect discovery — `/.well-known/openid-configuration`.

    Upstream `getOpenIdConfig` 404s when the issuer does not advertise the
    `openid` scope (i.e. it is operating as a pure OAuth 2.0 server).
    """
    opts = _options(ctx.auth)
    if "openid" not in opts.supported_scopes:
        raise APIError(404, "NOT_FOUND")
    return _metadata(opts, openid=True)


async def _as_metadata(ctx: EndpointContext) -> dict[str, object]:
    """RFC 8414 OAuth 2.0 authorization-server metadata."""
    return _metadata(_options(ctx.auth), openid=False)


async def _register(ctx: EndpointContext) -> dict[str, object]:
    opts = _options(ctx.auth)
    if not opts.enable_dynamic_registration:
        raise APIError(404, "NOT_FOUND")
    body: RegisterBody = ctx.body
    # A self-registering client may not grant itself consent-skip; that is a
    # privileged flag only the admin create-client path may set.
    if body.skip_consent:
        raise _oauth_error(
            400,
            "invalid_client_metadata",
            "skip_consent may not be set during dynamic client registration",
        )
    _validate_subject_type(body.subject_type, body.redirect_uris, opts)
    # RFC 7591: only the authorization_code response type ("code") is supported.
    if body.response_types is not None and body.response_types != ["code"]:
        raise _oauth_error(
            400,
            "invalid_client_metadata",
            "only the 'code' response_type is supported",
        )
    # Public/confidential consistency: a public client (auth method "none") may
    # not declare a confidential client type, and vice versa.
    is_public = body.token_endpoint_auth_method == "none"
    confidential_types = {"web"}
    public_types = {"native", "user-agent-based"}
    if is_public and body.type in confidential_types:
        raise _oauth_error(
            400, "invalid_client_metadata", "public client cannot be type 'web'"
        )
    if not is_public and body.type in public_types:
        raise _oauth_error(
            400,
            "invalid_client_metadata",
            f"confidential client cannot be type '{body.type}'",
        )
    client_id = secrets.token_urlsafe(16)
    client_secret = (
        "" if body.token_endpoint_auth_method == "none" else secrets.token_urlsafe(32)
    )
    now = int(time.time())
    await ctx.auth.adapter.create(
        model="oauthClient",
        data={
            "clientId": client_id,
            "clientSecret": _store_secret(opts.store_client_secret, client_secret)
            if client_secret
            else client_secret,
            "name": body.name,
            "redirectUris": ",".join(body.redirect_uris),
            "allowedScopes": ",".join(body.allowed_scopes),
            "requirePKCE": body.require_pkce,
            "tokenEndpointAuthMethod": body.token_endpoint_auth_method,
            "subjectType": body.subject_type,
            # Dynamic registration may declare post-logout redirect URIs, but it
            # may NOT grant itself `enableEndSession` (privileged, admin-only).
            "postLogoutRedirectUris": ",".join(body.post_logout_redirect_uris or []),
            "createdAt": now,
            "updatedAt": now,
        },
    )
    out: dict[str, object] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uris": body.redirect_uris,
        "allowed_scopes": body.allowed_scopes,
        "token_endpoint_auth_method": body.token_endpoint_auth_method,
        "client_name": body.name,
    }
    if body.subject_type:
        out["subject_type"] = body.subject_type
    if body.post_logout_redirect_uris is not None:
        out["post_logout_redirect_uris"] = body.post_logout_redirect_uris
    return out


async def _end_session(ctx: EndpointContext) -> dict[str, object] | None:
    """OIDC RP-initiated logout (`end_session_endpoint`).

    Validates the `id_token_hint`, confirms the issuing client is allowed to end
    sessions, terminates the session named by the token's `sid` claim, and —
    when a registered `post_logout_redirect_uri` is supplied — returns a redirect
    (with optional `state`). Mirrors upstream's end-session handler.

    @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    """
    opts = _options(ctx.auth)
    qs = ctx.request.query
    id_token_hint = _q(qs, "id_token_hint")
    post_logout_redirect_uri = _q(qs, "post_logout_redirect_uri")
    state = _q(qs, "state")

    if not id_token_hint:
        raise _oauth_error(401, "invalid_request", "id_token_hint is required")
    try:
        claims: Mapping[str, Any] = await verify_local_jwt(
            ctx.auth, id_token_hint, issuer=opts.issuer
        )
    except ValueError as exc:
        raise _oauth_error(401, "invalid_request", "invalid id_token_hint") from exc

    aud = claims.get("aud")
    client_id = aud[0] if isinstance(aud, list) and aud else aud
    if not isinstance(client_id, str) or not client_id:
        raise _oauth_error(401, "invalid_request", "id_token_hint missing audience")
    try:
        client = await _load_client(ctx.auth, client_id)
    except APIError as exc:
        raise _oauth_error(401, "invalid_request", "unknown client") from exc
    # Only clients granted RP-initiated logout may terminate sessions; absence of
    # an `sid` claim (the issuance-time signal a client was *not* opted in) is
    # treated the same way.
    if not client.enable_end_session:
        raise _oauth_error(
            401, "invalid_request", "client is not allowed to end sessions"
        )
    sid = claims.get("sid")
    if not isinstance(sid, str) or not sid:
        raise _oauth_error(401, "invalid_request", "id_token_hint missing sid")

    await ctx.auth.adapter.delete(
        model="session", where=(Where(field="id", value=sid),)
    )

    if post_logout_redirect_uri:
        if post_logout_redirect_uri not in client.post_logout_redirect_uris:
            raise _oauth_error(
                400, "invalid_request", "post_logout_redirect_uri not registered"
            )
        redirect = post_logout_redirect_uri
        if state:
            sep = "&" if "?" in redirect else "?"
            redirect = f"{redirect}{sep}{urlencode({'state': state})}"
        ctx.response_headers["Location"] = redirect
        return {"redirect": redirect}
    return None


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
AS_METADATA = create_auth_endpoint(
    "/.well-known/oauth-authorization-server",
    EndpointOptions(method="GET"),
    _as_metadata,
)
REGISTER = create_auth_endpoint(
    "/oauth2/register",
    EndpointOptions(method="POST", body=RegisterBody),
    _register,
)
END_SESSION = create_auth_endpoint(
    "/oauth2/end-session",
    EndpointOptions(method="GET"),
    _end_session,
)


_ENDPOINTS: tuple[AuthEndpoint, ...] = (
    AUTHORIZE,
    TOKEN,
    USERINFO,
    REVOKE,
    INTROSPECT,
    DISCOVERY,
    AS_METADATA,
    REGISTER,
    END_SESSION,
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
                OAUTH_ACCESS_TOKEN_MODEL,
            )
        )
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: _ENDPOINTS)
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = ()
    error_codes: Mapping[str, str] = field(default_factory=lambda: {})
    init: None = None


def oauth_provider(options: OAuthProviderOptions) -> KerniaPlugin:
    """Construct the OIDC/OAuth2 provider plugin."""
    return _OAuthProviderPlugin(  # type: ignore[return-value]
        opts=options, rate_limit=_build_rate_limits(options)
    )


def _validate_subject_type(
    subject_type: str | None, redirect_uris: Sequence[str], opts: OAuthProviderOptions
) -> None:
    """Reject pairwise client registration that cannot produce stable subs.

    Mirrors upstream: pairwise requires a configured `pairwiseSecret`, and every
    redirect URI must share the same host (sector) so the computed `sub` is
    deterministic.
    """
    if subject_type != "pairwise":
        return
    if not opts.pairwise_secret:
        raise _oauth_error(
            400,
            "invalid_client_metadata",
            "pairwise subject_type requires a configured pairwiseSecret",
        )
    from urllib.parse import urlsplit

    hosts = {urlsplit(u).netloc for u in redirect_uris if u}
    if len(hosts) > 1:
        raise _oauth_error(
            400,
            "invalid_redirect_uri",
            "pairwise subject_type requires all redirect URIs to share one host",
        )


async def create_client(
    auth: AuthContext,
    *,
    name: str,
    redirect_uris: Sequence[str],
    allowed_scopes: Sequence[str] = ("openid", "profile", "email"),
    require_pkce: bool = True,
    token_endpoint_auth_method: str = "client_secret_basic",
    subject_type: str | None = None,
    enable_end_session: bool = False,
    post_logout_redirect_uris: Sequence[str] = (),
) -> OAuthClient:
    """Register a client programmatically (the privileged / admin path).

    Unlike dynamic registration (`/oauth2/register`), this path may set
    ``enable_end_session`` — opting the client into the `sid` id_token claim and
    the RP-initiated logout endpoint.
    """
    opts = _options(auth)
    _validate_subject_type(subject_type, redirect_uris, opts)
    client_id = secrets.token_urlsafe(16)
    client_secret = "" if token_endpoint_auth_method == "none" else secrets.token_urlsafe(32)
    now = int(time.time())
    await auth.adapter.create(
        model="oauthClient",
        data={
            "clientId": client_id,
            "clientSecret": _store_secret(opts.store_client_secret, client_secret)
            if client_secret
            else client_secret,
            "name": name,
            "redirectUris": ",".join(redirect_uris),
            "allowedScopes": ",".join(allowed_scopes),
            "requirePKCE": require_pkce,
            "tokenEndpointAuthMethod": token_endpoint_auth_method,
            "subjectType": subject_type,
            "disabled": False,
            "enableEndSession": enable_end_session,
            "postLogoutRedirectUris": ",".join(post_logout_redirect_uris),
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
        subject_type=subject_type,
        enable_end_session=enable_end_session,
        post_logout_redirect_uris=tuple(post_logout_redirect_uris),
    )


__all__ = [
    "oauth_provider",
    "OAuthProviderOptions",
    "OAuthClient",
    "create_client",
]
