"""API key plugin construction.

The wire format is `ba_<prefix>_<random>`:
  * `ba_`     — namespace marker so server-side code can detect keys quickly
  * `<prefix>` — 8 char base32 prefix (also stored as `keyPrefix` for display)
  * `<random>` — 32 char base32 entropy

Stored columns: `id`, `name`, `userId`, `organizationId?`, `keyPrefix`,
`keyHash` (argon2id of the full key), `scope` (JSON), `expiresAt?`,
`lastUsedAt?`, `createdAt`, `updatedAt`.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.api.endpoint import create_auth_endpoint
from kernia.crypto import hash_password, verify_password
from kernia.error import APIError
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.context import EndpointContext, Session
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema


API_KEY_ERROR_CODES: Mapping[str, str] = {
    "API_KEY_INVALID": "API key is invalid or has been revoked.",
    "API_KEY_EXPIRED": "API key has expired.",
    "API_KEY_NOT_FOUND": "API key does not exist.",
}


_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def generate_api_key() -> tuple[str, str]:
    """Return `(plaintext, prefix)` for a freshly minted API key."""
    prefix = "".join(secrets.choice(_ALPHABET) for _ in range(8))
    body = "".join(secrets.choice(_ALPHABET) for _ in range(32))
    return f"ba_{prefix}_{body}", prefix


def parse_api_key(raw: str) -> str | None:
    """Return the prefix if `raw` looks like a `ba_<prefix>_<body>` key, else None."""
    if not raw or not raw.startswith("ba_"):
        return None
    parts = raw.split("_")
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None
    return parts[1]


API_KEY_MODEL = ModelDef(
    name="apiKey",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("name", "string", required=False),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("organizationId", "string", required=False),
        FieldDef("keyPrefix", "string"),
        FieldDef("keyHash", "string"),
        FieldDef("scope", "json", required=False),
        FieldDef("expiresAt", "number", required=False),
        FieldDef("lastUsedAt", "number", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


# --------------------------------------------------------------------------- options


@dataclass(frozen=True, slots=True)
class ApiKeyOptions:
    default_scope: Mapping[str, Any] | None = None


# --------------------------------------------------------------------------- bodies


@dataclass(frozen=True, slots=True)
class CreateApiKeyBody:
    name: str | None = None
    organization_id: str | None = None
    scope: dict[str, Any] | None = None
    expires_in: int | None = None  # seconds from now


@dataclass(frozen=True, slots=True)
class RevokeApiKeyBody:
    id: str


@dataclass(frozen=True, slots=True)
class VerifyApiKeyBody:
    key: str


# --------------------------------------------------------------------------- plugin


@dataclass(frozen=True)
class _ApiKeyPlugin:
    id: str = "api-key"
    version: str | None = "0.0.0"
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: None = None
    on_request: Any = None
    on_response: None = None
    rate_limit: None = None
    error_codes: Mapping[str, str] = field(default_factory=lambda: dict(API_KEY_ERROR_CODES))
    init: None = None


async def _verify_lookup(ctx: EndpointContext, raw: str) -> dict[str, Any] | None:
    """Find and verify an api key by plaintext value.

    Returns the row if valid, or None if invalid/expired.
    """
    prefix = parse_api_key(raw)
    if prefix is None:
        return None
    rows = await ctx.auth.adapter.find_many(
        model="apiKey",
        where=(Where(field="keyPrefix", value=prefix),),
    )
    now = int(time.time())
    for row in rows:
        if not verify_password(raw, row["keyHash"]):
            continue
        expires = row.get("expiresAt")
        if expires is not None and int(expires) < now:
            return None
        # Update last-used (fire and forget — same task is fine).
        await ctx.auth.adapter.update(
            model="apiKey",
            where=(Where(field="id", value=row["id"]),),
            update={"lastUsedAt": now},
        )
        return row
    return None


def _attach_synthetic_session(ctx: EndpointContext, row: dict[str, Any]) -> None:
    """Build a synthetic Session for the request so endpoint handlers see auth."""
    if ctx.session is not None:
        return
    ctx.session = Session(
        id=f"apikey:{row['id']}",
        user_id=row["userId"],
        expires_at=int(row.get("expiresAt") or (int(time.time()) + 3600)),
        token=f"apikey:{row['id']}",
    )


def api_key(options: ApiKeyOptions | None = None) -> KerniaPlugin:
    opts = options or ApiKeyOptions()

    async def create_key(ctx: EndpointContext) -> dict[str, Any]:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        body: CreateApiKeyBody = ctx.body or CreateApiKeyBody()
        plaintext, prefix = generate_api_key()
        now = int(time.time())
        expires_at = (now + body.expires_in) if body.expires_in else None
        row = await ctx.auth.adapter.create(
            model="apiKey",
            data={
                "name": body.name,
                "userId": ctx.session.user_id,
                "organizationId": body.organization_id,
                "keyPrefix": prefix,
                "keyHash": hash_password(plaintext),
                "scope": json.dumps(body.scope) if body.scope else None,
                "expiresAt": expires_at,
                "createdAt": now,
                "updatedAt": now,
            },
        )
        return {
            "id": row["id"],
            "key": plaintext,  # plaintext returned ONCE
            "name": row.get("name"),
            "keyPrefix": prefix,
            "expiresAt": expires_at,
        }

    async def list_keys(ctx: EndpointContext) -> dict[str, Any]:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        rows = await ctx.auth.adapter.find_many(
            model="apiKey",
            where=(Where(field="userId", value=ctx.session.user_id),),
        )
        # Strip hashes from the listing.
        for r in rows:
            r.pop("keyHash", None)
        return {"keys": rows}

    async def revoke_key(ctx: EndpointContext) -> dict[str, Any]:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        body: RevokeApiKeyBody = ctx.body
        row = await ctx.auth.adapter.find_one(
            model="apiKey",
            where=(Where(field="id", value=body.id),),
        )
        if row is None or row.get("userId") != ctx.session.user_id:
            raise APIError(404, "API_KEY_NOT_FOUND")
        await ctx.auth.adapter.delete_many(
            model="apiKey",
            where=(Where(field="id", value=body.id),),
        )
        return {"success": True}

    async def verify_key(ctx: EndpointContext) -> dict[str, Any]:
        body: VerifyApiKeyBody = ctx.body
        row = await _verify_lookup(ctx, body.key)
        if row is None:
            return {"valid": False}
        scope = row.get("scope")
        if isinstance(scope, str):
            try:
                scope = json.loads(scope)
            except json.JSONDecodeError:
                scope = None
        return {"valid": True, "userId": row["userId"], "scope": scope}

    endpoints = (
        create_auth_endpoint(
            "/api-key/create",
            EndpointOptions(method="POST", body=CreateApiKeyBody),
            create_key,
        ),
        create_auth_endpoint(
            "/api-key/list",
            EndpointOptions(method="GET"),
            list_keys,
        ),
        create_auth_endpoint(
            "/api-key/revoke",
            EndpointOptions(method="POST", body=RevokeApiKeyBody),
            revoke_key,
        ),
        create_auth_endpoint(
            "/api-key/verify",
            EndpointOptions(method="POST", body=VerifyApiKeyBody),
            verify_key,
        ),
    )

    # `on_request`: resolve `Authorization: ApiKey <key>` headers into a session.
    async def on_request(ctx: EndpointContext) -> None:
        if ctx.session is not None:
            return
        auth_header = ctx.request.headers.get("authorization", "")
        if not auth_header.lower().startswith("apikey "):
            return
        raw = auth_header.split(" ", 1)[1].strip()
        row = await _verify_lookup(ctx, raw)
        if row is not None:
            _attach_synthetic_session(ctx, row)

    return _ApiKeyPlugin(  # type: ignore[return-value]
        schema=PluginSchema(tables=(API_KEY_MODEL,)),
        endpoints=endpoints,
        on_request=on_request,
    )
