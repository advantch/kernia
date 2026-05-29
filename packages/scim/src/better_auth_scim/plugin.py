"""SCIM 2.0 plugin construction.

Exposes the standard SCIM 2.0 surface for the User resource type. Groups
support is best-effort — when the `organization` plugin's `member` table is
present we surface organizations as groups; otherwise the Groups routes return
empty collections (documented).

Authentication: an admin session OR an `api_key` whose stored `permissions`
map carries the `"scim"` resource.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.crypto import hash_password
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema

from better_auth_scim.patch import apply_patch_ops

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


SCIM_ERROR_CODES: Mapping[str, str] = {
    "SCIM_UNAUTHORIZED": "SCIM access requires admin or api-key with scim scope.",
    "SCIM_INVALID_REQUEST": "SCIM request is malformed.",
}


# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SCIMOptions:
    require_admin: bool = True
    admin_roles: tuple[str, ...] = ("admin",)


def _scim_error(status: int, code: str, detail: str) -> APIError:
    return APIError(
        status,
        code,
        message=detail,
        data={"schemas": [SCIM_ERROR_SCHEMA], "status": str(status), "detail": detail},
    )


def _user_to_scim(user: dict[str, Any]) -> dict[str, Any]:
    name = user.get("name") or ""
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user["id"],
        "userName": user.get("email"),
        "name": {"formatted": name},
        "displayName": name or user.get("email"),
        "active": not bool(user.get("banned")),
        "emails": [{"primary": True, "value": user.get("email")}],
        "meta": {
            "resourceType": "User",
            "created": user.get("createdAt"),
            "lastModified": user.get("updatedAt"),
            "location": f"/scim/v2/Users/{user['id']}",
        },
    }


def _scim_to_user_updates(payload: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if "userName" in payload:
        out["email"] = payload["userName"]
    emails = payload.get("emails")
    if isinstance(emails, list) and emails:
        primary = next((e for e in emails if e.get("primary")), emails[0])
        if isinstance(primary, dict) and primary.get("value"):
            out["email"] = primary["value"]
    name = payload.get("name")
    if isinstance(name, Mapping):
        formatted = name.get("formatted") or " ".join(
            [s for s in (name.get("givenName"), name.get("familyName")) if s]
        ).strip()
        if formatted:
            out["name"] = formatted
    elif "displayName" in payload:
        out["name"] = payload["displayName"]
    if "active" in payload:
        out["banned"] = not bool(payload["active"])
    return out


async def _is_scim_authorized(ctx: EndpointContext, opts: SCIMOptions) -> bool:
    # 1. API key scope.scim == true. If the request was authenticated via an
    # ApiKey header we never fall back to a cookie-based admin check — the key
    # acts as the sole credential and must carry the scim scope explicitly.
    auth_header = ctx.request.headers.get("authorization", "")
    if auth_header.lower().startswith("apikey "):
        raw = auth_header.split(" ", 1)[1].strip()
        from better_auth_api_key import default_key_hasher

        # The api-key package stores SHA-256(key) under the `key` column of the
        # `apikey` table (upstream schema). SCIM scope is carried in the key's
        # `permissions` map under the "scim" resource.
        hashed = default_key_hasher(raw)
        row = await ctx.auth.adapter.find_one(
            model="apikey",
            where=(Where(field="key", value=hashed),),
        )
        if row is not None and row.get("enabled", True):
            perms = row.get("permissions")
            if isinstance(perms, str):
                try:
                    perms = json.loads(perms)
                except json.JSONDecodeError:
                    perms = None
            if isinstance(perms, Mapping) and perms.get("scim"):
                return True
        return False
    # 2. Admin role on the session user
    if ctx.session is None:
        return False
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if user is None:
        return False
    role = str(user.get("role") or "user")
    return any(r.strip() in opts.admin_roles for r in role.split(","))


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SCIMPlugin:
    id: str = "scim"
    version: str | None = "0.0.0"
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    error_codes: Mapping[str, str] = field(default_factory=lambda: dict(SCIM_ERROR_CODES))
    init: None = None


def scim(options: SCIMOptions | None = None) -> BetterAuthPlugin:
    opts = options or SCIMOptions()

    async def _gate(ctx: EndpointContext) -> None:
        if not await _is_scim_authorized(ctx, opts):
            raise _scim_error(401, "SCIM_UNAUTHORIZED", "Unauthorized")

    async def list_users(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        query = ctx.request.query
        start = int(_first(query, "startIndex", "1"))
        count = int(_first(query, "count", "50"))
        offset = max(0, start - 1)
        rows = await ctx.auth.adapter.find_many(
            model="user", limit=count, offset=offset
        )
        total = await ctx.auth.adapter.count(model="user")
        return {
            "schemas": [SCIM_LIST_RESPONSE],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": len(rows),
            "Resources": [_user_to_scim(r) for r in rows],
        }

    async def get_user(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        user_id = ctx.path_params.get("id", "")
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=user_id),)
        )
        if not user:
            raise _scim_error(404, "USER_NOT_FOUND", "User not found")
        return _user_to_scim(user)

    async def create_user(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        raw = await ctx.request.json()
        if not isinstance(raw, dict):
            raise _scim_error(400, "SCIM_INVALID_REQUEST", "Body must be a JSON object")
        email = raw.get("userName")
        if not email:
            primary = (raw.get("emails") or [{}])[0]
            email = primary.get("value")
        if not email:
            raise _scim_error(400, "SCIM_INVALID_REQUEST", "userName or emails[0].value required")
        existing = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="email", value=email),)
        )
        if existing:
            raise _scim_error(409, "USER_ALREADY_EXISTS", "User already exists")
        now = int(time.time())
        name_field = raw.get("name") or {}
        full_name = (
            name_field.get("formatted")
            if isinstance(name_field, dict)
            else None
        ) or raw.get("displayName")
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                "email": email,
                "name": full_name,
                "emailVerified": False,
                "createdAt": now,
                "updatedAt": now,
            },
        )
        # If a password was supplied via the urn extension, set it.
        password = raw.get("password")
        if password:
            await ctx.auth.adapter.create(
                model="account",
                data={
                    "userId": user["id"],
                    "accountId": user["id"],
                    "providerId": "credential",
                    "password": hash_password(password),
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
        return _user_to_scim(user)

    async def replace_user(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        user_id = ctx.path_params.get("id", "")
        raw = await ctx.request.json()
        if not isinstance(raw, dict):
            raise _scim_error(400, "SCIM_INVALID_REQUEST", "Body must be a JSON object")
        updates = _scim_to_user_updates(raw)
        updates["updatedAt"] = int(time.time())
        updated = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user_id),),
            update=updates,
        )
        if not updated:
            raise _scim_error(404, "USER_NOT_FOUND", "User not found")
        return _user_to_scim(updated)

    async def patch_user(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        user_id = ctx.path_params.get("id", "")
        raw = await ctx.request.json()
        if not isinstance(raw, dict):
            raise _scim_error(400, "SCIM_INVALID_REQUEST", "Body must be a JSON object")
        ops = raw.get("Operations") or []
        if not isinstance(ops, list):
            raise _scim_error(400, "SCIM_INVALID_REQUEST", "Operations must be a list")

        existing = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=user_id),)
        )
        if not existing:
            raise _scim_error(404, "USER_NOT_FOUND", "User not found")
        # Apply patch to the SCIM document to validate ops, but build the
        # user-row update map from the operations directly so we only touch
        # the changed fields.
        scim_doc = _user_to_scim(existing)
        try:
            apply_patch_ops(scim_doc, ops)
        except ValueError as e:
            raise _scim_error(400, "SCIM_INVALID_REQUEST", str(e)) from None
        updates: dict[str, Any] = {}
        for op in ops:
            path = (op.get("path") or "").lower()
            value = op.get("value")
            if path == "username" or path.startswith("emails"):
                # take from patched doc which already absorbed any add/replace
                updates["email"] = scim_doc.get("userName")
            elif path == "displayname":
                updates["name"] = value
            elif path == "name.formatted" or path == "name":
                updates["name"] = (
                    value.get("formatted") if isinstance(value, Mapping) else value
                )
            elif path == "active":
                updates["banned"] = not bool(value)
        updates["updatedAt"] = int(time.time())
        updated = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user_id),),
            update=updates,
        )
        return _user_to_scim(updated or existing)

    async def delete_user(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        user_id = ctx.path_params.get("id", "")
        await ctx.auth.adapter.delete_many(
            model="session", where=(Where(field="userId", value=user_id),)
        )
        await ctx.auth.adapter.delete_many(
            model="account", where=(Where(field="userId", value=user_id),)
        )
        await ctx.auth.adapter.delete_many(
            model="user", where=(Where(field="id", value=user_id),)
        )
        return {"success": True}

    async def service_provider_config(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://better-auth.com/docs/plugins/scim",
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": False, "maxResults": 0},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {"name": "OAuth Bearer Token", "type": "oauthbearertoken"},
                {"name": "API Key", "type": "httpbasic"},
            ],
        }

    async def resource_types(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        return {
            "schemas": [SCIM_LIST_RESPONSE],
            "totalResults": 2,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "User",
                    "name": "User",
                    "endpoint": "/Users",
                    "schema": SCIM_USER_SCHEMA,
                },
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "Group",
                    "name": "Group",
                    "endpoint": "/Groups",
                    "schema": SCIM_GROUP_SCHEMA,
                },
            ],
        }

    async def schemas(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        return {
            "schemas": [SCIM_LIST_RESPONSE],
            "totalResults": 2,
            "Resources": [
                {"id": SCIM_USER_SCHEMA, "name": "User"},
                {"id": SCIM_GROUP_SCHEMA, "name": "Group"},
            ],
        }

    async def list_groups(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        # Best-effort: read from the `organization` model if present; otherwise
        # return an empty list (documented).
        try:
            orgs = await ctx.auth.adapter.find_many(model="organization")
        except Exception:
            orgs = []
        return {
            "schemas": [SCIM_LIST_RESPONSE],
            "totalResults": len(orgs),
            "startIndex": 1,
            "itemsPerPage": len(orgs),
            "Resources": [
                {
                    "schemas": [SCIM_GROUP_SCHEMA],
                    "id": o["id"],
                    "displayName": o.get("name"),
                    "meta": {
                        "resourceType": "Group",
                        "location": f"/scim/v2/Groups/{o['id']}",
                    },
                }
                for o in orgs
            ],
        }

    async def get_group(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        group_id = ctx.path_params.get("id", "")
        try:
            org = await ctx.auth.adapter.find_one(
                model="organization", where=(Where(field="id", value=group_id),)
            )
        except Exception:
            org = None
        if not org:
            raise _scim_error(404, "GROUP_NOT_FOUND", "Group not found")
        return {
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": org["id"],
            "displayName": org.get("name"),
        }

    async def write_group(ctx: EndpointContext) -> dict[str, Any]:
        await _gate(ctx)
        raise _scim_error(
            501, "SCIM_NOT_IMPLEMENTED", "Group writes require the organization plugin"
        )

    endpoints = (
        create_auth_endpoint("/scim/v2/Users", EndpointOptions(method="GET"), list_users),
        create_auth_endpoint(
            "/scim/v2/Users/:id", EndpointOptions(method="GET"), get_user
        ),
        create_auth_endpoint(
            "/scim/v2/Users", EndpointOptions(method="POST"), create_user
        ),
        create_auth_endpoint(
            "/scim/v2/Users/:id", EndpointOptions(method="PUT"), replace_user
        ),
        create_auth_endpoint(
            "/scim/v2/Users/:id", EndpointOptions(method="PATCH"), patch_user
        ),
        create_auth_endpoint(
            "/scim/v2/Users/:id", EndpointOptions(method="DELETE"), delete_user
        ),
        create_auth_endpoint("/scim/v2/Groups", EndpointOptions(method="GET"), list_groups),
        create_auth_endpoint(
            "/scim/v2/Groups/:id", EndpointOptions(method="GET"), get_group
        ),
        create_auth_endpoint(
            "/scim/v2/Groups", EndpointOptions(method="POST"), write_group
        ),
        create_auth_endpoint(
            "/scim/v2/Groups/:id", EndpointOptions(method="PUT"), write_group
        ),
        create_auth_endpoint(
            "/scim/v2/Groups/:id", EndpointOptions(method="PATCH"), write_group
        ),
        create_auth_endpoint(
            "/scim/v2/Groups/:id", EndpointOptions(method="DELETE"), write_group
        ),
        create_auth_endpoint(
            "/scim/v2/ServiceProviderConfig",
            EndpointOptions(method="GET"),
            service_provider_config,
        ),
        create_auth_endpoint(
            "/scim/v2/ResourceTypes", EndpointOptions(method="GET"), resource_types
        ),
        create_auth_endpoint("/scim/v2/Schemas", EndpointOptions(method="GET"), schemas),
    )

    return _SCIMPlugin(endpoints=endpoints)  # type: ignore[return-value]


def _first(q: Mapping[str, Any], key: str, default: str) -> str:
    v = q.get(key)
    if v is None:
        return default
    if isinstance(v, list):
        return str(v[0]) if v else default
    return str(v)
