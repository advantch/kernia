"""better-auth SCIM 2.0 plugin.

Mirrors ``reference/packages/scim/src/index.ts`` + ``routes.ts`` +
``middlewares.ts``. Exposes:

  * Provider/token management (org-scoped): ``/scim/generate-token``,
    ``/scim/list-provider-connections``, ``/scim/get-provider-connection``,
    ``/scim/delete-provider-connection``. These require a logged-in session.
  * The SCIM 2.0 User surface under ``/scim/v2/`` authenticated by a Bearer
    ``scimToken`` (NOT a session/api-key).
  * Discovery endpoints (``ServiceProviderConfig``/``Schemas``/``ResourceTypes``).

Authentication for ``/scim/v2/`` is a Bearer ``scimToken`` — a base64url-encoded
``baseToken:providerId[:organizationId]`` string. The core router does not run an
endpoint's ``use`` middlewares, so the auth check is performed inline at the top
of every SCIM v2 handler via :func:`_authenticate`.

Known parity caveat: the Python core router always renders dict handler results
with HTTP 200 (it cannot emit 201/204). Upstream sets 201 on create and 204 on
patch/delete. Behaviour (body + ``location`` header) is otherwise identical; the
ported tests assert on the body and headers rather than the numeric status.
"""

from __future__ import annotations

import base64
import secrets
import string
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema

from kernia_scim.mappings import (
    get_account_id,
    get_resource_url,
    get_user_full_name,
    get_user_primary_email,
)
from kernia_scim.patch_operations import build_user_patch
from kernia_scim.schemas import (
    SCIM_USER_RESOURCE_SCHEMA,
    SCIM_USER_RESOURCE_TYPE,
)
from kernia_scim.scim_error import SCIMAPIError
from kernia_scim.scim_filters import SCIMParseError, parse_scim_user_filter
from kernia_scim.scim_resources import create_user_resource
from kernia_scim.scim_tokens import store_scim_token, verify_scim_token
from kernia_scim.types import SCIMOptions, SCIMProvider

LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

# providerIds that collide with built-in account.providerId values — issuing a
# SCIM token for these would allow acting against non-SCIM-provisioned accounts.
_RESERVED_PROVIDER_IDS = frozenset(
    {"credential", "email-otp", "magic-link", "phone-number", "anonymous", "siwe"}
)

_TOKEN_ALPHABET = string.ascii_letters + string.digits


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _generate_random_string(length: int) -> str:
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(length))


def _b64url_encode(value: str) -> str:
    raw = base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=")
    return raw.decode("ascii")


def _b64url_decode(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")


def _parse_member_roles(role: str) -> list[str]:
    return [entry.strip() for entry in role.split(",") if entry.strip()]


def _has_required_role(member_role: str, required_role: list[str]) -> bool:
    if not required_role:
        return True
    return any(role in required_role for role in _parse_member_roles(member_role))


def _get_plugin(ctx: EndpointContext, plugin_id: str) -> Any | None:
    for plugin in ctx.auth.plugins:
        if getattr(plugin, "id", None) == plugin_id:
            return plugin
    return None


def _has_plugin(ctx: EndpointContext, plugin_id: str) -> bool:
    return _get_plugin(ctx, plugin_id) is not None


def _resolve_required_roles(ctx: EndpointContext, opts: SCIMOptions) -> list[str]:
    if opts.required_role:
        return list(opts.required_role)

    creator_role: str | None = opts.creator_role
    if creator_role is None:
        org_plugin = _get_plugin(ctx, "organization")
        org_options = getattr(org_plugin, "options", None) if org_plugin else None
        if isinstance(org_options, Mapping):
            creator_role = org_options.get("creatorRole") or org_options.get(
                "creator_role"
            )
        else:
            creator_role = getattr(org_options, "creator_role", None) or getattr(
                org_options, "creatorRole", None
            )

    seen: dict[str, None] = {}
    for role in ("admin", creator_role or "owner"):
        seen.setdefault(role, None)
    return list(seen)


def _is_provider_ownership_enabled(opts: SCIMOptions) -> bool:
    return bool(opts.provider_ownership and opts.provider_ownership.enabled)


def _require_session_user_id(ctx: EndpointContext) -> str:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED", message="Unauthorized")
    return ctx.session.user_id


async def _request_session_user(ctx: EndpointContext) -> dict[str, Any]:
    user_id = _require_session_user_id(ctx)
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=user_id),)
    )
    if user is None:
        raise APIError(401, "UNAUTHORIZED", message="Unauthorized")
    return user


async def _find_organization_member(
    ctx: EndpointContext, user_id: str, organization_id: str
) -> dict[str, Any] | None:
    return await ctx.auth.adapter.find_one(
        model="member",
        where=(
            Where(field="userId", value=user_id),
            Where(field="organizationId", value=organization_id),
        ),
    )


def _normalize_scim_provider(provider: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": provider.get("id"),
        "providerId": provider.get("providerId"),
        "organizationId": provider.get("organizationId") or None,
    }


async def _assert_scim_provider_access(
    ctx: EndpointContext,
    user_id: str,
    provider: Mapping[str, Any],
    required_role: list[str],
) -> None:
    organization_id = provider.get("organizationId")
    if organization_id:
        if not _has_plugin(ctx, "organization"):
            raise APIError(
                403,
                "FORBIDDEN",
                message="Organization plugin is required to access this SCIM provider",
            )
        member = await _find_organization_member(ctx, user_id, organization_id)
        if not member:
            raise APIError(
                403,
                "FORBIDDEN",
                message="You must be a member of the organization to access this provider",
            )
        if not _has_required_role(member.get("role", ""), required_role):
            raise APIError(
                403, "FORBIDDEN", message="Insufficient role for this operation"
            )
    elif provider.get("userId") and provider.get("userId") != user_id:
        raise APIError(
            403, "FORBIDDEN", message="You must be the owner to access this provider"
        )


async def _check_scim_provider_access(
    ctx: EndpointContext,
    user_id: str,
    provider_id: str,
    required_role: list[str],
) -> dict[str, Any]:
    provider = await ctx.auth.adapter.find_one(
        model="scimProvider",
        where=(Where(field="providerId", value=provider_id),),
    )
    if not provider:
        raise APIError(404, "NOT_FOUND", message="SCIM provider not found")
    await _assert_scim_provider_access(ctx, user_id, provider, required_role)
    return provider


async def _find_user_by_id(
    ctx: EndpointContext,
    *,
    user_id: str,
    provider_id: str,
    organization_id: str | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    account = await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=user_id),
            Where(field="providerId", value=provider_id),
        ),
    )
    if not account:
        return None, None

    if organization_id:
        member = await ctx.auth.adapter.find_one(
            model="member",
            where=(
                Where(field="organizationId", value=organization_id),
                Where(field="userId", value=user_id),
            ),
        )
        if not member:
            return None, None

    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=user_id),)
    )
    if not user:
        return None, None
    return user, account


# ---------------------------------------------------------------------------
# SCIM v2 Bearer-token authentication (inline; router skips `use`)
# ---------------------------------------------------------------------------


async def _authenticate(ctx: EndpointContext, opts: SCIMOptions) -> dict[str, Any]:
    """Resolve and validate the Bearer ``scimToken``, returning the provider row."""
    auth_header = ctx.request.headers.get("authorization") or ctx.request.headers.get(
        "Authorization"
    )
    auth_scim_token = ""
    if auth_header:
        stripped = auth_header.strip()
        if stripped.lower().startswith("bearer "):
            auth_scim_token = stripped[len("bearer ") :].strip()

    if not auth_scim_token:
        raise SCIMAPIError("UNAUTHORIZED", detail="SCIM token is required")

    try:
        decoded = _b64url_decode(auth_scim_token)
    except Exception:
        raise SCIMAPIError("UNAUTHORIZED", detail="Invalid SCIM token") from None

    parts = decoded.split(":")
    scim_token = parts[0] if parts else ""
    provider_id = parts[1] if len(parts) > 1 else ""
    organization_id = ":".join(parts[2:])

    if not scim_token or not provider_id:
        raise SCIMAPIError("UNAUTHORIZED", detail="Invalid SCIM token")

    # In-memory default providers take precedence over the DB.
    default_provider = None
    for p in opts.default_scim:
        if p.provider_id == provider_id and not organization_id:
            default_provider = p
            break
        if (
            p.provider_id == provider_id
            and organization_id
            and p.organization_id == organization_id
        ):
            default_provider = p
            break

    if default_provider is not None:
        if default_provider.scim_token == scim_token:
            return {
                "providerId": default_provider.provider_id,
                "organizationId": default_provider.organization_id,
                "scimToken": default_provider.scim_token,
            }
        raise SCIMAPIError("UNAUTHORIZED", detail="Invalid SCIM token")

    where = [Where(field="providerId", value=provider_id)]
    if organization_id:
        where.append(Where(field="organizationId", value=organization_id))
    provider = await ctx.auth.adapter.find_one(model="scimProvider", where=tuple(where))

    if not provider:
        raise SCIMAPIError("UNAUTHORIZED", detail="Invalid SCIM token")

    is_valid = await verify_scim_token(ctx, opts, provider["scimToken"], scim_token)
    if not is_valid:
        raise SCIMAPIError("UNAUTHORIZED", detail="Invalid SCIM token")
    return provider


def _parse_scim_api_user_filter(filter_str: str | None) -> list[Any]:
    if not filter_str:
        return []
    try:
        return parse_scim_user_filter(filter_str)
    except SCIMParseError as e:
        raise SCIMAPIError(
            "BAD_REQUEST", detail=str(e), scimType="invalidFilter"
        ) from None
    except Exception:
        raise SCIMAPIError(
            "BAD_REQUEST", detail="Invalid SCIM filter", scimType="invalidFilter"
        ) from None


def _query_value(ctx: EndpointContext, key: str) -> str | None:
    raw = ctx.request.query.get(key)
    if raw is None:
        return None
    if isinstance(raw, list):
        return str(raw[0]) if raw else None
    return str(raw)


async def _read_json_object(ctx: EndpointContext) -> dict[str, Any]:
    try:
        body = await ctx.request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        return {}
    return body


# ---------------------------------------------------------------------------
# Plugin object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SCIMPlugin:
    id: str = "scim"
    version: str | None = "0.0.0"
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: None = None
    database_hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    error_codes: Mapping[str, str] = field(default_factory=dict)
    init: None = None
    options: SCIMOptions | None = None


def scim(options: SCIMOptions | None = None) -> KerniaPlugin:
    opts = options or SCIMOptions()

    provider_fields = [
        FieldDef("providerId", "string", required=True, unique=True),
        FieldDef("scimToken", "string", required=True, unique=True),
        FieldDef("organizationId", "string", required=False),
    ]
    if _is_provider_ownership_enabled(opts):
        provider_fields.append(FieldDef("userId", "string", required=False))

    schema = PluginSchema(
        tables=(ModelDef(name="scimProvider", fields=tuple(provider_fields)),)
    )

    # -- provider/token management -----------------------------------------

    async def generate_scim_token(ctx: EndpointContext) -> dict[str, Any]:
        user = await _request_session_user(ctx)
        body = await _read_json_object(ctx)
        provider_id = body.get("providerId")
        organization_id = body.get("organizationId") or None
        required_role = _resolve_required_roles(ctx, opts)

        if not provider_id or not isinstance(provider_id, str):
            raise APIError(400, "BAD_REQUEST", message="providerId is required")

        if ":" in provider_id:
            raise APIError(
                400, "BAD_REQUEST", message="Provider id contains forbidden characters"
            )

        reserved = set(_RESERVED_PROVIDER_IDS)
        reserved.update((ctx.auth.options.social_providers or {}).keys())
        if provider_id in reserved:
            raise APIError(
                400,
                "BAD_REQUEST",
                message="Provider id collides with a built-in account provider and cannot be used for SCIM",
            )

        if organization_id and not _has_plugin(ctx, "organization"):
            raise APIError(
                400,
                "BAD_REQUEST",
                message="Restricting a token to an organization requires the organization plugin",
            )

        member: dict[str, Any] | None = None
        if organization_id:
            member = await _find_organization_member(ctx, user["id"], organization_id)
            if not member:
                raise APIError(
                    403,
                    "FORBIDDEN",
                    message="You are not a member of the organization",
                )
            if not _has_required_role(member.get("role", ""), required_role):
                raise APIError(
                    403, "FORBIDDEN", message="Insufficient role for this operation"
                )

        where = [Where(field="providerId", value=provider_id)]
        if organization_id:
            where.append(Where(field="organizationId", value=organization_id))
        existing = await ctx.auth.adapter.find_one(
            model="scimProvider", where=tuple(where)
        )
        if existing:
            await _assert_scim_provider_access(
                ctx, user["id"], existing, required_role
            )
            await ctx.auth.adapter.delete(
                model="scimProvider",
                where=(Where(field="id", value=existing["id"]),),
            )

        base_token = _generate_random_string(24)
        token_payload = f"{base_token}:{provider_id}"
        if organization_id:
            token_payload += f":{organization_id}"
        scim_token = _b64url_encode(token_payload)

        if opts.before_scim_token_generated:
            result = opts.before_scim_token_generated(
                {"user": user, "member": member, "scimToken": scim_token}
            )
            if hasattr(result, "__await__"):
                await result

        data: dict[str, Any] = {
            "providerId": provider_id,
            "organizationId": organization_id,
            "scimToken": await store_scim_token(ctx, opts, base_token),
        }
        if _is_provider_ownership_enabled(opts):
            data["userId"] = user["id"]
        new_provider = await ctx.auth.adapter.create(
            model="scimProvider", data=data
        )

        if opts.after_scim_token_generated:
            result = opts.after_scim_token_generated(
                {
                    "user": user,
                    "member": member,
                    "scimToken": scim_token,
                    "scimProvider": new_provider,
                }
            )
            if hasattr(result, "__await__"):
                await result

        ctx.response_headers["x-scim-status"] = "201"
        return {"scimToken": scim_token}

    async def list_provider_connections(ctx: EndpointContext) -> dict[str, Any]:
        user_id = _require_session_user_id(ctx)
        required_role = _resolve_required_roles(ctx, opts)

        org_memberships: dict[str, list[str]] = {}
        if _has_plugin(ctx, "organization"):
            members = await ctx.auth.adapter.find_many(
                model="member",
                where=(Where(field="userId", value=user_id),),
            )
            for m in members:
                org_memberships[m["organizationId"]] = _parse_member_roles(
                    m.get("role", "")
                )

        all_providers = await ctx.auth.adapter.find_many(model="scimProvider")

        accessible: list[dict[str, Any]] = []
        for p in all_providers:
            org_id = p.get("organizationId")
            if org_id:
                roles = org_memberships.get(org_id)
                if roles is None:
                    continue
                if not required_role or any(r in required_role for r in roles):
                    accessible.append(p)
            else:
                if p.get("userId") == user_id or not p.get("userId"):
                    accessible.append(p)

        return {"providers": [_normalize_scim_provider(p) for p in accessible]}

    async def get_provider_connection(ctx: EndpointContext) -> dict[str, Any]:
        user_id = _require_session_user_id(ctx)
        provider_id = _query_value(ctx, "providerId")
        if not provider_id:
            raise APIError(400, "BAD_REQUEST", message="providerId is required")
        required_role = _resolve_required_roles(ctx, opts)
        provider = await _check_scim_provider_access(
            ctx, user_id, provider_id, required_role
        )
        return _normalize_scim_provider(provider)

    async def delete_provider_connection(ctx: EndpointContext) -> dict[str, Any]:
        user_id = _require_session_user_id(ctx)
        body = await _read_json_object(ctx)
        provider_id = body.get("providerId")
        if not provider_id:
            raise APIError(400, "BAD_REQUEST", message="providerId is required")
        required_role = _resolve_required_roles(ctx, opts)
        await _check_scim_provider_access(ctx, user_id, provider_id, required_role)
        await ctx.auth.adapter.delete(
            model="scimProvider",
            where=(Where(field="providerId", value=provider_id),),
        )
        return {"success": True}

    # -- SCIM v2 User CRUD --------------------------------------------------

    async def create_scim_user(ctx: EndpointContext) -> dict[str, Any]:
        provider = await _authenticate(ctx, opts)
        body = await _read_json_object(ctx)
        provider_id = provider["providerId"]
        user_name = body.get("userName")
        external_id = body.get("externalId")
        account_id = get_account_id(user_name, external_id)

        existing_account = await ctx.auth.adapter.find_one(
            model="account",
            where=(
                Where(field="accountId", value=account_id),
                Where(field="providerId", value=provider_id),
            ),
        )
        if existing_account:
            raise SCIMAPIError(
                "CONFLICT", detail="User already exists", scimType="uniqueness"
            )

        email = get_user_primary_email(user_name, body.get("emails"))
        name = get_user_full_name(email, body.get("name"))

        existing_user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="email", value=email),)
        )

        async def _create_account(uid: str) -> dict[str, Any]:
            return await ctx.auth.adapter.create(
                model="account",
                data={
                    "userId": uid,
                    "providerId": provider_id,
                    "accountId": account_id,
                    "accessToken": "",
                    "refreshToken": "",
                },
            )

        async def _create_org_membership(uid: str) -> None:
            org_id = provider.get("organizationId")
            if not org_id:
                return
            is_member = await ctx.auth.adapter.find_one(
                model="member",
                where=(
                    Where(field="organizationId", value=org_id),
                    Where(field="userId", value=uid),
                ),
            )
            if not is_member:
                await ctx.auth.adapter.create(
                    model="member",
                    data={
                        "userId": uid,
                        "role": "member",
                        "organizationId": org_id,
                    },
                )

        async with ctx.auth.transaction():
            if existing_user:
                user = existing_user
            else:
                user = await ctx.auth.adapter.create(
                    model="user",
                    data={"email": email, "name": name, "emailVerified": False},
                )
            account = await _create_account(user["id"])
            await _create_org_membership(user["id"])

        resource = create_user_resource(ctx.auth.base_url, user, account)
        ctx.response_headers["location"] = resource["meta"]["location"]
        ctx.response_headers["x-scim-status"] = "201"
        return resource

    async def update_scim_user(ctx: EndpointContext) -> dict[str, Any]:
        provider = await _authenticate(ctx, opts)
        body = await _read_json_object(ctx)
        user_id = ctx.path_params.get("userId", "")
        provider_id = provider["providerId"]
        organization_id = provider.get("organizationId")
        account_id = get_account_id(body.get("userName"), body.get("externalId"))

        user, account = await _find_user_by_id(
            ctx,
            user_id=user_id,
            provider_id=provider_id,
            organization_id=organization_id,
        )
        if not user or not account:
            raise SCIMAPIError("NOT_FOUND", detail="User not found")

        email = get_user_primary_email(body.get("userName"), body.get("emails"))
        name = get_user_full_name(email, body.get("name"))

        async with ctx.auth.transaction():
            updated_user = await ctx.auth.adapter.update(
                model="user",
                where=(Where(field="id", value=user_id),),
                update={"email": email, "name": name},
            )
            updated_account = await ctx.auth.adapter.update(
                model="account",
                where=(Where(field="id", value=account["id"]),),
                update={"accountId": account_id},
            )

        return create_user_resource(
            ctx.auth.base_url, updated_user or user, updated_account or account
        )

    async def list_scim_users(ctx: EndpointContext) -> dict[str, Any]:
        provider = await _authenticate(ctx, opts)

        empty = {
            "schemas": [LIST_RESPONSE_SCHEMA],
            "totalResults": 0,
            "startIndex": 1,
            "itemsPerPage": 0,
            "Resources": [],
        }

        api_filters = _parse_scim_api_user_filter(_query_value(ctx, "filter"))
        provider_id = provider["providerId"]

        accounts = await ctx.auth.adapter.find_many(
            model="account",
            where=(Where(field="providerId", value=provider_id),),
        )
        account_user_ids = [a["userId"] for a in accounts]
        if not account_user_ids:
            return empty

        user_filters: list[Where] = [
            Where(field="id", value=account_user_ids, operator="in")
        ]

        organization_id = provider.get("organizationId")
        if organization_id:
            members = await ctx.auth.adapter.find_many(
                model="member",
                where=(
                    Where(field="organizationId", value=organization_id),
                    Where(field="userId", value=account_user_ids, operator="in"),
                ),
            )
            member_user_ids = [m["userId"] for m in members]
            if not member_user_ids:
                return empty
            user_filters = [Where(field="id", value=member_user_ids, operator="in")]

        where = tuple(user_filters) + tuple(
            Where(field=f.field, value=f.value, operator=f.operator or "eq")
            for f in api_filters
        )
        users = await ctx.auth.adapter.find_many(model="user", where=where)

        resources = []
        for user in users:
            account = next((a for a in accounts if a["userId"] == user["id"]), None)
            resources.append(
                create_user_resource(ctx.auth.base_url, user, account)
            )

        return {
            "schemas": [LIST_RESPONSE_SCHEMA],
            "totalResults": len(users),
            "startIndex": 1,
            "itemsPerPage": len(users),
            "Resources": resources,
        }

    async def get_scim_user(ctx: EndpointContext) -> dict[str, Any]:
        provider = await _authenticate(ctx, opts)
        user_id = ctx.path_params.get("userId", "")
        user, account = await _find_user_by_id(
            ctx,
            user_id=user_id,
            provider_id=provider["providerId"],
            organization_id=provider.get("organizationId"),
        )
        if not user:
            raise SCIMAPIError("NOT_FOUND", detail="User not found")
        return create_user_resource(ctx.auth.base_url, user, account)

    async def patch_scim_user(ctx: EndpointContext) -> dict[str, Any]:
        provider = await _authenticate(ctx, opts)
        body = await _read_json_object(ctx)
        user_id = ctx.path_params.get("userId", "")

        schemas = body.get("schemas") or []
        if PATCH_OP_SCHEMA not in schemas:
            raise SCIMAPIError("BAD_REQUEST", detail="Invalid schemas for PatchOp")
        operations = body.get("Operations") or []

        # Validate the `op` field up front, mirroring the upstream zod schema
        # (`z.enum(["replace", "add", "remove"])`). An unknown op yields a
        # VALIDATION_ERROR envelope, not a SCIM error, and is checked before
        # the user lookup.
        for index, op in enumerate(operations):
            if not isinstance(op, Mapping):
                continue
            op_value = op.get("op")
            if op_value is None:
                continue
            if str(op_value).lower() not in ("replace", "add", "remove"):
                raise APIError(
                    400,
                    "VALIDATION_ERROR",
                    f"[body.Operations.{index}.op] Invalid option: "
                    'expected one of "replace"|"add"|"remove"',
                )

        user, account = await _find_user_by_id(
            ctx,
            user_id=user_id,
            provider_id=provider["providerId"],
            organization_id=provider.get("organizationId"),
        )
        if not user or not account:
            raise SCIMAPIError("NOT_FOUND", detail="User not found")

        # Normalize op casing + default to "replace" (mirrors upstream zod schema).
        normalized_ops = []
        for op in operations:
            if not isinstance(op, Mapping):
                continue
            normalized_ops.append(
                {
                    "op": str(op.get("op", "replace")).lower(),
                    "path": op.get("path"),
                    "value": op.get("value"),
                }
            )

        patch = build_user_patch(user, normalized_ops)
        user_patch = patch["user"]
        account_patch = patch["account"]

        if not user_patch and not account_patch:
            raise SCIMAPIError("BAD_REQUEST", detail="No valid fields to update")

        async with ctx.auth.transaction():
            if user_patch:
                await ctx.auth.adapter.update(
                    model="user",
                    where=(Where(field="id", value=user_id),),
                    update=dict(user_patch),
                )
            if account_patch:
                await ctx.auth.adapter.update(
                    model="account",
                    where=(Where(field="id", value=account["id"]),),
                    update=dict(account_patch),
                )

        ctx.response_headers["x-scim-status"] = "204"
        return {}

    async def delete_scim_user(ctx: EndpointContext) -> dict[str, Any]:
        provider = await _authenticate(ctx, opts)
        user_id = ctx.path_params.get("userId", "")
        user, _account = await _find_user_by_id(
            ctx,
            user_id=user_id,
            provider_id=provider["providerId"],
            organization_id=provider.get("organizationId"),
        )
        if not user:
            raise SCIMAPIError("NOT_FOUND", detail="User not found")

        await _delete_user_sessions(ctx, user_id)
        await ctx.auth.adapter.delete_many(
            model="account", where=(Where(field="userId", value=user_id),)
        )
        await ctx.auth.adapter.delete(
            model="user", where=(Where(field="id", value=user_id),)
        )
        ctx.response_headers["x-scim-status"] = "204"
        return {}

    # -- discovery endpoints ------------------------------------------------

    async def service_provider_config(ctx: EndpointContext) -> dict[str, Any]:
        return {
            "patch": {"supported": True},
            "bulk": {"supported": False},
            "filter": {"supported": True},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "name": "OAuth Bearer Token",
                    "description": (
                        "Authentication scheme using the Authorization header with a "
                        "bearer token tied to an organization."
                    ),
                    "specUri": "http://www.rfc-editor.org/info/rfc6750",
                    "type": "oauthbearertoken",
                    "primary": True,
                }
            ],
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
            ],
            "meta": {"resourceType": "ServiceProviderConfig"},
        }

    async def get_scim_schemas(ctx: EndpointContext) -> dict[str, Any]:
        resources = [_with_location(SCIM_USER_RESOURCE_SCHEMA, ctx.auth.base_url)]
        return {
            "totalResults": 1,
            "itemsPerPage": 1,
            "startIndex": 1,
            "schemas": [LIST_RESPONSE_SCHEMA],
            "Resources": resources,
        }

    async def get_scim_schema(ctx: EndpointContext) -> dict[str, Any]:
        schema_id = ctx.path_params.get("schemaId", "")
        if schema_id != SCIM_USER_RESOURCE_SCHEMA["id"]:
            raise SCIMAPIError("NOT_FOUND", detail="Schema not found")
        return _with_location(SCIM_USER_RESOURCE_SCHEMA, ctx.auth.base_url)

    async def get_scim_resource_types(ctx: EndpointContext) -> dict[str, Any]:
        resources = [_with_location(SCIM_USER_RESOURCE_TYPE, ctx.auth.base_url)]
        return {
            "totalResults": 1,
            "itemsPerPage": 1,
            "startIndex": 1,
            "schemas": [LIST_RESPONSE_SCHEMA],
            "Resources": resources,
        }

    async def get_scim_resource_type(ctx: EndpointContext) -> dict[str, Any]:
        resource_type_id = ctx.path_params.get("resourceTypeId", "")
        if resource_type_id != SCIM_USER_RESOURCE_TYPE["id"]:
            raise SCIMAPIError("NOT_FOUND", detail="Resource type not found")
        return _with_location(SCIM_USER_RESOURCE_TYPE, ctx.auth.base_url)

    endpoints = (
        create_auth_endpoint(
            "/scim/generate-token",
            EndpointOptions(method="POST", requires_session=True),
            generate_scim_token,
        ),
        create_auth_endpoint(
            "/scim/list-provider-connections",
            EndpointOptions(method="GET", requires_session=True),
            list_provider_connections,
        ),
        create_auth_endpoint(
            "/scim/get-provider-connection",
            EndpointOptions(method="GET", requires_session=True),
            get_provider_connection,
        ),
        create_auth_endpoint(
            "/scim/delete-provider-connection",
            EndpointOptions(method="POST", requires_session=True),
            delete_provider_connection,
        ),
        create_auth_endpoint(
            "/scim/v2/Users", EndpointOptions(method="POST"), create_scim_user
        ),
        create_auth_endpoint(
            "/scim/v2/Users", EndpointOptions(method="GET"), list_scim_users
        ),
        create_auth_endpoint(
            "/scim/v2/Users/:userId",
            EndpointOptions(method="GET"),
            get_scim_user,
        ),
        create_auth_endpoint(
            "/scim/v2/Users/:userId",
            EndpointOptions(method="PUT"),
            update_scim_user,
        ),
        create_auth_endpoint(
            "/scim/v2/Users/:userId",
            EndpointOptions(method="PATCH"),
            patch_scim_user,
        ),
        create_auth_endpoint(
            "/scim/v2/Users/:userId",
            EndpointOptions(method="DELETE"),
            delete_scim_user,
        ),
        create_auth_endpoint(
            "/scim/v2/ServiceProviderConfig",
            EndpointOptions(method="GET"),
            service_provider_config,
        ),
        create_auth_endpoint(
            "/scim/v2/Schemas", EndpointOptions(method="GET"), get_scim_schemas
        ),
        create_auth_endpoint(
            "/scim/v2/Schemas/:schemaId",
            EndpointOptions(method="GET"),
            get_scim_schema,
        ),
        create_auth_endpoint(
            "/scim/v2/ResourceTypes",
            EndpointOptions(method="GET"),
            get_scim_resource_types,
        ),
        create_auth_endpoint(
            "/scim/v2/ResourceTypes/:resourceTypeId",
            EndpointOptions(method="GET"),
            get_scim_resource_type,
        ),
    )

    return _SCIMPlugin(schema=schema, endpoints=endpoints, options=opts)  # type: ignore[return-value]


def _with_location(resource: dict[str, Any], base_url: str) -> dict[str, Any]:
    out = dict(resource)
    out["meta"] = dict(resource["meta"])
    out["meta"]["location"] = get_resource_url(resource["meta"]["location"], base_url)
    return out


async def _delete_user_sessions(ctx: EndpointContext, user_id: str) -> None:
    """Delete a user's sessions, clearing secondary storage when present."""
    sessions = await ctx.auth.adapter.find_many(
        model="session", where=(Where(field="userId", value=user_id),)
    )
    secondary = getattr(ctx.auth, "secondary_storage", None)
    if secondary is not None:
        for session in sessions:
            token = session.get("token")
            if token is None:
                continue
            delete = getattr(secondary, "delete", None)
            if delete is not None:
                result = delete(token)
                if hasattr(result, "__await__"):
                    await result
    await ctx.auth.adapter.delete_many(
        model="session", where=(Where(field="userId", value=user_id),)
    )


__all__ = ["SCIMOptions", "SCIMProvider", "scim"]
