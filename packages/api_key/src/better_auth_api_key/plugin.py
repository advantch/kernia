"""API key plugin — behavioral parity port of ``reference/packages/api-key``.

Surface (all camelCase on the wire, mapped to snake_case dataclass fields by the
core router):

  * POST ``/api-key/create``                  — mint a key, returns plaintext once
  * POST ``/api-key/verify``                  — validate a key (no session needed)
  * GET  ``/api-key/get``                      — fetch one key by id (owner only)
  * POST ``/api-key/update``                  — mutate a key (owner only)
  * POST ``/api-key/delete``                  — delete a key (owner only)
  * GET  ``/api-key/list``                     — list the caller's keys (+pagination)
  * POST ``/api-key/delete-all-expired-api-keys`` — bulk purge expired keys

Keys are hashed at rest with SHA-256 (base64url, unpadded) like upstream's
``defaultKeyHasher`` so lookup is a deterministic hash match. ``disableKeyHashing``
stores the plaintext key instead. The plaintext is only ever returned on create.

Dates (``expiresAt``/``lastRequest``/``lastRefillAt``/``createdAt``/``updatedAt``)
are stored and returned as epoch-milliseconds integers. ``rateLimitTimeWindow`` and
``refillInterval`` are milliseconds; ``expiresIn`` on the wire is **seconds**.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.plugins.access import role
from better_auth.types.adapter import FieldDef, ModelDef, Where
from better_auth.types.context import EndpointContext, Session
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.hooks import BeforeHook, PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema

# --------------------------------------------------------------------------- errors

API_KEY_ERROR_CODES: Mapping[str, str] = {
    "INVALID_METADATA_TYPE": "metadata must be an object or undefined",
    "REFILL_AMOUNT_AND_INTERVAL_REQUIRED": (
        "refillAmount is required when refillInterval is provided"
    ),
    "REFILL_INTERVAL_AND_AMOUNT_REQUIRED": (
        "refillInterval is required when refillAmount is provided"
    ),
    "USER_BANNED": "User is banned",
    "UNAUTHORIZED_SESSION": "Unauthorized or invalid session",
    "KEY_NOT_FOUND": "API Key not found",
    "KEY_DISABLED": "API Key is disabled",
    "KEY_EXPIRED": "API Key has expired",
    "USAGE_EXCEEDED": "API Key has reached its usage limit",
    "KEY_NOT_RECOVERABLE": "API Key is not recoverable",
    "EXPIRES_IN_IS_TOO_SMALL": (
        "The expiresIn is smaller than the predefined minimum value."
    ),
    "EXPIRES_IN_IS_TOO_LARGE": (
        "The expiresIn is larger than the predefined maximum value."
    ),
    "INVALID_REMAINING": "The remaining count is either too large or too small.",
    "INVALID_PREFIX_LENGTH": "The prefix length is either too large or too small.",
    "INVALID_NAME_LENGTH": "The name length is either too large or too small.",
    "METADATA_DISABLED": "Metadata is disabled.",
    "RATE_LIMIT_EXCEEDED": "Rate limit exceeded.",
    "NO_VALUES_TO_UPDATE": "No values to update.",
    "KEY_DISABLED_EXPIRATION": "Custom key expiration values are disabled.",
    "INVALID_API_KEY": "Invalid API key.",
    "INVALID_USER_ID_FROM_API_KEY": "The user id from the API key is invalid.",
    "INVALID_REFERENCE_ID_FROM_API_KEY": "The reference id from the API key is invalid.",
    "INVALID_API_KEY_GETTER_RETURN_TYPE": (
        "API Key getter returned an invalid key type. Expected string."
    ),
    "SERVER_ONLY_PROPERTY": (
        "The property you're trying to set can only be set from the server auth "
        "instance only."
    ),
    "FAILED_TO_UPDATE_API_KEY": "Failed to update API key",
    "NAME_REQUIRED": "API Key name is required.",
    "ORGANIZATION_ID_REQUIRED": (
        "Organization ID is required for organization-owned API keys."
    ),
    "USER_NOT_MEMBER_OF_ORGANIZATION": (
        "You are not a member of the organization that owns this API key."
    ),
    "INSUFFICIENT_API_KEY_PERMISSIONS": (
        "You do not have permission to perform this action on organization API keys."
    ),
    "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND": (
        "No default api-key configuration found."
    ),
    "ORGANIZATION_PLUGIN_REQUIRED": (
        "Organization plugin is required for organization-owned API keys. Please "
        "install and configure the organization plugin."
    ),
}

API_KEY_TABLE_NAME = "apikey"

_DAY_MS = 1000 * 60 * 60 * 24


# --------------------------------------------------------------------------- hashing

_KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def default_key_hasher(key: str) -> str:
    """SHA-256 → base64url (no padding), matching upstream ``defaultKeyHasher``."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def default_key_generator(length: int, prefix: str | None) -> str:
    body = "".join(secrets.choice(_KEY_ALPHABET) for _ in range(length))
    return f"{prefix or ''}{body}"


# --------------------------------------------------------------------------- legacy helpers
# Kept for backward-compatibility with code importing these symbols.


def generate_api_key(length: int = 64, prefix: str | None = None) -> tuple[str, str]:
    """Return ``(plaintext, start)`` for a freshly minted key.

    ``start`` is the first 6 characters (including the prefix) — the value stored
    in the ``start`` column for UI display.
    """
    key = default_key_generator(length, prefix)
    return key, key[:6]


def parse_api_key(raw: str) -> str | None:
    """Return the leading characters of a key, or None for empty input."""
    if not raw:
        return None
    return raw[:6]


# --------------------------------------------------------------------------- options


@dataclass(frozen=True, slots=True)
class KeyExpirationOptions:
    default_expires_in: int | None = None  # seconds; None disables default expiry
    disable_custom_expires_time: bool = False
    min_expires_in: int = 1  # days
    max_expires_in: int = 365  # days


@dataclass(frozen=True, slots=True)
class RateLimitOptions:
    enabled: bool = True
    time_window: int = _DAY_MS  # ms
    max_requests: int = 10


@dataclass(frozen=True, slots=True)
class StartingCharactersConfig:
    should_store: bool = True
    characters_length: int = 6


@dataclass(frozen=True, slots=True)
class PermissionsOptions:
    default_permissions: Mapping[str, list[str]] | None = None


@dataclass(frozen=True, slots=True)
class ApiKeyOptions:
    api_key_headers: str | tuple[str, ...] = "x-api-key"
    default_key_length: int = 64
    default_prefix: str | None = None
    maximum_prefix_length: int = 32
    minimum_prefix_length: int = 1
    maximum_name_length: int = 32
    minimum_name_length: int = 1
    enable_metadata: bool = False
    disable_key_hashing: bool = False
    require_name: bool = False
    key_expiration: KeyExpirationOptions = field(default_factory=KeyExpirationOptions)
    rate_limit: RateLimitOptions = field(default_factory=RateLimitOptions)
    starting_characters_config: StartingCharactersConfig = field(
        default_factory=StartingCharactersConfig
    )
    enable_session_for_api_keys: bool = False
    permissions: PermissionsOptions | None = None
    defer_updates: bool = False
    # legacy/no-op compat
    default_scope: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class ApiKeyConfigurationOptions:
    """A single named API-key configuration in a multi-configuration setup.

    Mirrors upstream ``ApiKeyConfigurationOptions``. When ``api_key`` is given a
    list of these, each gets its own ``config_id`` and may bind to a different
    owner type via ``references`` ("user" or "organization").
    """

    config_id: str | None = None
    references: str = "user"  # "user" | "organization"
    default_prefix: str | None = None
    api_key_headers: str | tuple[str, ...] = "x-api-key"
    default_key_length: int = 64
    maximum_prefix_length: int = 32
    minimum_prefix_length: int = 1
    maximum_name_length: int = 32
    minimum_name_length: int = 1
    enable_metadata: bool = False
    disable_key_hashing: bool = False
    require_name: bool = False
    key_expiration: KeyExpirationOptions = field(default_factory=KeyExpirationOptions)
    rate_limit: RateLimitOptions = field(default_factory=RateLimitOptions)
    starting_characters_config: StartingCharactersConfig = field(
        default_factory=StartingCharactersConfig
    )
    enable_session_for_api_keys: bool = False
    permissions: PermissionsOptions | None = None
    defer_updates: bool = False


@dataclass(frozen=True, slots=True)
class _ResolvedConfig:
    """A configuration resolved to per-key effective settings."""

    config_id: str
    references: str
    default_prefix: str | None
    api_key_headers: str | tuple[str, ...]
    default_key_length: int
    maximum_prefix_length: int
    minimum_prefix_length: int
    maximum_name_length: int
    minimum_name_length: int
    enable_metadata: bool
    disable_key_hashing: bool
    require_name: bool
    key_expiration: KeyExpirationOptions
    rate_limit: RateLimitOptions
    starting_characters_config: StartingCharactersConfig
    enable_session_for_api_keys: bool
    permissions: PermissionsOptions | None
    defer_updates: bool


def _resolved_from_options(opts: ApiKeyOptions) -> _ResolvedConfig:
    return _ResolvedConfig(
        config_id="default",
        references="user",
        default_prefix=opts.default_prefix,
        api_key_headers=opts.api_key_headers,
        default_key_length=opts.default_key_length,
        maximum_prefix_length=opts.maximum_prefix_length,
        minimum_prefix_length=opts.minimum_prefix_length,
        maximum_name_length=opts.maximum_name_length,
        minimum_name_length=opts.minimum_name_length,
        enable_metadata=opts.enable_metadata,
        disable_key_hashing=opts.disable_key_hashing,
        require_name=opts.require_name,
        key_expiration=opts.key_expiration,
        rate_limit=opts.rate_limit,
        starting_characters_config=opts.starting_characters_config,
        enable_session_for_api_keys=opts.enable_session_for_api_keys,
        permissions=opts.permissions,
        defer_updates=opts.defer_updates,
    )


def _resolved_from_config(cfg: ApiKeyConfigurationOptions) -> _ResolvedConfig:
    return _ResolvedConfig(
        config_id=cfg.config_id or "default",
        references=cfg.references,
        default_prefix=cfg.default_prefix,
        api_key_headers=cfg.api_key_headers,
        default_key_length=cfg.default_key_length,
        maximum_prefix_length=cfg.maximum_prefix_length,
        minimum_prefix_length=cfg.minimum_prefix_length,
        maximum_name_length=cfg.maximum_name_length,
        minimum_name_length=cfg.minimum_name_length,
        enable_metadata=cfg.enable_metadata,
        disable_key_hashing=cfg.disable_key_hashing,
        require_name=cfg.require_name,
        key_expiration=cfg.key_expiration,
        rate_limit=cfg.rate_limit,
        starting_characters_config=cfg.starting_characters_config,
        enable_session_for_api_keys=cfg.enable_session_for_api_keys,
        permissions=cfg.permissions,
        defer_updates=cfg.defer_updates,
    )


# --------------------------------------------------------------------------- schema


def _api_key_model(default_rate_limit_max: int, default_time_window: int) -> ModelDef:
    return ModelDef(
        name="apikey",
        table_name=API_KEY_TABLE_NAME,
        fields=(
            FieldDef("configId", "string", required=False, input=False),
            FieldDef("name", "string", required=False, input=False),
            FieldDef("start", "string", required=False, input=False),
            FieldDef("prefix", "string", required=False, input=False),
            FieldDef("key", "string", required=True, input=False, index=True),
            FieldDef(
                "referenceId",
                "string",
                required=True,
                input=False,
                index=True,
            ),
            FieldDef("refillInterval", "number", required=False, input=False),
            FieldDef("refillAmount", "number", required=False, input=False),
            FieldDef("lastRefillAt", "date", required=False, input=False),
            FieldDef("enabled", "boolean", required=False, input=False, default=True),
            FieldDef(
                "rateLimitEnabled",
                "boolean",
                required=False,
                input=False,
                default=True,
            ),
            FieldDef(
                "rateLimitTimeWindow",
                "number",
                required=False,
                input=False,
                default=default_time_window,
            ),
            FieldDef(
                "rateLimitMax",
                "number",
                required=False,
                input=False,
                default=default_rate_limit_max,
            ),
            FieldDef("requestCount", "number", required=False, input=False, default=0),
            FieldDef("remaining", "number", required=False, input=False),
            FieldDef("lastRequest", "date", required=False, input=False),
            FieldDef("expiresAt", "date", required=False, input=False),
            FieldDef("createdAt", "date", required=True, input=False),
            FieldDef("updatedAt", "date", required=True, input=False),
            FieldDef("permissions", "string", required=False, input=False),
            FieldDef("metadata", "string", required=False, input=True),
        ),
    )


# --------------------------------------------------------------------------- request bodies


@dataclass(frozen=True, slots=True)
class CreateApiKeyBody:
    name: str | None = None
    expires_in: int | None = None  # seconds
    prefix: str | None = None
    remaining: int | None = None
    metadata: Any = None
    refill_amount: int | None = None
    refill_interval: int | None = None
    rate_limit_time_window: int | None = None
    rate_limit_max: int | None = None
    rate_limit_enabled: bool | None = None
    permissions: dict[str, list[str]] | None = None
    user_id: str | None = None
    config_id: str | None = None
    organization_id: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyApiKeyBody:
    key: str
    permissions: dict[str, list[str]] | None = None
    config_id: str | None = None


@dataclass(frozen=True, slots=True)
class UpdateApiKeyBody:
    key_id: str
    user_id: str | None = None
    name: str | None = None
    enabled: bool | None = None
    remaining: int | None = None
    refill_amount: int | None = None
    refill_interval: int | None = None
    metadata: Any = None
    expires_in: int | None = None
    rate_limit_enabled: bool | None = None
    rate_limit_time_window: int | None = None
    rate_limit_max: int | None = None
    permissions: dict[str, list[str]] | None = None
    config_id: str | None = None


@dataclass(frozen=True, slots=True)
class DeleteApiKeyBody:
    key_id: str
    config_id: str | None = None


# legacy body kept so old callers don't break
@dataclass(frozen=True, slots=True)
class RevokeApiKeyBody:
    id: str


# --------------------------------------------------------------------------- helpers

# Sentinel: distinguishes "field omitted" from "explicitly null/None" for the
# create-body fields where upstream treats `null` and `undefined` differently
# (notably `remaining`). The wire never carries our sentinel; the router only
# fills declared fields, so omitted fields keep their dataclass default (None).
_OMITTED = object()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _to_ms(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _is_client_request(ctx: EndpointContext) -> bool:
    # Every HTTP dispatch carries a request; treat all reachable calls as client
    # requests (server-only direct `auth.api` calls are not exercised over HTTP).
    return True


def _parse_json(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return None
        # Legacy double-stringified payloads (an earlier serialization bug stored
        # `JSON.stringify(JSON.stringify(obj))`): unwrap one extra layer when the
        # decoded value is itself a JSON string that decodes to an object/array.
        if isinstance(parsed, str):
            try:
                inner = json.loads(parsed)
            except (json.JSONDecodeError, ValueError):
                return parsed
            if isinstance(inner, dict | list):
                return inner
        return parsed
    return value


def _migrated_metadata(raw: Any) -> Any:
    """Return the unwrapped object when ``raw`` is legacy double-stringified.

    Returns ``None`` when no migration is needed, so callers can detect whether a
    write-back to single-stringified form is required.
    """
    if not isinstance(raw, str):
        return None
    try:
        once = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(once, str):
        return None
    try:
        twice = json.loads(once)
    except (json.JSONDecodeError, ValueError):
        return None
    return twice if isinstance(twice, dict | list) else None


def _serialize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Strip the hashed ``key`` and parse JSON columns for the response."""
    out = dict(row)
    out.pop("key", None)
    out["metadata"] = _parse_json(out.get("metadata"))
    out["permissions"] = _parse_json(out.get("permissions"))
    return out


async def _migrate_metadata_row(
    ctx: EndpointContext, row: dict[str, Any]
) -> dict[str, Any]:
    """Repair a row whose ``metadata`` was stored double-stringified.

    Rewrites the column to the correct single-stringified form so subsequent
    reads are clean, mirroring upstream's lazy migration on get/list.
    """
    migrated = _migrated_metadata(row.get("metadata"))
    if migrated is None:
        return row
    fixed = json.dumps(migrated)
    await ctx.auth.adapter.update(
        model="apikey",
        where=(Where(field="id", value=row["id"]),),
        update={"metadata": fixed},
    )
    return {**row, "metadata": fixed}


async def _require_session(ctx: EndpointContext) -> Session:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED_SESSION")
    return ctx.session


# --------------------------------------------------------------------------- validate


def _is_rate_limited(row: dict[str, Any], opts: Any) -> dict[str, Any]:
    now = _now_ms()
    last_request = row.get("lastRequest")
    window = row.get("rateLimitTimeWindow")
    max_req = row.get("rateLimitMax")
    request_count = row.get("requestCount") or 0

    if opts.rate_limit.enabled is False:
        return {"success": True, "try_again_in": None, "update": {"lastRequest": now}}
    if row.get("rateLimitEnabled") is False:
        return {"success": True, "try_again_in": None, "update": {"lastRequest": now}}
    if window is None or max_req is None:
        return {"success": True, "try_again_in": None, "update": None}
    if last_request is None:
        return {
            "success": True,
            "try_again_in": None,
            "update": {"lastRequest": now, "requestCount": 1},
        }
    elapsed = now - int(last_request)
    if elapsed > window:
        return {
            "success": True,
            "try_again_in": None,
            "update": {"lastRequest": now, "requestCount": 1},
        }
    if request_count >= max_req:
        return {
            "success": False,
            "try_again_in": int(window - elapsed),
            "update": None,
        }
    return {
        "success": True,
        "try_again_in": None,
        "update": {"lastRequest": now, "requestCount": request_count + 1},
    }


async def validate_api_key(
    ctx: EndpointContext,
    hashed_key: str,
    opts: Any,
    permissions: dict[str, list[str]] | None = None,
    *,
    expected_config_id: str | None = None,
) -> dict[str, Any]:
    """Validate + mutate a key; returns the updated row or raises ``APIError``."""
    row = await ctx.auth.adapter.find_one(
        model="apikey",
        where=(Where(field="key", value=hashed_key),),
    )
    if not row:
        raise APIError(401, "INVALID_API_KEY")

    if expected_config_id is not None:
        key_config = row.get("configId") or "default"
        if key_config != expected_config_id:
            raise APIError(401, "INVALID_API_KEY")

    if row.get("enabled") is False:
        raise APIError(401, "KEY_DISABLED")

    expires_at = row.get("expiresAt")
    if expires_at:
        if _now_ms() > int(expires_at):
            await ctx.auth.adapter.delete(
                model="apikey",
                where=(Where(field="id", value=row["id"]),),
            )
            raise APIError(401, "KEY_EXPIRED")

    if permissions:
        key_perms = _parse_json(row.get("permissions"))
        if not key_perms:
            raise APIError(401, "KEY_NOT_FOUND")
        result = role(key_perms).authorize(permissions)
        if not result.success:
            raise APIError(401, "KEY_NOT_FOUND")

    remaining = row.get("remaining")
    last_refill_at = row.get("lastRefillAt")

    if remaining == 0 and row.get("refillAmount") is None:
        await ctx.auth.adapter.delete(
            model="apikey",
            where=(Where(field="id", value=row["id"]),),
        )
        raise APIError(429, "USAGE_EXCEEDED")
    elif remaining is not None:
        now = _now_ms()
        refill_interval = row.get("refillInterval")
        refill_amount = row.get("refillAmount")
        last_time = int(last_refill_at) if last_refill_at else int(row["createdAt"])
        if refill_interval and refill_amount:
            if now - last_time > refill_interval:
                remaining = refill_amount
                last_refill_at = now
        if remaining == 0:
            raise APIError(429, "USAGE_EXCEEDED")
        remaining -= 1

    rl = _is_rate_limited(row, opts)
    if rl["success"] is False:
        raise APIError(
            429,
            "RATE_LIMITED",
            message=API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"],
            data={"tryAgainIn": rl["try_again_in"]},
        )

    update: dict[str, Any] = {}
    if rl["update"]:
        update.update(rl["update"])
    update["remaining"] = remaining
    update["lastRefillAt"] = last_refill_at
    update["updatedAt"] = _now_ms()

    updated = await ctx.auth.adapter.update(
        model="apikey",
        where=(Where(field="id", value=row["id"]),),
        update=update,
    )
    if not updated:
        raise APIError(500, "FAILED_TO_UPDATE_API_KEY")
    return updated


# --------------------------------------------------------------------------- expiry purge


async def _delete_all_expired(ctx: EndpointContext) -> None:
    await ctx.auth.adapter.delete_many(
        model="apikey",
        where=(
            Where(field="expiresAt", value=_now_ms(), operator="lt"),
            Where(field="expiresAt", value=None, operator="ne"),
        ),
    )


# --------------------------------------------------------------------------- plugin assembly


@dataclass(frozen=True)
class _ApiKeyPlugin:
    id: str = "api-key"
    version: str | None = "0.0.0"
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    database_hooks: None = None
    on_request: Any = None
    on_response: None = None
    rate_limit: None = None
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(API_KEY_ERROR_CODES)
    )
    init: None = None


# --------------------------------------------------------------------------- org auth


def _get_org_options(ctx: EndpointContext) -> Mapping[str, Any] | None:
    """Return the organization plugin config, or None if not installed."""
    advanced = getattr(ctx.auth.options, "advanced", None)
    if isinstance(advanced, Mapping):
        org = advanced.get("organization")
        if isinstance(org, Mapping):
            return org
    return None


async def _check_org_permission(
    ctx: EndpointContext,
    user_id: str,
    organization_id: str,
    action: str,
) -> dict[str, Any]:
    """Authorize a user against an org-owned key for ``action``.

    Mirrors upstream ``checkOrgApiKeyPermission``: owners get full access; other
    members must have the ``apiKey`` permission for ``action`` in their role.
    """
    from better_auth.plugins.organization import has_permission as _org_has_permission
    from better_auth.plugins.organization.access_control import (
        DEFAULT_ROLES,
        merge_dynamic_roles,
    )

    org_opts = _get_org_options(ctx)
    if org_opts is None:
        raise APIError(500, "ORGANIZATION_PLUGIN_REQUIRED")

    member = await ctx.auth.adapter.find_one(
        model="member",
        where=(
            Where(field="userId", value=user_id),
            Where(field="organizationId", value=organization_id),
        ),
    )
    if not member:
        raise APIError(403, "USER_NOT_MEMBER_OF_ORGANIZATION")

    member_role = member.get("role") or "member"
    creator_role = org_opts.get("creator_role") or "owner"
    # Organization owners (creator role) get full access.
    if creator_role in str(member_role).split(","):
        return member

    # Build the role table, overlaying any dynamic roles from the DB.
    role_table = dict(DEFAULT_ROLES)
    try:
        dynamic_rows = await ctx.auth.adapter.find_many(
            model="organizationRole",
            where=(Where(field="organizationId", value=organization_id),),
        )
        if dynamic_rows:
            role_table = merge_dynamic_roles(dynamic_rows, base=DEFAULT_ROLES)
    except Exception:  # pragma: no cover - org without dynamic roles
        pass

    ok = False
    for r in str(member_role).split(","):
        if _org_has_permission(
            r.strip(),
            {"apiKey": [action]},
            role_table,
        ):
            ok = True
            break
    if not ok:
        raise APIError(403, "INSUFFICIENT_API_KEY_PERMISSIONS")
    return member


def api_key(
    configurations: ApiKeyOptions
    | ApiKeyConfigurationOptions
    | list[ApiKeyConfigurationOptions]
    | None = None,
) -> BetterAuthPlugin:
    # ----------------------------------------------------- resolve configs
    resolved: list[_ResolvedConfig]
    if isinstance(configurations, list):
        if len(configurations) > 0:
            if not all(c.config_id for c in configurations):
                raise ValueError(
                    "configId is required for each API key configuration in the "
                    "api-key plugin."
                )
            ids = [c.config_id for c in configurations]
            if len(set(ids)) != len(ids):
                raise ValueError(
                    "configId must be unique for each API key configuration in the "
                    "api-key plugin."
                )
            resolved = [_resolved_from_config(c) for c in configurations]
        else:
            resolved = [_resolved_from_options(ApiKeyOptions())]
    elif isinstance(configurations, ApiKeyConfigurationOptions):
        resolved = [_resolved_from_config(configurations)]
    else:
        resolved = [_resolved_from_options(configurations or ApiKeyOptions())]

    single = len(resolved) == 1
    # Schema defaults only meaningful for a single configuration.
    base = resolved[0]
    model = _api_key_model(
        default_rate_limit_max=base.rate_limit.max_requests if single else 10,
        default_time_window=base.rate_limit.time_window if single else _DAY_MS,
    )

    def _resolve_config(config_id: str | None) -> _ResolvedConfig:
        if not config_id:
            for c in resolved:
                if c.config_id == "default":
                    return c
            raise APIError(400, "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND")
        for c in resolved:
            if c.config_id == config_id:
                return c
        for c in resolved:
            if c.config_id == "default":
                return c
        raise APIError(400, "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND")

    def _hash(key: str, cfg: _ResolvedConfig) -> str:
        return key if cfg.disable_key_hashing else default_key_hasher(key)

    # ---------------------------------------------------------------- create
    async def create_key(ctx: EndpointContext) -> dict[str, Any]:
        body: CreateApiKeyBody = ctx.body or CreateApiKeyBody()
        cfg = _resolve_config(body.config_id)
        is_client = _is_client_request(ctx)

        using_server_only = (
            body.refill_amount is not None
            or body.refill_interval is not None
            or body.rate_limit_max is not None
            or body.rate_limit_time_window is not None
            or body.rate_limit_enabled is not None
            or body.permissions is not None
            or body.remaining is not None
        )
        # A signed-in client request may not set server-only props.
        if is_client and ctx.session is not None and using_server_only:
            raise APIError(400, "SERVER_ONLY_PROPERTY")

        # ------------------------------------------------ resolve owner
        if cfg.references == "organization":
            if not body.organization_id:
                raise APIError(400, "ORGANIZATION_ID_REQUIRED")
            if ctx.session is not None:
                await _check_org_permission(
                    ctx, ctx.session.user_id, body.organization_id, "create"
                )
            reference_id = body.organization_id
        else:
            # Client request with explicit userId is rejected (from session).
            if ctx.session is not None and body.user_id is not None:
                raise APIError(401, "UNAUTHORIZED_SESSION")
            if ctx.session is not None:
                reference_id = ctx.session.user_id
            elif body.user_id is not None:
                reference_id = body.user_id
            else:
                raise APIError(401, "UNAUTHORIZED_SESSION")

        metadata = body.metadata
        if metadata is not None:
            if cfg.enable_metadata is False:
                raise APIError(400, "METADATA_DISABLED")
            if not isinstance(metadata, dict):
                raise APIError(400, "INVALID_METADATA_TYPE")

        if body.refill_amount and not body.refill_interval:
            raise APIError(400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED")
        if body.refill_interval and not body.refill_amount:
            raise APIError(400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED")

        if body.expires_in:
            if cfg.key_expiration.disable_custom_expires_time:
                raise APIError(400, "KEY_DISABLED_EXPIRATION")
            expires_days = body.expires_in / (60 * 60 * 24)
            if cfg.key_expiration.min_expires_in > expires_days:
                raise APIError(400, "EXPIRES_IN_IS_TOO_SMALL")
            if cfg.key_expiration.max_expires_in < expires_days:
                raise APIError(400, "EXPIRES_IN_IS_TOO_LARGE")

        prefix = body.prefix or cfg.default_prefix
        if body.prefix:
            if len(body.prefix) < cfg.minimum_prefix_length:
                raise APIError(400, "INVALID_PREFIX_LENGTH")
            if len(body.prefix) > cfg.maximum_prefix_length:
                raise APIError(400, "INVALID_PREFIX_LENGTH")

        if body.name:
            if len(body.name) < cfg.minimum_name_length:
                raise APIError(400, "INVALID_NAME_LENGTH")
            if len(body.name) > cfg.maximum_name_length:
                raise APIError(400, "INVALID_NAME_LENGTH")
        elif cfg.require_name:
            raise APIError(400, "NAME_REQUIRED")

        await _delete_all_expired(ctx)

        key = default_key_generator(cfg.default_key_length, prefix)
        hashed = _hash(key, cfg)

        start = None
        if cfg.starting_characters_config.should_store:
            start = key[: cfg.starting_characters_config.characters_length]

        default_perms = cfg.permissions.default_permissions if cfg.permissions else None
        if body.permissions is not None:
            perms_to_apply: str | None = json.dumps(body.permissions)
        elif default_perms is not None:
            perms_to_apply = json.dumps(dict(default_perms))
        else:
            perms_to_apply = None

        if body.expires_in:
            expires_at: int | None = _now_ms() + body.expires_in * 1000
        elif cfg.key_expiration.default_expires_in:
            expires_at = _now_ms() + cfg.key_expiration.default_expires_in * 1000
        else:
            expires_at = None

        if body.remaining is None and body.refill_amount is not None:
            remaining: int | None = body.refill_amount
        else:
            remaining = body.remaining

        now = _now_ms()
        rate_limit_enabled = (
            cfg.rate_limit.enabled
            if body.rate_limit_enabled is None
            else body.rate_limit_enabled
        )
        data: dict[str, Any] = {
            "configId": cfg.config_id,
            "name": body.name,
            "prefix": prefix,
            "start": start,
            "key": hashed,
            "enabled": True,
            "expiresAt": expires_at,
            "referenceId": reference_id,
            "lastRefillAt": None,
            "lastRequest": None,
            "metadata": json.dumps(metadata) if metadata is not None else None,
            "rateLimitMax": (
                body.rate_limit_max
                if body.rate_limit_max is not None
                else cfg.rate_limit.max_requests
            ),
            "rateLimitTimeWindow": (
                body.rate_limit_time_window
                if body.rate_limit_time_window is not None
                else cfg.rate_limit.time_window
            ),
            "remaining": remaining,
            "refillAmount": body.refill_amount,
            "refillInterval": body.refill_interval,
            "rateLimitEnabled": rate_limit_enabled,
            "requestCount": 0,
            "permissions": perms_to_apply,
            "createdAt": now,
            "updatedAt": now,
        }
        row = await ctx.auth.adapter.create(model="apikey", data=data)
        out = _serialize_row(row)
        out["key"] = key  # plaintext returned once
        out["metadata"] = metadata
        return out

    # ---------------------------------------------------------------- verify
    async def verify_key(ctx: EndpointContext) -> dict[str, Any]:
        body: VerifyApiKeyBody = ctx.body
        cfg = _resolve_config(body.config_id)
        hashed = _hash(body.key, cfg)
        try:
            row = await validate_api_key(
                ctx,
                hashed,
                cfg,
                body.permissions,
                expected_config_id=cfg.config_id,
            )
        except APIError as e:
            return {
                "valid": False,
                "error": {"message": e.message, "code": e.code},
                "key": None,
            }
        out = _serialize_row(row)
        return {"valid": True, "error": None, "key": out}

    # ------------------------------------------------ owner/access guard
    async def _authorize_row(
        ctx: EndpointContext,
        session: Session,
        row: dict[str, Any],
        cfg: _ResolvedConfig,
        action: str,
    ) -> None:
        """Raise if ``session``'s user may not perform ``action`` on ``row``."""
        if cfg.references == "organization":
            await _check_org_permission(
                ctx, session.user_id, row.get("referenceId"), action
            )
        elif row.get("referenceId") != session.user_id:
            raise APIError(404, "KEY_NOT_FOUND")

    # ---------------------------------------------------------------- get
    async def get_key(ctx: EndpointContext) -> dict[str, Any]:
        session = await _require_session(ctx)
        q = ctx.request.query
        key_id = q.get("id")
        config_id = q.get("configId")
        cfg = _resolve_config(config_id)
        if not key_id:
            raise APIError(400, "KEY_NOT_FOUND")
        row = await ctx.auth.adapter.find_one(
            model="apikey",
            where=(Where(field="id", value=key_id),),
        )
        if not row:
            raise APIError(404, "KEY_NOT_FOUND")
        # configId mismatch → not found
        if (row.get("configId") or "default") != cfg.config_id:
            raise APIError(404, "KEY_NOT_FOUND")
        await _authorize_row(ctx, session, row, cfg, "read")
        await _delete_all_expired(ctx)
        row = await _migrate_metadata_row(ctx, row)
        return _serialize_row(row)

    # ---------------------------------------------------------------- update
    async def update_key(ctx: EndpointContext) -> dict[str, Any]:
        session = await _require_session(ctx)
        body: UpdateApiKeyBody = ctx.body
        cfg = _resolve_config(body.config_id)

        row = await ctx.auth.adapter.find_one(
            model="apikey",
            where=(Where(field="id", value=body.key_id),),
        )
        if not row:
            raise APIError(404, "KEY_NOT_FOUND")
        if (row.get("configId") or "default") != cfg.config_id:
            raise APIError(404, "KEY_NOT_FOUND")
        await _authorize_row(ctx, session, row, cfg, "update")

        # For user-owned keys, a client (session) cannot set server-only props.
        is_org = cfg.references == "organization"
        using_server_only = (
            body.refill_amount is not None
            or body.refill_interval is not None
            or body.rate_limit_max is not None
            or body.rate_limit_time_window is not None
            or body.rate_limit_enabled is not None
            or body.remaining is not None
            or body.permissions is not None
        )
        if using_server_only and not is_org and ctx.session is not None:
            raise APIError(400, "SERVER_ONLY_PROPERTY")

        new_values: dict[str, Any] = {}

        if body.name is not None:
            if len(body.name) < cfg.minimum_name_length:
                raise APIError(400, "INVALID_NAME_LENGTH")
            if len(body.name) > cfg.maximum_name_length:
                raise APIError(400, "INVALID_NAME_LENGTH")
            new_values["name"] = body.name

        if body.enabled is not None:
            new_values["enabled"] = body.enabled

        if body.expires_in is not None:
            if cfg.key_expiration.disable_custom_expires_time:
                raise APIError(400, "KEY_DISABLED_EXPIRATION")
            expires_days = body.expires_in / (60 * 60 * 24)
            if expires_days < cfg.key_expiration.min_expires_in:
                raise APIError(400, "EXPIRES_IN_IS_TOO_SMALL")
            if expires_days > cfg.key_expiration.max_expires_in:
                raise APIError(400, "EXPIRES_IN_IS_TOO_LARGE")
            new_values["expiresAt"] = (
                _now_ms() + body.expires_in * 1000 if body.expires_in else None
            )

        if body.metadata is not None and cfg.enable_metadata:
            if not isinstance(body.metadata, dict):
                raise APIError(400, "INVALID_METADATA_TYPE")
            new_values["metadata"] = json.dumps(body.metadata)

        if body.remaining is not None:
            new_values["remaining"] = body.remaining

        if body.refill_amount is not None or body.refill_interval is not None:
            if body.refill_amount is not None and body.refill_interval is None:
                raise APIError(400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED")
            if body.refill_interval is not None and body.refill_amount is None:
                raise APIError(400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED")
            new_values["refillAmount"] = body.refill_amount
            new_values["refillInterval"] = body.refill_interval

        if body.rate_limit_enabled is not None:
            new_values["rateLimitEnabled"] = body.rate_limit_enabled
        if body.rate_limit_time_window is not None:
            new_values["rateLimitTimeWindow"] = body.rate_limit_time_window
        if body.rate_limit_max is not None:
            new_values["rateLimitMax"] = body.rate_limit_max

        if body.permissions is not None:
            new_values["permissions"] = json.dumps(body.permissions)

        if not new_values:
            raise APIError(400, "NO_VALUES_TO_UPDATE")

        # Bug-fix parity (#5309): updating config must NOT touch lastRequest or
        # auto-decrement remaining — we only persist the explicitly set fields.
        new_values["updatedAt"] = _now_ms()
        updated = await ctx.auth.adapter.update(
            model="apikey",
            where=(Where(field="id", value=body.key_id),),
            update=new_values,
        )
        await _delete_all_expired(ctx)
        return _serialize_row(updated or row)

    # ---------------------------------------------------------------- delete
    async def delete_key(ctx: EndpointContext) -> dict[str, Any]:
        session = await _require_session(ctx)
        body: DeleteApiKeyBody = ctx.body
        cfg = _resolve_config(body.config_id)
        row = await ctx.auth.adapter.find_one(
            model="apikey",
            where=(Where(field="id", value=body.key_id),),
        )
        if not row:
            raise APIError(404, "KEY_NOT_FOUND")
        if (row.get("configId") or "default") != cfg.config_id:
            raise APIError(404, "KEY_NOT_FOUND")
        await _authorize_row(ctx, session, row, cfg, "delete")
        await ctx.auth.adapter.delete(
            model="apikey",
            where=(Where(field="id", value=body.key_id),),
        )
        await _delete_all_expired(ctx)
        return {"success": True}

    # ---------------------------------------------------------------- list
    async def list_keys(ctx: EndpointContext) -> dict[str, Any]:
        session = await _require_session(ctx)
        q = ctx.request.query
        organization_id = q.get("organizationId")
        config_id = q.get("configId")

        if organization_id:
            # Org-scoped listing: authorize the caller, then return org keys.
            org_cfg = None
            for c in resolved:
                if c.references == "organization" and (
                    config_id is None or c.config_id == config_id
                ):
                    org_cfg = c
                    break
            if org_cfg is None:
                org_cfg = _resolve_config(config_id)
            await _check_org_permission(ctx, session.user_id, organization_id, "read")
            where = (Where(field="referenceId", value=organization_id),)
        else:
            where = (Where(field="referenceId", value=session.user_id),)

        rows = await ctx.auth.adapter.find_many(model="apikey", where=where)

        # When configs reference different owner types, a plain user list should
        # exclude org-owned keys (referenceId == user id already filters those).
        if config_id:
            rows = [r for r in rows if (r.get("configId") or "default") == config_id]
        elif not organization_id:
            # Hide keys whose config references "organization" from user listing.
            org_config_ids = {c.config_id for c in resolved if c.references == "organization"}
            if org_config_ids:
                rows = [
                    r
                    for r in rows
                    if (r.get("configId") or "default") not in org_config_ids
                ]

        sort_by = q.get("sortBy")
        if sort_by:
            direction = q.get("sortDirection", "asc")
            rows = sorted(
                rows,
                key=lambda r: (r.get(sort_by) is None, r.get(sort_by)),
                reverse=direction == "desc",
            )

        total = len(rows)
        offset = q.get("offset")
        limit = q.get("limit")
        if offset is not None:
            rows = rows[int(offset):]
        if limit is not None:
            rows = rows[: int(limit)]

        await _delete_all_expired(ctx)
        rows = [await _migrate_metadata_row(ctx, r) for r in rows]
        api_keys = [_serialize_row(r) for r in rows]
        return {
            "apiKeys": api_keys,
            "total": total,
            "limit": int(limit) if limit is not None else None,
            "offset": int(offset) if offset is not None else None,
        }

    # ---------------------------------------------------------------- bulk purge
    async def delete_all_expired(ctx: EndpointContext) -> dict[str, Any]:
        try:
            await _delete_all_expired(ctx)
        except Exception as e:  # pragma: no cover - defensive
            return {"success": False, "error": str(e)}
        return {"success": True, "error": None}

    endpoints = (
        create_auth_endpoint(
            "/api-key/create",
            EndpointOptions(method="POST", body=CreateApiKeyBody),
            create_key,
        ),
        create_auth_endpoint(
            "/api-key/verify",
            EndpointOptions(method="POST", body=VerifyApiKeyBody),
            verify_key,
        ),
        create_auth_endpoint(
            "/api-key/get",
            EndpointOptions(method="GET"),
            get_key,
        ),
        create_auth_endpoint(
            "/api-key/update",
            EndpointOptions(method="POST", body=UpdateApiKeyBody),
            update_key,
        ),
        create_auth_endpoint(
            "/api-key/delete",
            EndpointOptions(method="POST", body=DeleteApiKeyBody),
            delete_key,
        ),
        create_auth_endpoint(
            "/api-key/list",
            EndpointOptions(method="GET"),
            list_keys,
        ),
        create_auth_endpoint(
            "/api-key/delete-all-expired-api-keys",
            EndpointOptions(method="POST"),
            delete_all_expired,
        ),
    )

    # ------------------------------------------------- enableSessionForAPIKeys
    def _key_from_config(
        ctx: EndpointContext, cfg: _ResolvedConfig
    ) -> str | None:
        headers = cfg.api_key_headers
        if isinstance(headers, tuple | list):
            for h in headers:
                v = ctx.request.headers.get(h)
                if v:
                    return v
            return None
        return ctx.request.headers.get(headers)

    def _find_key_and_config(
        ctx: EndpointContext,
    ) -> tuple[str, _ResolvedConfig] | None:
        # Mirrors upstream findApiKeyAndConfig: only configs that opt into
        # session resolution are considered, first match wins.
        for cfg in resolved:
            if not cfg.enable_session_for_api_keys:
                continue
            key = _key_from_config(ctx, cfg)
            if key:
                return key, cfg
        return None

    async def _session_before_hook(ctx: EndpointContext) -> None:
        if ctx.session is not None:
            return
        found = _find_key_and_config(ctx)
        if found is None:
            return
        key, cfg = found
        if len(key) < cfg.default_key_length:
            raise APIError(403, "INVALID_API_KEY")
        hashed = _hash(key, cfg)
        row = await validate_api_key(
            ctx, hashed, cfg, expected_config_id=cfg.config_id
        )
        # Session mocking only works for user-owned API keys.
        if cfg.references != "user":
            raise APIError(401, "INVALID_REFERENCE_ID_FROM_API_KEY")
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=row["referenceId"]),),
        )
        if not user:
            raise APIError(401, "INVALID_REFERENCE_ID_FROM_API_KEY")
        ctx.session = Session(
            id=row["id"],
            user_id=row["referenceId"],
            expires_at=(
                int(row["expiresAt"])
                if row.get("expiresAt")
                else _now_ms() + 7 * _DAY_MS
            ),
            token=key,
        )

    hooks: PluginHooks | None = None
    if any(c.enable_session_for_api_keys for c in resolved):
        hooks = PluginHooks(
            before=(BeforeHook(match=lambda ctx: True, handler=_session_before_hook),)
        )

    return _ApiKeyPlugin(  # type: ignore[return-value]
        schema=PluginSchema(tables=(model,)),
        endpoints=endpoints,
        hooks=hooks,
    )
