"""Admin configuration plugin."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.plugin import KerniaPlugin, PluginSchema


ADMIN_CONFIG_ERROR_CODES: Mapping[str, str] = {
    "AUTH_METHOD_DISABLED": "This login method is disabled.",
    "ADMIN_CONFIG_FORBIDDEN": "You are not allowed to manage admin configuration.",
    "ADMIN_CONFIG_NOT_FOUND": "Configuration was not found.",
}

ADMIN_CONFIG_MODEL = ModelDef(
    name="adminConfig",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("key", "string"),
        FieldDef("value", "json"),
        FieldDef("secretFields", "json", required=False),
        FieldDef("createdAt", "number"),
        FieldDef("updatedAt", "number"),
    ),
)

EmailClientKind = Literal["smtp", "resend", "postmark"]


DEFAULT_AUTH_METHODS: dict[str, dict[str, Any]] = {
    "email-password": {"enabled": True, "label": "Email and password"},
    "magic-link": {"enabled": False, "label": "Magic link"},
    "email-otp": {"enabled": False, "label": "Email OTP"},
    "google": {"enabled": False, "label": "Google"},
    "github": {"enabled": False, "label": "GitHub"},
    "passkey": {"enabled": False, "label": "Passkey"},
    "two-factor": {"enabled": False, "label": "Two-factor"},
    "username": {"enabled": False, "label": "Username"},
    "phone-number": {"enabled": False, "label": "Phone number"},
    "siwe": {"enabled": False, "label": "Ethereum wallet"},
    "anonymous": {"enabled": False, "label": "Anonymous"},
    "one-tap": {"enabled": False, "label": "Google One Tap"},
    "sso": {"enabled": False, "label": "Enterprise SSO"},
}

AUTH_METHOD_PATHS: Mapping[str, tuple[str, ...]] = {
    "email-password": (
        "/sign-up/email",
        "/sign-in/email",
        "/forget-password",
        "/reset-password",
    ),
    "magic-link": ("/sign-in/magic-link", "/magic-link/verify"),
    "email-otp": (
        "/sign-in/email-otp",
        "/email-otp/verify",
        "/email-otp/send-verification-otp",
        "/email-otp/verify-email",
        "/forget-password/email-otp",
        "/email-otp/reset-password",
        "/email-otp/request-email-change",
        "/email-otp/change-email",
    ),
    "username": ("/sign-up/username", "/sign-in/username"),
    "phone-number": ("/phone-number",),
    "siwe": ("/siwe",),
    "anonymous": ("/sign-in/anonymous",),
    "one-tap": ("/one-tap",),
    "passkey": ("/passkey",),
    "sso": ("/sso", "/saml"),
}


@dataclass(frozen=True, slots=True)
class AdminConfigOptions:
    admin_user_ids: tuple[str, ...] = ()
    admin_roles: tuple[str, ...] = ("admin", "owner")
    allow_any_authenticated: bool = False
    default_auth_methods: Mapping[str, Mapping[str, Any]] = field(
        default_factory=lambda: DEFAULT_AUTH_METHODS
    )


class ConfigBody(BaseModel):
    value: dict[str, Any] = Field(default_factory=dict)
    secretFields: list[str] = Field(default_factory=list)


async def _config_row(ctx: EndpointContext, key: str) -> dict[str, Any] | None:
    return await ctx.auth.adapter.find_one(
        model="adminConfig",
        where=(Where(field="key", value=key),),
    )


def _decode(row: dict[str, Any] | None, default: Any) -> Any:
    if row is None:
        return default
    value = row.get("value")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value if value is not None else default


def _secret_fields(row: dict[str, Any] | None) -> list[str]:
    if row is None:
        return []
    raw = row.get("secretFields")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return list(parsed) if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return list(raw) if isinstance(raw, list) else []


def _redact(value: Any, secret_fields: list[str]) -> Any:
    if isinstance(value, list):
        return [_redact(item, secret_fields) for item in value]
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for key, item in value.items():
        if key in secret_fields and item:
            out[key] = "********"
        else:
            out[key] = _redact(item, secret_fields)
    return out


async def _upsert_config(
    ctx: EndpointContext,
    *,
    key: str,
    value: Mapping[str, Any],
    secret_fields: list[str],
) -> dict[str, Any]:
    now = int(time.time())
    existing = await _config_row(ctx, key)
    payload = {
        "key": key,
        "value": json.dumps(dict(value)),
        "secretFields": json.dumps(secret_fields),
        "updatedAt": now,
    }
    if existing is None:
        payload["createdAt"] = now
        return await ctx.auth.adapter.create(model="adminConfig", data=payload)
    updated = await ctx.auth.adapter.update(
        model="adminConfig",
        where=(Where(field="id", value=existing["id"]),),
        update=payload,
    )
    return updated or existing


async def _require_admin(ctx: EndpointContext, opts: AdminConfigOptions) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if user is None:
        raise APIError(401, "UNAUTHORIZED")
    if opts.allow_any_authenticated or user["id"] in opts.admin_user_ids:
        return user
    roles = {str(r).strip() for r in str(user.get("role") or "").split(",") if r}
    if roles.intersection(opts.admin_roles):
        return user
    raise APIError(403, "ADMIN_CONFIG_FORBIDDEN")


async def _auth_methods(ctx: EndpointContext, opts: AdminConfigOptions) -> dict[str, Any]:
    row = await _config_row(ctx, "auth-methods")
    configured = _decode(row, {})
    methods = {k: dict(v) for k, v in opts.default_auth_methods.items()}
    if isinstance(configured, dict):
        for key, value in configured.items():
            if isinstance(value, dict):
                methods.setdefault(key, {}).update(value)
    return {"methods": methods}


def _is_path_disabled(path: str, methods: Mapping[str, Any]) -> str | None:
    for method_id, prefixes in AUTH_METHOD_PATHS.items():
        for prefix in prefixes:
            if path == prefix or path.startswith(prefix + "/"):
                cfg = methods.get(method_id)
                if isinstance(cfg, dict) and cfg.get("enabled") is False:
                    return method_id
    if path == "/sign-in/social":
        provider = None
        # Provider is in the request body; global gate cannot inspect before body
        # construction for every plugin, so social provider availability is shown
        # through the public config endpoint and validated by configured provider
        # presence in the normal route.
        return provider
    return None


def _build_endpoints(opts: AdminConfigOptions) -> tuple[AuthEndpoint, ...]:
    async def public_auth(ctx: EndpointContext) -> dict[str, Any]:
        data = await _auth_methods(ctx, opts)
        return data

    async def get_auth_methods(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts)
        return await _auth_methods(ctx, opts)

    async def put_auth_methods(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts)
        body: ConfigBody = ctx.body
        await _upsert_config(
            ctx,
            key="auth-methods",
            value=body.value,
            secret_fields=[],
        )
        return await _auth_methods(ctx, opts)

    async def get_email_clients(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts)
        row = await _config_row(ctx, "email-clients")
        return {
            "clients": _redact(_decode(row, {"clients": []}), _secret_fields(row)).get(
                "clients", []
            )
        }

    async def put_email_clients(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts)
        body: ConfigBody = ctx.body
        secret_fields = body.secretFields or [
            "password",
            "apiKey",
            "token",
            "secret",
        ]
        row = await _upsert_config(
            ctx,
            key="email-clients",
            value=body.value,
            secret_fields=secret_fields,
        )
        return {
            "clients": _redact(_decode(row, {"clients": []}), secret_fields).get(
                "clients", []
            )
        }

    async def get_stripe_config(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts)
        row = await _config_row(ctx, "stripe")
        return {"stripe": _redact(_decode(row, {}), _secret_fields(row))}

    async def put_stripe_config(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts)
        body: ConfigBody = ctx.body
        secret_fields = body.secretFields or ["apiKey", "webhookSecret"]
        row = await _upsert_config(
            ctx,
            key="stripe",
            value=body.value,
            secret_fields=secret_fields,
        )
        return {"stripe": _redact(_decode(row, {}), secret_fields)}

    return (
        create_auth_endpoint(
            "/admin/config/public-auth",
            EndpointOptions(method="GET"),
            public_auth,
        ),
        create_auth_endpoint(
            "/admin/config/auth-methods",
            EndpointOptions(method="GET", requires_session=True),
            get_auth_methods,
        ),
        create_auth_endpoint(
            "/admin/config/auth-methods",
            EndpointOptions(method="POST", body=ConfigBody, requires_session=True),
            put_auth_methods,
        ),
        create_auth_endpoint(
            "/admin/config/email-clients",
            EndpointOptions(method="GET", requires_session=True),
            get_email_clients,
        ),
        create_auth_endpoint(
            "/admin/config/email-clients",
            EndpointOptions(method="POST", body=ConfigBody, requires_session=True),
            put_email_clients,
        ),
        create_auth_endpoint(
            "/admin/config/stripe",
            EndpointOptions(method="GET", requires_session=True),
            get_stripe_config,
        ),
        create_auth_endpoint(
            "/admin/config/stripe",
            EndpointOptions(method="POST", body=ConfigBody, requires_session=True),
            put_stripe_config,
        ),
    )


@dataclass(frozen=True)
class _AdminConfigPlugin:
    id: str = "admin-config"
    version: str | None = "0.0.0"
    schema: PluginSchema | None = PluginSchema(tables=(ADMIN_CONFIG_MODEL,))
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: None = None
    on_request: Any = None
    on_response: None = None
    rate_limit: None = None
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(ADMIN_CONFIG_ERROR_CODES)
    )
    init: None = None


def admin_config(options: AdminConfigOptions | None = None) -> KerniaPlugin:
    opts = options or AdminConfigOptions()

    async def gate(ctx: EndpointContext) -> None:
        data = await _auth_methods(ctx, opts)
        disabled = _is_path_disabled(ctx.request.path, data["methods"])
        if disabled:
            raise APIError(
                403,
                "AUTH_METHOD_DISABLED",
                message=f"{disabled} is disabled.",
            )

    return _AdminConfigPlugin(  # type: ignore[return-value]
        endpoints=_build_endpoints(opts),
        on_request=gate,
    )


__all__ = [
    "ADMIN_CONFIG_ERROR_CODES",
    "ADMIN_CONFIG_MODEL",
    "AdminConfigOptions",
    "admin_config",
]
