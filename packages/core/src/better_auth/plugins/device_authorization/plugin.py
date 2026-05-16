"""Device-authorization plugin construction.

Implements RFC 8628 (OAuth 2.0 Device Authorization Grant).

Mirrors `reference/packages/better-auth/src/plugins/device-authorization/`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.device_authorization import routes
from better_auth.types.adapter import FieldDef, ModelDef
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


DEVICE_AUTHORIZATION_ERROR_CODES: Mapping[str, str] = {
    "INVALID_DEVICE_CODE": "The device code is invalid.",
    "EXPIRED_DEVICE_CODE": "The device code has expired.",
    "AUTHORIZATION_PENDING": "User has not yet approved this device.",
    "ACCESS_DENIED": "The user denied this device authorization.",
    "POLLING_TOO_FREQUENTLY": "Polling too quickly; respect the `interval` value.",
    "INVALID_USER_CODE": "The user code is invalid.",
    "EXPIRED_USER_CODE": "The user code has expired.",
    "DEVICE_CODE_ALREADY_PROCESSED": "This device code has already been processed.",
    "AUTHENTICATION_REQUIRED": "Sign-in is required to approve a device.",
}


DEVICE_CODE_MODEL = ModelDef(
    name="deviceCode",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("deviceCode", "string", unique=True),
        FieldDef("userCode", "string", unique=True),
        FieldDef("userId", "string", required=False, references=("user", "id")),
        FieldDef("expiresAt", "date"),
        FieldDef("status", "string"),  # pending | approved | denied
        FieldDef("pollingInterval", "number", required=False),
        FieldDef("clientId", "string", required=False),
        FieldDef("scope", "string", required=False),
        FieldDef("lastPolledAt", "date", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


@dataclass(frozen=True, slots=True)
class _DeviceAuthorizationPlugin:
    id: str = "device-authorization"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(tables=(DEVICE_CODE_MODEL,))
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = ()
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(DEVICE_AUTHORIZATION_ERROR_CODES)
    )
    init: None = None


def device_authorization(
    *,
    expires_in: int = 600,
    interval: int = 5,
    user_code_length: int = 8,
    device_code_length: int = 40,
    verification_uri: str | None = None,
) -> BetterAuthPlugin:
    routes.configure(
        routes.DeviceAuthorizationOptions(
            expires_in=expires_in,
            interval=interval,
            user_code_length=user_code_length,
            device_code_length=device_code_length,
            verification_uri=verification_uri,
        )
    )
    return _DeviceAuthorizationPlugin()  # type: ignore[return-value]
