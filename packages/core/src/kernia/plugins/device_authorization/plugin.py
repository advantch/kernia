"""Device-authorization plugin construction.

Implements RFC 8628 (OAuth 2.0 Device Authorization Grant).

Mirrors `reference/packages/better-auth/src/plugins/device-authorization/`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field

from kernia.plugins.device_authorization import routes
from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

# Mirrors `reference/.../device-authorization/error-codes.ts`.
DEVICE_AUTHORIZATION_ERROR_CODES: Mapping[str, str] = {
    "INVALID_DEVICE_CODE": "Invalid device code",
    "EXPIRED_DEVICE_CODE": "Device code has expired",
    "EXPIRED_USER_CODE": "User code has expired",
    "AUTHORIZATION_PENDING": "Authorization pending",
    "ACCESS_DENIED": "Access denied",
    "INVALID_USER_CODE": "Invalid user code",
    "DEVICE_CODE_ALREADY_PROCESSED": "Device code already processed",
    "DEVICE_CODE_NOT_CLAIMED": (
        "Device code has not been claimed by a verifying session; call "
        "`GET /device` with the `user_code` while signed in before approving "
        "or denying"
    ),
    "POLLING_TOO_FREQUENTLY": "Polling too frequently",
    "USER_NOT_FOUND": "User not found",
    "FAILED_TO_CREATE_SESSION": "Failed to create session",
    "INVALID_DEVICE_CODE_STATUS": "Invalid device code status",
    "AUTHENTICATION_REQUIRED": "Authentication required",
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
    expires_in: str | int = "30m",
    interval: str | int = "5s",
    user_code_length: int = 8,
    device_code_length: int = 40,
    verification_uri: str | None = None,
    generate_device_code: Callable[[], str | Awaitable[str]] | None = None,
    generate_user_code: Callable[[], str | Awaitable[str]] | None = None,
    validate_client: Callable[[str], bool | Awaitable[bool]] | None = None,
    on_device_auth_request: (
        Callable[[str, str | None], None | Awaitable[None]] | None
    ) = None,
) -> KerniaPlugin:
    """Construct the device-authorization plugin (RFC 8628).

    Upstream-parity options:
      * ``expires_in`` / ``interval`` — time strings ('30m', '5s', '1h') or ms ints.
      * ``user_code_length`` / ``device_code_length`` — default code lengths.
      * ``verification_uri`` — absolute URL or relative path (default ``/device``).
      * ``generate_device_code`` / ``generate_user_code`` — custom code generators.
      * ``validate_client`` — ``(client_id) -> bool`` gate on /device/code + /token.
      * ``on_device_auth_request`` — ``(client_id, scope) -> None`` side effect.
    """
    routes.configure(
        routes.DeviceAuthorizationOptions(
            expires_in=expires_in,
            interval=interval,
            user_code_length=user_code_length,
            device_code_length=device_code_length,
            verification_uri=verification_uri,
            generate_device_code=generate_device_code,
            generate_user_code=generate_user_code,
            validate_client=validate_client,
            on_device_auth_request=on_device_auth_request,
        )
    )
    return _DeviceAuthorizationPlugin()  # type: ignore[return-value]
