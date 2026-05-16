"""Phone-number plugin construction.

Mirrors `reference/packages/better-auth/src/plugins/phone-number/index.ts`.

Configuration lives under `BetterAuthOptions.advanced["phone-number"]`:

    advanced={
        "phone-number": {
            "send_sms": async (phone, message) -> None,
            "otp_length": 6,
            "expires_in": 300,
            "disable_sign_up": False,
        }
    }
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.phone_number import routes
from better_auth.plugins.phone_number.schema import phone_number_schema
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


PHONE_NUMBER_ERROR_CODES: Mapping[str, str] = {
    "INVALID_PHONE_NUMBER_OR_PASSWORD": "Phone number or password is incorrect.",
    "PHONE_NUMBER_NOT_CONFIGURED": "Phone-number plugin is missing send_sms.",
    "PHONE_NUMBER_SIGN_UP_DISABLED": "Sign-up via phone number is disabled.",
    "PHONE_NUMBER_NOT_VERIFIED": "Phone number has not been verified.",
}


@dataclass(frozen=True, slots=True)
class _PhoneNumberPlugin:
    id: str = "phone-number"
    version: str | None = None
    schema: PluginSchema | None = field(default_factory=phone_number_schema)
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sign-in/phone-number", window=60, max=10),
        RateLimitRule(path="/phone-number/send-otp", window=60, max=3),
        RateLimitRule(path="/phone-number/verify", window=60, max=5),
        RateLimitRule(path="/phone-number/request-password-reset", window=60, max=3),
        RateLimitRule(path="/phone-number/reset-password", window=60, max=5),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(PHONE_NUMBER_ERROR_CODES)
    )
    init: None = None


def phone_number() -> BetterAuthPlugin:
    """Construct the phone-number plugin."""
    return _PhoneNumberPlugin()  # type: ignore[return-value]
