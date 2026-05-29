"""Email-OTP plugin construction.

Mirrors `reference/packages/better-auth/src/plugins/email-otp/index.ts`.

Configuration lives under `BetterAuthOptions.advanced["email-otp"]`:

    advanced={
        "email-otp": {
            "send_otp": async (email, otp, purpose) -> None,
            "otp_length": 6,           # optional
            "expires_in": 300,         # optional, seconds
            "disable_sign_up": False,  # optional
        }
    }
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.email_otp import routes
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

EMAIL_OTP_ERROR_CODES: Mapping[str, str] = {
    "OTP_EXPIRED": "OTP expired",
    "INVALID_OTP": "Invalid OTP",
    "TOO_MANY_ATTEMPTS": "Too many attempts",
    "INVALID_OTP_TYPE": "Invalid OTP type",
    "OTP_HASHED": "OTP is hashed, cannot return the plain text OTP",
    "CHANGE_EMAIL_DISABLED": "Change email with OTP is disabled",
    "EMAIL_IS_THE_SAME": "Email is the same",
    "EMAIL_ALREADY_IN_USE": "Email already in use",
    "OTP_REQUIRED": "OTP is required to verify current email",
    "EMAIL_OTP_NOT_CONFIGURED": "Email-OTP plugin is missing send_otp.",
    "EMAIL_OTP_SIGN_UP_DISABLED": "Sign-up via email OTP is disabled.",
}


@dataclass(frozen=True, slots=True)
class _EmailOTPPlugin:
    id: str = "email-otp"
    version: str | None = None
    schema: PluginSchema | None = None  # reuses core verification table
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sign-in/email-otp", window=60, max=3),
        RateLimitRule(path="/email-otp/verify", window=60, max=5),
        RateLimitRule(path="/email-otp/send-verification-otp", window=60, max=3),
        RateLimitRule(path="/email-otp/verify-email", window=60, max=5),
        RateLimitRule(path="/forget-password/email-otp", window=60, max=3),
        RateLimitRule(path="/email-otp/reset-password", window=60, max=5),
        RateLimitRule(path="/email-otp/request-email-change", window=60, max=3),
        RateLimitRule(path="/email-otp/change-email", window=60, max=5),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(EMAIL_OTP_ERROR_CODES)
    )
    init: None = None


def email_otp() -> BetterAuthPlugin:
    """Construct the email-OTP plugin."""
    return _EmailOTPPlugin()  # type: ignore[return-value]
