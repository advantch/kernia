"""Email/password plugin construction.

The handler bodies (sign-up, sign-in, etc.) live in `routes.py` so this file stays
focused on registration. Plugin shape mirrors `BetterAuthPlugin`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.email_password import routes
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

EMAIL_PASSWORD_ERROR_CODES: Mapping[str, str] = {
    "EMAIL_ALREADY_IN_USE": "An account with that email already exists.",
    "INVALID_CREDENTIALS": "Email or password is incorrect.",
    "PASSWORD_TOO_SHORT": "Password does not meet the minimum length policy.",
    "PASSWORD_TOO_LONG": "Password exceeds the maximum length policy.",
    "EMAIL_NOT_VERIFIED": "Email address has not been verified.",
    "FAILED_TO_CREATE_USER": "Failed to create user",
}


@dataclass(frozen=True, slots=True)
class _EmailPasswordPlugin:
    id: str = "email-password"
    version: str | None = None
    schema: PluginSchema | None = None  # uses core models only
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sign-in/email", window=60, max=10),
        RateLimitRule(path="/sign-up/email", window=60, max=5),
        RateLimitRule(path="/forget-password", window=60, max=3),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(EMAIL_PASSWORD_ERROR_CODES)
    )
    init: None = None


def email_and_password() -> BetterAuthPlugin:
    """Construct the email/password plugin.

    The plugin is enabled by the top-level `BetterAuthOptions.email_and_password`
    feature flag; this constructor simply registers the routes + error codes.
    """
    return _EmailPasswordPlugin()  # type: ignore[return-value]
