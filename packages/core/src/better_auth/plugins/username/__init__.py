"""username plugin — port of `reference/packages/better-auth/src/plugins/username/`.

Adds username-based sign-up/sign-in alongside the email/password credential rows.
The username column is stored in normalized (lower-case) form; `displayUsername`
preserves the originally-supplied casing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.username import routes
from better_auth.types.adapter import FieldDef
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


USERNAME_ERROR_CODES: Mapping[str, str] = {
    "INVALID_USERNAME_OR_PASSWORD": "Invalid username or password",
    "USERNAME_IS_ALREADY_TAKEN": "Username is already taken. Please try another.",
    "USERNAME_TOO_SHORT": "Username is too short",
    "USERNAME_TOO_LONG": "Username is too long",
    "INVALID_USERNAME": "Username is invalid",
    "INVALID_DISPLAY_USERNAME": "Display username is invalid",
}


_USERNAME_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("username", "string", required=False, unique=True),
    FieldDef("displayUsername", "string", required=False),
)


@dataclass(frozen=True, slots=True)
class _UsernamePlugin:
    id: str = "username"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(extend={"user": _USERNAME_USER_FIELDS})
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sign-in/username", window=60, max=10),
        RateLimitRule(path="/sign-up/username", window=60, max=5),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(USERNAME_ERROR_CODES)
    )
    init: None = None


def username() -> BetterAuthPlugin:
    """Construct the username plugin."""
    return _UsernamePlugin()  # type: ignore[return-value]


__all__ = ["USERNAME_ERROR_CODES", "username"]
