"""username plugin — port of `reference/packages/better-auth/src/plugins/username/`.

Adds username-based sign-up/sign-in alongside the email/password credential rows.
The username column is stored in normalized (lower-case) form; `displayUsername`
preserves the originally-supplied casing.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from kernia.plugins.username import routes
from kernia.types.adapter import FieldDef
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

_UPDATE_USER_HOOKS = PluginHooks(
    before=(BeforeHook(match="/update-user", handler=routes.update_user_before),)
)

USERNAME_ERROR_CODES: Mapping[str, str] = {
    "INVALID_USERNAME_OR_PASSWORD": "Invalid username or password",
    "EMAIL_NOT_VERIFIED": "Email not verified",
    "UNEXPECTED_ERROR": "Unexpected error",
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
    options: UsernameOptions = field(default_factory=UsernameOptions)
    id: str = "username"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(extend={"user": _USERNAME_USER_FIELDS})
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = field(default_factory=lambda: _UPDATE_USER_HOOKS)
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sign-in/username", window=60, max=10),
        RateLimitRule(path="/sign-up/username", window=60, max=5),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(USERNAME_ERROR_CODES)
    )

    async def init(self, ctx: AuthContext) -> None:
        """Stash resolved per-instance options for the handlers to read.

        Mirrors upstream `username().init`, which threads the constructor
        options into the request context. The Python port parks the resolved
        :class:`UsernameOptions` under ``plugin_state["username"]`` so multiple
        plugin instances can carry distinct config.
        """
        ctx.plugin_state["username"] = self.options


def username() -> KerniaPlugin:
    """Construct the username plugin."""
    return _UsernamePlugin()  # type: ignore[return-value]


__all__ = ["USERNAME_ERROR_CODES", "username"]
