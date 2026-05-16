"""Magic-link plugin construction.

Mirrors `reference/packages/better-auth/src/plugins/magic-link/index.ts`.

Configuration lives under `BetterAuthOptions.advanced["magic-link"]`:

    advanced={
        "magic-link": {
            "send_magic_link": async (email, url, token) -> None,
            "expires_in": 300,         # optional, seconds
            "disable_sign_up": False,  # optional
        }
    }
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.magic_link import routes
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


MAGIC_LINK_ERROR_CODES: Mapping[str, str] = {
    "MAGIC_LINK_INVALID": "Magic link is invalid or has already been used.",
    "MAGIC_LINK_EXPIRED": "Magic link has expired.",
    "MAGIC_LINK_SIGN_UP_DISABLED": "Sign-up via magic link is disabled.",
    "MAGIC_LINK_NOT_CONFIGURED": "Magic link plugin is missing send_magic_link.",
}


@dataclass(frozen=True, slots=True)
class _MagicLinkPlugin:
    id: str = "magic-link"
    version: str | None = None
    schema: PluginSchema | None = None  # reuses core verification table
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sign-in/magic-link", window=60, max=5),
        RateLimitRule(path="/magic-link/verify", window=60, max=10),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(MAGIC_LINK_ERROR_CODES)
    )
    init: None = None


def magic_link() -> BetterAuthPlugin:
    """Construct the magic-link plugin."""
    return _MagicLinkPlugin()  # type: ignore[return-value]
