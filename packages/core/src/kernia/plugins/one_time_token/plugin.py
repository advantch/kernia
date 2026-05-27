"""One-time-token plugin construction.

Mirrors `reference/packages/better-auth/src/plugins/one-time-token/index.ts`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from kernia.plugins.one_time_token import routes
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


ONE_TIME_TOKEN_ERROR_CODES: Mapping[str, str] = {
    "ONE_TIME_TOKEN_INVALID": "One-time token is invalid or has already been used.",
    "ONE_TIME_TOKEN_EXPIRED": "One-time token has expired.",
}


@dataclass(frozen=True, slots=True)
class _OneTimeTokenPlugin:
    id: str = "one-time-token"
    version: str | None = None
    schema: PluginSchema | None = None  # reuses core verification table
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/generate-one-time-token", window=60, max=10),
        RateLimitRule(path="/verify-one-time-token", window=60, max=10),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(ONE_TIME_TOKEN_ERROR_CODES)
    )
    init: None = None


def one_time_token() -> KerniaPlugin:
    """Construct the one-time-token plugin."""
    return _OneTimeTokenPlugin()  # type: ignore[return-value]
