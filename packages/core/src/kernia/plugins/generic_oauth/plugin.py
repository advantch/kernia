"""Generic OAuth plugin entry point.

Mirrors `genericOAuth()` in
`reference/packages/better-auth/src/plugins/generic-oauth/index.ts`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from kernia.plugins.generic_oauth.config import GenericOAuthConfig
from kernia.plugins.generic_oauth.routes import build_routes
from kernia.types.endpoint import AuthEndpoint
from kernia.types.plugin import KerniaPlugin

GENERIC_OAUTH_ERROR_CODES: Mapping[str, str] = {
    "INVALID_OAUTH_CONFIGURATION": "Invalid OAuth configuration",
    "TOKEN_URL_NOT_FOUND": "Invalid OAuth configuration. Token URL not found.",
    "PROVIDER_CONFIG_NOT_FOUND": "No config found for provider",
    "PROVIDER_ID_REQUIRED": "Provider ID is required",
    "INVALID_OAUTH_CONFIG": "Invalid OAuth configuration.",
    "SESSION_REQUIRED": "Session is required",
    "ISSUER_MISMATCH": (
        "OAuth issuer mismatch. The authorization server issuer does not match "
        "the expected value (RFC 9207)."
    ),
    "ISSUER_MISSING": (
        "OAuth issuer parameter missing. The authorization server did not include "
        "the required iss parameter (RFC 9207)."
    ),
    # Retained for backwards compatibility with existing callers.
    "PROVIDER_NOT_FOUND": "Unknown OAuth provider.",
    "OAUTH_ERROR": "OAuth provider returned an error.",
    "USER_INFO_MISSING": "OAuth provider did not return user info.",
    "USER_INFO_MISSING_ID": "OAuth user info has no id/sub.",
}


@dataclass(frozen=True, slots=True)
class _GenericOAuthPlugin:
    id: str = "generic-oauth"
    version: str | None = None
    schema: object | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: object | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple = ()
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(GENERIC_OAUTH_ERROR_CODES)
    )
    init: None = None


def generic_oauth(config: Sequence[GenericOAuthConfig]) -> KerniaPlugin:
    """Construct the generic OAuth plugin.

    `config` is a sequence of `GenericOAuthConfig` values (one per provider).
    The plugin registers `/oauth2/sign-in/:provider_id`, the callback endpoint
    (GET *and* POST for response_mode=form_post providers), the JSON
    `/sign-in/oauth2` endpoint, and `/oauth2/link` for account linking.
    """
    seen: set[str] = set()
    for c in config:
        if c.provider_id in seen:
            raise ValueError(f"duplicate provider_id: {c.provider_id}")
        seen.add(c.provider_id)
    options_state: dict = {"configs": {c.provider_id: c for c in config}}
    endpoints = build_routes(options_state)
    return _GenericOAuthPlugin(endpoints=endpoints)  # type: ignore[return-value]


__all__ = ["generic_oauth", "GENERIC_OAUTH_ERROR_CODES"]
