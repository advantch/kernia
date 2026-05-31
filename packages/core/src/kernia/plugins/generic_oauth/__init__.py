"""Generic OAuth plugin.

Mirrors `reference/packages/better-auth/src/plugins/generic-oauth/`. Lets users
plug in any OAuth2/OIDC provider by URL — discovery, code exchange, userinfo —
without writing a dedicated provider module.
"""

from kernia.plugins.generic_oauth.config import GenericOAuthConfig
from kernia.plugins.generic_oauth.plugin import (
    GENERIC_OAUTH_ERROR_CODES,
    generic_oauth,
)
from kernia.plugins.generic_oauth.providers import (
    auth0,
    gumroad,
    hubspot,
    keycloak,
    line_generic,
    microsoft_entra_id,
    okta,
    patreon,
    slack_generic,
)

__all__ = [
    "GENERIC_OAUTH_ERROR_CODES",
    "GenericOAuthConfig",
    "auth0",
    "generic_oauth",
    "gumroad",
    "hubspot",
    "keycloak",
    "line_generic",
    "microsoft_entra_id",
    "okta",
    "patreon",
    "slack_generic",
]
