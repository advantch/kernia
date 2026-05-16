"""Built-in generic-OAuth provider helpers.

Mirrors `reference/.../plugins/generic-oauth/providers/`. Each helper returns a
`GenericOAuthConfig` ready to be passed to the generic OAuth plugin. The full
upstream list is exposed here.
"""

from better_auth.plugins.generic_oauth.providers.auth0 import auth0
from better_auth.plugins.generic_oauth.providers.gumroad import gumroad
from better_auth.plugins.generic_oauth.providers.hubspot import hubspot
from better_auth.plugins.generic_oauth.providers.keycloak import keycloak
from better_auth.plugins.generic_oauth.providers.line import line as line_generic
from better_auth.plugins.generic_oauth.providers.microsoft_entra_id import (
    microsoft_entra_id,
)
from better_auth.plugins.generic_oauth.providers.okta import okta
from better_auth.plugins.generic_oauth.providers.patreon import patreon
from better_auth.plugins.generic_oauth.providers.slack import slack as slack_generic

__all__ = [
    "auth0",
    "gumroad",
    "hubspot",
    "keycloak",
    "line_generic",
    "microsoft_entra_id",
    "okta",
    "patreon",
    "slack_generic",
]
