"""better_auth_sso — SAML 2.0 + OpenID Connect SSO plugin.

Mirrors `reference/packages/sso/src/`. The plugin exposes provider CRUD,
domain-verification, an OIDC authorization-code flow, and a SAML SP (metadata +
AuthnRequest + ACS + SLO). All routes live under `/sso/...`.

See `plugin.sso()` for the entry point.
"""

from better_auth_sso import domain, oidc, saml
from better_auth_sso.errors import SSO_ERROR_CODES
from better_auth_sso.plugin import sso
from better_auth_sso.schema import SSO_DOMAIN_MODEL, SSO_MODELS, SSO_PROVIDER_MODEL

__all__ = [
    "SSO_DOMAIN_MODEL",
    "SSO_ERROR_CODES",
    "SSO_MODELS",
    "SSO_PROVIDER_MODEL",
    "domain",
    "oidc",
    "saml",
    "sso",
]
