"""kernia_sso — SAML 2.0 + OpenID Connect SSO plugin.

Mirrors `reference/packages/sso/src/`. The plugin exposes provider CRUD,
domain-verification, an OIDC authorization-code flow, and a SAML SP (metadata +
AuthnRequest + ACS + SLO). All routes live under `/sso/...`.

See `plugin.sso()` for the entry point.
"""

from kernia_sso import domain, oidc, saml
from kernia_sso.errors import SSO_ERROR_CODES
from kernia_sso.linking import (
    assign_organization_by_domain,
    assign_organization_from_provider,
)
from kernia_sso.plugin import sso
from kernia_sso.schema import SSO_DOMAIN_MODEL, SSO_MODELS, SSO_PROVIDER_MODEL

__all__ = [
    "SSO_DOMAIN_MODEL",
    "SSO_ERROR_CODES",
    "SSO_MODELS",
    "SSO_PROVIDER_MODEL",
    "assign_organization_by_domain",
    "assign_organization_from_provider",
    "domain",
    "oidc",
    "saml",
    "sso",
]
