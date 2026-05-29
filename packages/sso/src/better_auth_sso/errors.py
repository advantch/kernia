"""Error codes for the SSO plugin.

These map machine-readable codes to human messages and are surfaced via the
plugin's `error_codes` registry. Plugins must declare every code they raise so
the global registry can detect collisions at startup.
"""

from __future__ import annotations

from collections.abc import Mapping

SSO_ERROR_CODES: Mapping[str, str] = {
    "SSO_PROVIDER_NOT_FOUND": "SSO provider not found.",
    "SSO_PROVIDER_EXISTS": "An SSO provider with that issuer already exists.",
    "SSO_INVALID_KIND": "SSO provider kind must be 'saml' or 'oidc'.",
    "SSO_MISSING_CONFIG": "SSO provider config is missing required fields.",
    "SSO_ADMIN_REQUIRED": "Only administrators may manage SSO providers.",
    "SSO_DOMAIN_NOT_FOUND": "SSO domain registration not found.",
    "SSO_DOMAIN_VERIFICATION_FAILED": "Domain verification token did not match.",
    "SSO_OIDC_STATE_INVALID": "OIDC state mismatch or missing.",
    "SSO_OIDC_EXCHANGE_FAILED": "Failed to exchange the OIDC authorization code.",
    "SSO_SAML_RESPONSE_INVALID": "SAML response failed validation.",
    "SSO_SAML_AUTHN_FAILED": "Could not build SAML AuthnRequest.",
}


__all__ = ["SSO_ERROR_CODES"]
