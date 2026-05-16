"""Domain-verification + email-domain → provider routing.

Two responsibilities:

  1. Generate verification tokens and confirm domains. We use a simple bearer-token
     match: the registrant supplies the same token we generated when we issued the
     verification challenge. In a real deployment the deployer would publish that
     token via a `_better-auth-token.<domain>` DNS TXT record or a
     `/.well-known/better-auth-domain.txt` file; the plugin doesn't perform the
     lookup itself because that's deployment-specific. The endpoint accepts the
     proof from the operator and trusts them to have verified it out-of-band.

  2. Given an email, return the provider id (if any) that owns the email's domain
     and is verified. This is what powers the `/sign-in/email` BeforeHook that
     enforces SSO.

The same module owns both pieces so the routing-test and verification-test files
have a single import surface.
"""

from __future__ import annotations

import secrets

from better_auth.types.adapter import Where
from better_auth.types.context import AuthContext


def make_verification_token() -> str:
    """Return a URL-safe token suitable for a DNS-TXT verification record."""
    return secrets.token_urlsafe(24)


def email_domain(email: str) -> str:
    """Lower-case domain portion of an email, or empty string if malformed."""
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower()


async def provider_for_email(
    auth: AuthContext, email: str
) -> tuple[str, str] | None:
    """Return `(provider_id, domain)` if `email` belongs to a verified SSO domain.

    Returns `None` if no domain matches or the matching domain is not yet verified.
    """
    domain = email_domain(email)
    if not domain:
        return None
    row = await auth.adapter.find_one(
        model="ssoDomain",
        where=(
            Where(field="domain", value=domain),
            Where(field="verified", value=True),
        ),
    )
    if not row:
        return None
    return row["ssoProviderId"], domain


__all__ = ["email_domain", "make_verification_token", "provider_for_email"]
