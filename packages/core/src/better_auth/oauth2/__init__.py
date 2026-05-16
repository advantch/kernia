"""OAuth2 / OIDC primitives.

Mirrors `reference/packages/better-auth/src/oauth2/`. Provides the building blocks
(PKCE, code exchange, id_token verification) reused by every social provider.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Mapping
from typing import Any


def pkce_verifier() -> str:
    """Return a fresh PKCE code verifier."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    """Compute the S256 code challenge for a given verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def random_state(n_bytes: int = 24) -> str:
    """Generate a CSRF state token for OAuth flows."""
    return base64.urlsafe_b64encode(secrets.token_bytes(n_bytes)).rstrip(b"=").decode("ascii")


async def exchange_code(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str | None,
) -> Mapping[str, Any]:
    """Exchange an authorization code for tokens. Implementation lands in Phase 2."""
    raise NotImplementedError("exchange_code is implemented in Phase 2")


async def verify_id_token(
    *,
    id_token: str,
    jwks_url: str,
    audience: str,
    issuer: str,
) -> Mapping[str, Any]:
    """Verify an OIDC id_token against the provider's JWKS. Phase 2."""
    raise NotImplementedError("verify_id_token is implemented in Phase 2")


async def fetch_userinfo(
    userinfo_url: str,
    *,
    access_token: str,
) -> Mapping[str, Any]:
    """Fetch normalized userinfo from the OIDC userinfo endpoint. Phase 2."""
    raise NotImplementedError("fetch_userinfo is implemented in Phase 2")


__all__ = [
    "exchange_code",
    "fetch_userinfo",
    "pkce_challenge",
    "pkce_verifier",
    "random_state",
    "verify_id_token",
]
