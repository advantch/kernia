"""`OAuthProvider` Protocol — the contract every social provider implements.

Mirrors `reference/packages/better-auth/src/social-providers/types.ts`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class OAuthUserProfile:
    """Normalized user info returned by `user_profile`."""

    id: str
    email: str | None
    email_verified: bool
    name: str | None
    image: str | None
    raw: Mapping[str, object]


@runtime_checkable
class OAuthProvider(Protocol):
    """Contract for an OAuth2 provider.

    `authorize` returns the URL to redirect the user to; `validate_token` exchanges
    the auth code for tokens; `user_profile` fetches the user's profile using the
    issued access token (or decodes it from the id_token).
    """

    id: str
    name: str
    scopes: tuple[str, ...]

    async def authorize(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_verifier: str | None,
        nonce: str | None,
    ) -> str: ...

    async def validate_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> Mapping[str, object]: ...

    async def user_profile(
        self,
        *,
        tokens: Mapping[str, object],
    ) -> OAuthUserProfile: ...
