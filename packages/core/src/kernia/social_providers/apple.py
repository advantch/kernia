"""Apple Sign-In provider.

Mirrors `reference/packages/core/src/social-providers/apple.ts`. Two important
quirks vs. the rest of the providers:

  1. Apple uses `response_mode=form_post`, so the callback arrives as a POST
     with `application/x-www-form-urlencoded` body. The core router has been
     extended to accept GET *and* POST on the OAuth callback path for this
     reason.
  2. Apple signs id_tokens with ES256 by default — our pure-stdlib verifier in
     `kernia.oauth2.verify_id_token` only handles RS256. We attempt RS256
     first; if Apple ever returns an ES256 token (current behavior) the call
     raises ``NotImplementedError`` with a clear message, and integrators can
     plug in `authlib` (already an optional dep). Production deployments should
     enable the dependency-group `jwt`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile


AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize"
TOKEN_URL = "https://appleid.apple.com/auth/token"
JWKS_URL = "https://appleid.apple.com/auth/keys"
ISSUER = "https://appleid.apple.com"


@dataclass
class _AppleProvider:
    client_id: str
    client_secret: str  # the JWT-signed client_secret as required by Apple
    scopes: tuple[str, ...] = ("name", "email")
    id: str = "apple"
    name: str = "Apple"

    async def authorize(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_verifier: str | None,
        nonce: str | None,
    ) -> str:
        params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code id_token",
            "response_mode": "form_post",
            "scope": " ".join(self.scopes),
            "state": state,
        }
        if nonce:
            params["nonce"] = nonce
        return f"{AUTHORIZATION_URL}?{urlencode(params)}"

    async def validate_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> Mapping[str, Any]:
        from kernia.oauth2 import exchange_code

        return await exchange_code(
            token_url=TOKEN_URL,
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

    async def user_profile(self, *, tokens: Mapping[str, Any]) -> OAuthUserProfile:
        from kernia.oauth2 import verify_id_token

        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise ValueError("Apple response missing id_token")
        try:
            claims = await verify_id_token(
                id_token=id_token,
                jwks_url=JWKS_URL,
                audience=self.client_id,
                issuer=ISSUER,
            )
        except ValueError as e:
            # Apple signs with ES256 — the stdlib verifier reports
            # 'unsupported alg'. Surface that distinctly so deployments know to
            # install the optional `jwt` dep-group.
            if "unsupported alg" in str(e):
                raise NotImplementedError(
                    "Apple id_token signatures use ES256; install the 'jwt' "
                    "dependency group (authlib) to verify them."
                ) from None
            raise
        return OAuthUserProfile(
            id=str(claims["sub"]),
            email=claims.get("email"),
            email_verified=_to_bool(claims.get("email_verified", False)),
            name=claims.get("name"),
            image=None,
            raw=claims,
        )


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() == "true"
    return bool(v)


def apple(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("name", "email"),
) -> OAuthProvider:
    """Construct an Apple Sign-In provider."""
    return _AppleProvider(
        client_id=client_id, client_secret=client_secret, scopes=scopes
    )


__all__ = ["apple"]
