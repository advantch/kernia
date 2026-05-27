"""Google OAuth2 provider.

Mirrors `reference/packages/better-auth/src/social-providers/google.ts`. Implements the
`OAuthProvider` Protocol using the OAuth2 + OIDC endpoints documented at
https://accounts.google.com/.well-known/openid-configuration.

The crypto-sensitive parts (id_token signature verification, PKCE) are kept inside
`kernia.oauth2` so they're shared with the generic OAuth plugin.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlencode

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile


AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


@dataclass
class _GoogleProvider:
    client_id: str
    client_secret: str
    scopes: tuple[str, ...] = ("openid", "email", "profile")
    id: str = "google"
    name: str = "Google"
    hd: str | None = None  # restrict to a Workspace domain
    access_type: str = "offline"

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
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "access_type": self.access_type,
            "prompt": "select_account",
        }
        if nonce:
            params["nonce"] = nonce
        if self.hd:
            params["hd"] = self.hd
        if code_verifier:
            from kernia.oauth2 import pkce_challenge

            params["code_challenge"] = pkce_challenge(code_verifier)
            params["code_challenge_method"] = "S256"
        return f"{AUTHORIZATION_URL}?{urlencode(params)}"

    async def validate_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> Mapping[str, object]:
        from kernia.oauth2 import exchange_code

        return await exchange_code(
            token_url=TOKEN_URL,
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

    async def user_profile(
        self,
        *,
        tokens: Mapping[str, object],
    ) -> OAuthUserProfile:
        from kernia.oauth2 import fetch_userinfo, verify_id_token

        id_token = tokens.get("id_token")
        if isinstance(id_token, str):
            claims = await verify_id_token(
                id_token=id_token,
                jwks_url=JWKS_URL,
                audience=self.client_id,
                issuer="https://accounts.google.com",
            )
            return OAuthUserProfile(
                id=str(claims["sub"]),
                email=claims.get("email"),
                email_verified=bool(claims.get("email_verified", False)),
                name=claims.get("name"),
                image=claims.get("picture"),
                raw=claims,
            )
        # Fallback: hit the userinfo endpoint with the access token.
        access_token = tokens.get("access_token")
        if not isinstance(access_token, str):
            raise ValueError("Google response had neither id_token nor access_token")
        claims = await fetch_userinfo(USERINFO_URL, access_token=access_token)
        return OAuthUserProfile(
            id=str(claims["sub"]),
            email=claims.get("email"),
            email_verified=bool(claims.get("email_verified", False)),
            name=claims.get("name"),
            image=claims.get("picture"),
            raw=claims,
        )


def google(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "email", "profile"),
    hd: str | None = None,
) -> OAuthProvider:
    """Construct a Google provider. Mirrors `google()` in the reference."""
    return _GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        hd=hd,
    )
