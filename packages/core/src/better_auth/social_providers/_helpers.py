"""Shared helpers used by social-provider constructors.

These keep the per-provider files tiny: roughly 80% of the providers follow the
same authorize-URL → token-exchange → userinfo flow, differing only in endpoint
URLs, default scopes, and how they shape the JSON userinfo response into our
`OAuthUserProfile`. We capture that shape here.

The crypto-sensitive bits (PKCE, id_token verification) still live in
`better_auth.oauth2`; helpers in this module are pure URL-construction and
HTTP-shape glue.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx

from better_auth.oauth2 import exchange_code, fetch_userinfo, pkce_challenge
from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile


ProfileMapper = Callable[[Mapping[str, Any]], OAuthUserProfile]


@dataclass
class _StandardOAuthProvider:
    """Configurable OAuth2 provider used by the canonical built-in providers.

    Roughly equivalent to a single entry in the reference's social-providers/
    directory. Use `make_provider` to construct one.
    """

    id: str
    name: str
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    user_info_endpoint: str | None
    scopes: tuple[str, ...]
    scope_separator: str = " "
    extra_authorize_params: Mapping[str, str] = field(default_factory=dict)
    requires_pkce: bool = False
    use_basic_auth: bool = False
    response_type: str = "code"
    response_mode: str | None = None
    profile_mapper: ProfileMapper | None = None
    token_post_headers: Mapping[str, str] | None = None
    extra_userinfo_headers: Mapping[str, str] | None = None
    # Optional override hook
    fetch_profile: Callable[[Mapping[str, Any]], Awaitable[OAuthUserProfile]] | None = None

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
            "response_type": self.response_type,
            "scope": self.scope_separator.join(self.scopes),
            "state": state,
        }
        if self.response_mode:
            params["response_mode"] = self.response_mode
        if nonce:
            params["nonce"] = nonce
        if code_verifier:
            params["code_challenge"] = pkce_challenge(code_verifier)
            params["code_challenge_method"] = "S256"
        for k, v in self.extra_authorize_params.items():
            params[k] = v
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    async def validate_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> Mapping[str, Any]:
        if self.use_basic_auth:
            # Pass client creds in the Authorization header (RFC 6749 §2.3.1).
            data: dict[str, str] = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            }
            if code_verifier:
                data["code_verifier"] = code_verifier
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(
                    self.token_endpoint,
                    data=data,
                    headers={
                        "accept": "application/json",
                        **(self.token_post_headers or {}),
                    },
                    auth=(self.client_id, self.client_secret),
                )
                r.raise_for_status()
                return r.json()
        return await exchange_code(
            token_url=self.token_endpoint,
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

    async def user_profile(self, *, tokens: Mapping[str, Any]) -> OAuthUserProfile:
        if self.fetch_profile is not None:
            return await self.fetch_profile(tokens)
        if not self.user_info_endpoint:
            raise ValueError(
                f"{self.id}: no user_info_endpoint configured and no fetch_profile override"
            )
        access_token = tokens.get("access_token")
        if not isinstance(access_token, str):
            raise ValueError(f"{self.id}: token response has no access_token")
        headers: dict[str, str] = {
            "authorization": f"Bearer {access_token}",
            "accept": "application/json",
        }
        if self.extra_userinfo_headers:
            headers.update(self.extra_userinfo_headers)
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(self.user_info_endpoint, headers=headers)
            r.raise_for_status()
            raw = r.json()
        if self.profile_mapper is None:
            return _default_profile_mapper(raw)
        return self.profile_mapper(raw)


def _default_profile_mapper(raw: Mapping[str, Any]) -> OAuthUserProfile:
    """OIDC-style mapper: assumes `sub`, `email`, `name`, `picture`."""
    sub = raw.get("sub") or raw.get("id") or raw.get("user_id")
    if sub is None:
        raise ValueError("Userinfo response missing 'sub' or 'id'")
    return OAuthUserProfile(
        id=str(sub),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name"),
        image=raw.get("picture") or raw.get("avatar_url") or raw.get("image"),
        raw=raw,
    )


def make_provider(
    *,
    id: str,
    name: str,
    client_id: str,
    client_secret: str,
    authorization_endpoint: str,
    token_endpoint: str,
    user_info_endpoint: str | None = None,
    scopes: tuple[str, ...] = (),
    scope_separator: str = " ",
    extra_authorize_params: Mapping[str, str] | None = None,
    requires_pkce: bool = False,
    use_basic_auth: bool = False,
    response_type: str = "code",
    response_mode: str | None = None,
    profile_mapper: ProfileMapper | None = None,
    token_post_headers: Mapping[str, str] | None = None,
    extra_userinfo_headers: Mapping[str, str] | None = None,
    fetch_profile: Callable[[Mapping[str, Any]], Awaitable[OAuthUserProfile]] | None = None,
) -> OAuthProvider:
    """Build a standard OAuth2 provider.

    Most of the built-in providers can be expressed via this helper; only
    Apple / Microsoft / a handful of others need a hand-rolled class because
    they layer extra steps (form_post response mode, multi-tenant URLs, etc).
    """
    return _StandardOAuthProvider(
        id=id,
        name=name,
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        user_info_endpoint=user_info_endpoint,
        scopes=scopes,
        scope_separator=scope_separator,
        extra_authorize_params=extra_authorize_params or {},
        requires_pkce=requires_pkce,
        use_basic_auth=use_basic_auth,
        response_type=response_type,
        response_mode=response_mode,
        profile_mapper=profile_mapper,
        token_post_headers=token_post_headers,
        extra_userinfo_headers=extra_userinfo_headers,
        fetch_profile=fetch_profile,
    )


__all__ = ["make_provider", "ProfileMapper", "_default_profile_mapper"]
