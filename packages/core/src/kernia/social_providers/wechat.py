"""WeChat OAuth2 provider. Mirrors `reference/.../social-providers/wechat.ts`.

WeChat uses non-standard parameter names (``appid``, ``secret``) and a custom
token endpoint shape — we send the request, then convert it through the same
``OAuthUserProfile`` shape as every other provider.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

import httpx

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


_AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect"
_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token"
_USER_INFO_URL = "https://api.weixin.qq.com/sns/userinfo"


async def _wechat_validate_token(
    *,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str | None,
) -> Mapping[str, Any]:
    params = {
        "appid": client_id,
        "secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(_TOKEN_URL, params=params)
        r.raise_for_status()
        return r.json()


async def _wechat_user_profile(tokens: Mapping[str, Any]) -> OAuthUserProfile:
    access_token = tokens.get("access_token")
    openid = tokens.get("openid")
    if not isinstance(access_token, str) or not isinstance(openid, str):
        raise ValueError("wechat: token response missing access_token or openid")
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(
            _USER_INFO_URL,
            params={"access_token": access_token, "openid": openid, "lang": "en"},
        )
        r.raise_for_status()
        profile = r.json()
    return OAuthUserProfile(
        id=str(profile.get("unionid") or profile.get("openid")),
        email=None,
        email_verified=False,
        name=profile.get("nickname"),
        image=profile.get("headimgurl"),
        raw=profile,
    )


class _WeChatProvider:
    id = "wechat"
    name = "WeChat"

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        scopes: tuple[str, ...],
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes

    async def authorize(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_verifier: str | None,
        nonce: str | None,
    ) -> str:
        params = {
            "appid": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": ",".join(self.scopes),
            "state": state,
        }
        return f"{_AUTH_URL}?{urlencode(params)}#wechat_redirect"

    async def validate_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> Mapping[str, Any]:
        return await _wechat_validate_token(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

    async def user_profile(self, *, tokens: Mapping[str, Any]) -> OAuthUserProfile:
        return await _wechat_user_profile(tokens)


def wechat(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("snsapi_login",),
) -> OAuthProvider:
    return _WeChatProvider(client_id=client_id, client_secret=client_secret, scopes=scopes)


__all__ = ["wechat"]
