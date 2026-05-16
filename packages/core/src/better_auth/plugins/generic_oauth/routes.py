"""Generic-OAuth endpoint definitions.

Mirrors `reference/.../plugins/generic-oauth/routes.ts`:
  * GET  /oauth2/sign-in/:provider_id   — build authorize URL & redirect
  * GET  /oauth2/callback/:provider_id  — handle authorization code
  * POST /oauth2/callback/:provider_id  — same, for response_mode=form_post
  * POST /oauth2/link-account/:provider_id — link to an authenticated user
  * POST /sign-in/oauth2                — JSON body equivalent of /sign-in
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.api.request import RedirectResponse
from better_auth.context import create_session
from better_auth.error import APIError
from better_auth.oauth2 import exchange_code, fetch_userinfo, pkce_verifier, random_state
from better_auth.oauth2.link_account import handle_oauth_user_info
from better_auth.oauth2.state import generate_state, parse_state
from better_auth.plugins.generic_oauth.config import GenericOAuthConfig
from better_auth.social_providers._base import OAuthUserProfile
from better_auth.social_providers._helpers import _default_profile_mapper
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions


@dataclass(frozen=True, slots=True)
class _Plan:
    """Internal: resolved endpoint URLs for one provider after optional discovery."""

    authorization_url: str
    token_url: str
    user_info_url: str | None
    issuer: str | None


_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}


async def _resolve(config: GenericOAuthConfig) -> _Plan:
    auth_url = config.authorization_url
    token_url = config.token_url
    user_info_url = config.user_info_url
    issuer = config.issuer
    if config.discovery_url:
        cached = _DISCOVERY_CACHE.get(config.discovery_url)
        if cached is None:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(config.discovery_url)
                r.raise_for_status()
                cached = r.json()
                _DISCOVERY_CACHE[config.discovery_url] = cached
        auth_url = auth_url or cached.get("authorization_endpoint")
        token_url = token_url or cached.get("token_endpoint")
        user_info_url = user_info_url or cached.get("userinfo_endpoint")
        issuer = issuer or cached.get("issuer")
    if not auth_url or not token_url:
        raise APIError(
            400,
            "INVALID_OAUTH_CONFIGURATION",
            message=f"{config.provider_id}: discovery did not yield endpoints",
        )
    return _Plan(
        authorization_url=auth_url,
        token_url=token_url,
        user_info_url=user_info_url,
        issuer=issuer,
    )


def _build_authorize_url(
    *,
    plan: _Plan,
    config: GenericOAuthConfig,
    state_token: str,
    code_verifier: str | None,
    redirect_uri: str,
) -> str:
    from urllib.parse import urlencode

    from better_auth.oauth2 import pkce_challenge

    params: dict[str, str] = {
        "client_id": config.client_id,
        "redirect_uri": redirect_uri,
        "response_type": config.response_type,
        "scope": " ".join(config.scopes),
        "state": state_token,
    }
    if config.response_mode:
        params["response_mode"] = config.response_mode
    if config.prompt:
        params["prompt"] = config.prompt
    if config.access_type:
        params["access_type"] = config.access_type
    if config.pkce and code_verifier:
        params["code_challenge"] = pkce_challenge(code_verifier)
        params["code_challenge_method"] = "S256"
    for k, v in config.authorization_url_params.items():
        params[k] = v
    return f"{plan.authorization_url}?{urlencode(params)}"


# ----- /oauth2/sign-in/:provider_id (GET) -----


def _sign_in_factory(options_state: dict[str, Any]):
    async def _handler(ctx: EndpointContext) -> RedirectResponse:
        provider_id = ctx.path_params.get("providerId") or ctx.path_params.get(
            "provider_id"
        )
        config = options_state["configs"].get(provider_id)
        if config is None:
            raise APIError(400, "PROVIDER_NOT_FOUND", message=f"unknown provider: {provider_id}")

        callback_url = (
            ctx.request.query.get("callbackURL")
            or ctx.request.query.get("callback_url")
            or ctx.auth.base_url
        )
        if isinstance(callback_url, list):
            callback_url = callback_url[0]
        error_callback_url = ctx.request.query.get("errorCallbackURL")
        if isinstance(error_callback_url, list):
            error_callback_url = error_callback_url[0]

        plan = await _resolve(config)
        code_verifier = pkce_verifier() if config.pkce else None
        state_token = generate_state(
            secret=ctx.auth.secret,
            callback_url=str(callback_url),
            provider_id=provider_id,
            error_callback_url=error_callback_url,
            code_verifier=code_verifier,
        )
        redirect_uri = config.redirect_uri or (
            f"{ctx.auth.base_url}/oauth2/callback/{provider_id}"
        )
        url = _build_authorize_url(
            plan=plan,
            config=config,
            state_token=state_token,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
        )
        return RedirectResponse(location=url)

    return _handler


# ----- POST /sign-in/oauth2 (JSON body) -----


class SignInOAuth2Body(BaseModel):
    provider_id: str
    callback_url: str | None = None
    error_callback_url: str | None = None
    new_user_callback_url: str | None = None
    request_sign_up: bool = False
    scopes: list[str] | None = None


def _sign_in_json_factory(options_state: dict[str, Any]):
    async def _handler(ctx: EndpointContext) -> dict[str, Any]:
        body: SignInOAuth2Body = ctx.body
        config = options_state["configs"].get(body.provider_id)
        if config is None:
            raise APIError(400, "PROVIDER_NOT_FOUND", message=f"unknown provider: {body.provider_id}")
        plan = await _resolve(config)
        code_verifier = pkce_verifier() if config.pkce else None
        state_token = generate_state(
            secret=ctx.auth.secret,
            callback_url=body.callback_url or ctx.auth.base_url,
            provider_id=body.provider_id,
            error_callback_url=body.error_callback_url,
            new_user_callback_url=body.new_user_callback_url,
            code_verifier=code_verifier,
        )
        redirect_uri = config.redirect_uri or (
            f"{ctx.auth.base_url}/oauth2/callback/{body.provider_id}"
        )
        # Merge dynamic scopes
        if body.scopes:
            config_merged = GenericOAuthConfig(
                **{**config.__dict__, "scopes": (*config.scopes, *body.scopes)}
            )
        else:
            config_merged = config
        url = _build_authorize_url(
            plan=plan,
            config=config_merged,
            state_token=state_token,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
        )
        return {"url": url, "redirect": True}

    return _handler


# ----- /oauth2/callback/:provider_id (GET + POST) -----


def _callback_factory(options_state: dict[str, Any]):
    async def _handler(ctx: EndpointContext) -> RedirectResponse:
        provider_id = ctx.path_params.get("providerId") or ctx.path_params.get(
            "provider_id"
        )
        config = options_state["configs"].get(provider_id)
        if config is None:
            raise APIError(400, "PROVIDER_NOT_FOUND")

        # form_post (Apple/etc.) — params arrive in the request body
        if ctx.request.method == "POST":
            raw_body = await ctx.request.body()
            from urllib.parse import parse_qs

            parsed = parse_qs(raw_body.decode("utf-8")) if raw_body else {}
            params: dict[str, str] = {k: v[0] for k, v in parsed.items() if v}
        else:
            params = {
                k: (v[0] if isinstance(v, list) else v)
                for k, v in ctx.request.query.items()
            }

        if params.get("error") or not params.get("code"):
            raise APIError(
                400,
                "OAUTH_ERROR",
                message=params.get("error_description") or "missing code",
            )

        state_token = params["state"]
        state = parse_state(state_token, secret=ctx.auth.secret)
        code_verifier = state.get("codeVerifier")
        callback_url = state.get("callbackURL", ctx.auth.base_url)

        plan = await _resolve(config)

        # Issuer validation (RFC 9207)
        if plan.issuer:
            iss = params.get("iss")
            if iss and iss != plan.issuer:
                raise APIError(400, "ISSUER_MISMATCH")
            if not iss and config.require_issuer_validation:
                raise APIError(400, "ISSUER_MISSING")

        redirect_uri = config.redirect_uri or (
            f"{ctx.auth.base_url}/oauth2/callback/{provider_id}"
        )

        if config.get_token is not None:
            tokens = await config.get_token(params["code"], redirect_uri, code_verifier)
        else:
            tokens = await exchange_code(
                token_url=plan.token_url,
                client_id=config.client_id,
                client_secret=config.client_secret,
                code=params["code"],
                redirect_uri=redirect_uri,
                code_verifier=code_verifier if config.pkce else None,
            )

        # User info
        if config.get_user_info is not None:
            user_info_raw = await config.get_user_info(tokens)
        else:
            user_info_raw = await _fallback_user_info(tokens, plan.user_info_url)
        if not user_info_raw:
            raise APIError(400, "USER_INFO_MISSING")

        if config.map_profile_to_user is not None:
            user_info_raw = {**user_info_raw, **config.map_profile_to_user(user_info_raw)}

        profile = _to_profile(user_info_raw)

        link_to_user_id = state.get("linkToUserId")
        trusted = ctx.auth.options.account.account_linking.trusted_providers
        user, _ = await handle_oauth_user_info(
            ctx.auth,
            provider_id=provider_id,
            profile=profile,
            tokens=tokens,
            link_to_user_id=link_to_user_id,
            disable_sign_up=config.disable_sign_up or config.disable_implicit_sign_up,
            trusted_providers=tuple(trusted),
        )

        # Issue a session unless we were linking to an already-signed-in user.
        if not link_to_user_id:
            session, cookies = await create_session(
                ctx.auth,
                user_id=user["id"],
                ip_address=ctx.request.headers.get("x-forwarded-for"),
                user_agent=ctx.request.headers.get("user-agent"),
            )
            ctx.set_cookies.extend(cookies)

        target = state.get("newUserCallbackURL") or callback_url
        return RedirectResponse(location=target)

    return _handler


async def _fallback_user_info(
    tokens: Mapping[str, Any],
    user_info_url: str | None,
) -> dict[str, Any] | None:
    """Decode id_token if present; else hit `user_info_url` with the access_token."""
    id_token = tokens.get("id_token")
    if isinstance(id_token, str):
        try:
            import base64
            import json

            _, payload, _ = id_token.split(".")
            pad = "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload + pad))
            if claims.get("sub") and claims.get("email"):
                return {
                    "id": claims["sub"],
                    "email": claims.get("email"),
                    "emailVerified": bool(claims.get("email_verified", False)),
                    "name": claims.get("name"),
                    "image": claims.get("picture"),
                    **claims,
                }
        except Exception:
            pass
    if not user_info_url:
        return None
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        return None
    raw = await fetch_userinfo(user_info_url, access_token=access_token)
    return {
        "id": raw.get("sub") or raw.get("id") or "",
        "email": raw.get("email"),
        "emailVerified": bool(raw.get("email_verified", False)),
        "name": raw.get("name"),
        "image": raw.get("picture"),
        **raw,
    }


def _to_profile(user_info: Mapping[str, Any]) -> OAuthUserProfile:
    sub = user_info.get("id") or user_info.get("sub")
    if not sub:
        raise APIError(400, "USER_INFO_MISSING_ID")
    return OAuthUserProfile(
        id=str(sub),
        email=user_info.get("email"),
        email_verified=bool(user_info.get("emailVerified") or user_info.get("email_verified")),
        name=user_info.get("name"),
        image=user_info.get("image") or user_info.get("picture"),
        raw=user_info,
    )


# ----- POST /oauth2/link-account (requires session) -----


class LinkAccountBody(BaseModel):
    provider_id: str
    callback_url: str
    error_callback_url: str | None = None
    scopes: list[str] | None = None


def _link_account_factory(options_state: dict[str, Any]):
    async def _handler(ctx: EndpointContext) -> dict[str, Any]:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        body: LinkAccountBody = ctx.body
        config = options_state["configs"].get(body.provider_id)
        if config is None:
            raise APIError(404, "PROVIDER_NOT_FOUND")

        plan = await _resolve(config)
        code_verifier = pkce_verifier() if config.pkce else None
        state_token = generate_state(
            secret=ctx.auth.secret,
            callback_url=body.callback_url,
            provider_id=body.provider_id,
            error_callback_url=body.error_callback_url,
            code_verifier=code_verifier,
            link_to_user_id=ctx.session.user_id,
        )
        redirect_uri = config.redirect_uri or (
            f"{ctx.auth.base_url}/oauth2/callback/{body.provider_id}"
        )
        if body.scopes:
            config_merged = GenericOAuthConfig(
                **{**config.__dict__, "scopes": (*config.scopes, *body.scopes)}
            )
        else:
            config_merged = config
        url = _build_authorize_url(
            plan=plan,
            config=config_merged,
            state_token=state_token,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
        )
        return {"url": url, "redirect": True}

    return _handler


def build_routes(options_state: dict[str, Any]) -> tuple[AuthEndpoint, ...]:
    return (
        create_auth_endpoint(
            "/oauth2/sign-in/:providerId",
            EndpointOptions(method="GET"),
            _sign_in_factory(options_state),
        ),
        create_auth_endpoint(
            "/sign-in/oauth2",
            EndpointOptions(method="POST", body=SignInOAuth2Body),
            _sign_in_json_factory(options_state),
        ),
        create_auth_endpoint(
            "/oauth2/callback/:providerId",
            EndpointOptions(method="GET"),
            _callback_factory(options_state),
        ),
        create_auth_endpoint(
            "/oauth2/callback/:providerId",
            EndpointOptions(method="POST"),
            _callback_factory(options_state),
        ),
        create_auth_endpoint(
            "/oauth2/link",
            EndpointOptions(method="POST", body=LinkAccountBody, requires_session=True),
            _link_account_factory(options_state),
        ),
    )


__all__ = ["build_routes"]
