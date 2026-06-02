"""Generic-OAuth endpoint definitions.

Mirrors `reference/.../plugins/generic-oauth/routes.ts`:
  * GET  /oauth2/sign-in/:provider_id   — build authorize URL & redirect
  * GET  /oauth2/callback/:provider_id  — handle authorization code
  * POST /oauth2/callback/:provider_id  — same, for response_mode=form_post
  * POST /oauth2/link-account/:provider_id — link to an authenticated user
  * POST /sign-in/oauth2                — JSON body equivalent of /sign-in
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from kernia.api.endpoint import create_auth_endpoint
from kernia.api.request import RedirectResponse
from kernia.context import create_session
from kernia.error import APIError
from kernia.oauth2 import exchange_code, fetch_userinfo, pkce_verifier
from kernia.oauth2.link_account import handle_oauth_user_info
from kernia.oauth2.state import generate_state, parse_state
from kernia.plugins.generic_oauth.config import GenericOAuthConfig
from kernia.social_providers._base import OAuthUserProfile
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions


@dataclass(frozen=True, slots=True)
class _Plan:
    """Internal: resolved endpoint URLs for one provider after optional discovery."""

    authorization_url: str
    token_url: str
    user_info_url: str | None
    issuer: str | None


_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}


def _generate_state_with_signup(
    *,
    secret: str,
    callback_url: str,
    provider_id: str,
    error_callback_url: str | None = None,
    new_user_callback_url: str | None = None,
    code_verifier: str | None = None,
    request_sign_up: bool = False,
    link_to_user_id: str | None = None,
    link_email: str | None = None,
) -> str:
    """Signed state token that also carries ``requestSignUp``.

    Mirrors upstream ``generateState`` which threads ``requestSignUp`` through
    the callback so ``disableImplicitSignUp`` providers can still create a user
    when sign-up was explicitly requested. The core ``generate_state`` helper
    does not expose this field, so the plugin builds the payload locally using
    the same signed/base64 wire format and ``parse_state`` reads it back.
    """
    import base64 as _base64
    import json as _json
    import secrets as _secrets
    import time as _time

    from kernia.cookies import sign as _sign

    payload: dict[str, Any] = {
        "v": 1,
        "callbackURL": callback_url,
        "providerId": provider_id,
        "nonce": _base64.urlsafe_b64encode(_secrets.token_bytes(16))
        .rstrip(b"=")
        .decode("ascii"),
        "createdAt": int(_time.time()),
    }
    if error_callback_url:
        payload["errorCallbackURL"] = error_callback_url
    if new_user_callback_url:
        payload["newUserCallbackURL"] = new_user_callback_url
    if code_verifier:
        payload["codeVerifier"] = code_verifier
    if request_sign_up:
        payload["requestSignUp"] = True
    if link_to_user_id:
        payload["linkToUserId"] = link_to_user_id
    if link_email:
        payload["linkEmail"] = link_email
    raw = (
        _base64.urlsafe_b64encode(
            _json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return _sign(raw, secret)


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

    from kernia.oauth2 import pkce_challenge

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
    # Wire format is camelCase (matching the JS client + upstream tests); accept
    # both camelCase aliases and snake_case field names.
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    provider_id: str = Field(alias="providerId")
    callback_url: str | None = Field(default=None, alias="callbackURL")
    error_callback_url: str | None = Field(default=None, alias="errorCallbackURL")
    new_user_callback_url: str | None = Field(default=None, alias="newUserCallbackURL")
    request_sign_up: bool = Field(default=False, alias="requestSignUp")
    disable_redirect: bool = Field(default=False, alias="disableRedirect")
    scopes: list[str] | None = None


def _sign_in_json_factory(options_state: dict[str, Any]):
    async def _handler(ctx: EndpointContext) -> dict[str, Any]:
        body: SignInOAuth2Body = ctx.body
        config = options_state["configs"].get(body.provider_id)
        if config is None:
            raise APIError(
                400,
                "PROVIDER_CONFIG_NOT_FOUND",
                message=f"No config found for provider {body.provider_id}",
            )
        plan = await _resolve(config)
        code_verifier = pkce_verifier() if config.pkce else None
        state_token = _generate_state_with_signup(
            secret=ctx.auth.secret,
            callback_url=body.callback_url or ctx.auth.base_url,
            provider_id=body.provider_id,
            error_callback_url=body.error_callback_url,
            new_user_callback_url=body.new_user_callback_url,
            code_verifier=code_verifier,
            request_sign_up=body.request_sign_up,
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
        return {"url": url, "redirect": not body.disable_redirect}

    return _handler


# ----- /oauth2/callback/:provider_id (GET + POST) -----


def _default_error_url(ctx: EndpointContext) -> str:
    return f"{ctx.auth.base_url}/error"


def _error_redirect(base: str, error: str) -> RedirectResponse:
    """Append ``?error=`` / ``&error=`` to the redirect URL (upstream parity)."""
    from urllib.parse import quote

    sep = "&" if "?" in base else "?"
    return RedirectResponse(location=f"{base}{sep}error={quote(error)}")


def _callback_factory(options_state: dict[str, Any]):
    async def _handler(ctx: EndpointContext) -> RedirectResponse:
        provider_id = ctx.path_params.get("providerId") or ctx.path_params.get(
            "provider_id"
        )
        config = options_state["configs"].get(provider_id)
        if config is None:
            raise APIError(
                400,
                "PROVIDER_CONFIG_NOT_FOUND",
                message=f"No config found for provider {provider_id}",
            )

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

        default_error_url = _default_error_url(ctx)

        # Provider returned an error or no code at all → bounce to /error.
        if params.get("error") or not params.get("code"):
            err = params.get("error") or "oAuth_code_missing"
            desc = params.get("error_description") or ""
            from urllib.parse import quote

            return RedirectResponse(
                location=(
                    f"{default_error_url}?error={quote(err)}"
                    f"&error_description={quote(desc)}"
                )
            )

        # Parse + verify state. A missing or tampered state must not be fatal;
        # upstream redirects to the error page so the user can restart.
        state_token = params.get("state")
        if not state_token:
            return _error_redirect(default_error_url, "please_restart_the_process")
        try:
            state = parse_state(state_token, secret=ctx.auth.secret)
        except ValueError:
            # Either the signature failed (forged/mismatched state — CSRF) or the
            # token is otherwise unreadable. Upstream distinguishes the two:
            # a state that does not match the issued one → state_mismatch,
            # an absent/garbled state → please_restart_the_process.
            return _error_redirect(default_error_url, "state_mismatch")

        code_verifier = state.get("codeVerifier")
        callback_url = state.get("callbackURL", ctx.auth.base_url)
        new_user_url = state.get("newUserCallbackURL")
        error_url = state.get("errorCallbackURL") or default_error_url
        request_sign_up = bool(state.get("requestSignUp"))
        link_to_user_id = state.get("linkToUserId")

        plan = await _resolve(config)

        # Issuer validation (RFC 9207)
        if plan.issuer:
            iss = params.get("iss")
            if iss and iss != plan.issuer:
                return _error_redirect(error_url, "issuer_mismatch")
            if not iss and config.require_issuer_validation:
                return _error_redirect(error_url, "issuer_missing")

        redirect_uri = config.redirect_uri or (
            f"{ctx.auth.base_url}/oauth2/callback/{provider_id}"
        )

        # --- token exchange ---
        try:
            if config.get_token is not None:
                tokens = await config.get_token(
                    params["code"], redirect_uri, code_verifier
                )
            else:
                tokens = await exchange_code(
                    token_url=plan.token_url,
                    client_id=config.client_id,
                    client_secret=config.client_secret,
                    code=params["code"],
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier if config.pkce else None,
                )
        except Exception:
            return _error_redirect(error_url, "oauth_code_verification_failed")
        if not tokens:
            return _error_redirect(error_url, "oauth_code_verification_failed")

        # --- user info ---
        if config.get_user_info is not None:
            user_info_raw = await config.get_user_info(tokens)
        else:
            user_info_raw = await _fallback_user_info(tokens, plan.user_info_url)
        if not user_info_raw:
            return _error_redirect(error_url, "user_info_is_missing")

        mapped = (
            config.map_profile_to_user(user_info_raw)
            if config.map_profile_to_user is not None
            else {}
        )
        # Upstream awaits mapProfileToUser, so support async mappers too.
        if inspect.isawaitable(mapped):
            mapped = await mapped
        if mapped:
            user_info_raw = {**user_info_raw, **mapped}

        # email / name resolution (upstream redirects, doesn't 500)
        email = user_info_raw.get("email")
        if not email:
            return _error_redirect(error_url, "email_is_missing")
        name = user_info_raw.get("name")
        if not name:
            return _error_redirect(error_url, "name_is_missing")

        profile = _to_profile(user_info_raw)

        trusted = ctx.auth.options.account.account_linking.trusted_providers
        allow_different_emails = (
            ctx.auth.options.account.account_linking.allow_different_emails
        )

        # Explicit account-link path requires the emails to match (unless the
        # instance opts into linking accounts with different emails).
        if link_to_user_id:
            link_email = state.get("linkEmail")
            if (
                not allow_different_emails
                and link_email
                and str(link_email).lower() != str(email).lower()
            ):
                return _error_redirect(error_url, "email_doesn't_match")

        # Was this a brand-new registration? (used to pick newUserCallbackURL)
        is_register = await _is_new_registration(
            ctx, provider_id=provider_id, account_id=profile.id, email=email
        )

        disable_sign_up = (
            config.disable_implicit_sign_up and not request_sign_up
        ) or config.disable_sign_up

        try:
            user, _ = await handle_oauth_user_info(
                ctx.auth,
                provider_id=provider_id,
                profile=profile,
                tokens=tokens,
                link_to_user_id=link_to_user_id,
                disable_sign_up=disable_sign_up,
                trusted_providers=tuple(trusted),
            )
        except APIError as e:
            code = getattr(e, "code", "") or ""
            if code in ("SIGNUP_DISABLED",) or "SIGNUP" in code.upper():
                return _error_redirect(error_url, "signup_disabled")
            if "ALREADY_LINKED" in code.upper():
                return _error_redirect(
                    error_url, "account_already_linked_to_different_user"
                )
            raise

        # Linking to a signed-in user: no new session, redirect to callbackURL.
        if link_to_user_id:
            return RedirectResponse(location=callback_url)

        session, cookies = await create_session(
            ctx.auth,
            user_id=user["id"],
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        ctx.set_cookies.extend(cookies)

        target = (new_user_url or callback_url) if is_register else callback_url
        return RedirectResponse(location=target)

    return _handler


async def _is_new_registration(
    ctx: EndpointContext,
    *,
    provider_id: str,
    account_id: str,
    email: str | None,
) -> bool:
    """Best-effort mirror of upstream ``result.isRegister``.

    A registration creates a brand-new user. That only happens when no account
    row already exists for ``(provider_id, account_id)`` *and* no user already
    exists with the resolved email (which would otherwise be linked/returned).
    """
    from kernia.types.adapter import Where

    existing_account = await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="providerId", value=provider_id),
            Where(field="accountId", value=str(account_id)),
        ),
    )
    if existing_account is not None:
        return False
    if email:
        existing_user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="email", value=email),),
        )
        if existing_user is not None:
            return False
    return True


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
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    provider_id: str = Field(alias="providerId")
    callback_url: str = Field(alias="callbackURL")
    error_callback_url: str | None = Field(default=None, alias="errorCallbackURL")
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
        link_email = None
        if ctx.user is not None:
            link_email = ctx.user.get("email") if isinstance(ctx.user, dict) else getattr(
                ctx.user, "email", None
            )
        state_token = _generate_state_with_signup(
            secret=ctx.auth.secret,
            callback_url=body.callback_url,
            provider_id=body.provider_id,
            error_callback_url=body.error_callback_url,
            code_verifier=code_verifier,
            link_to_user_id=ctx.session.user_id,
            link_email=link_email,
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
