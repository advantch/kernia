"""Canonical social sign-in routes.

Mirrors `reference/.../api/routes/sign-in.ts::signInSocial` and `callback.ts`:

  POST /sign-in/social     — body {provider, callbackURL, ...} → {url, redirect: true}
  GET  /callback/:provider — handle the OAuth redirect, create session, redirect
  POST /callback/:provider — same path for `response_mode=form_post` (Apple)

Providers come from `BetterAuthOptions.social_providers`. Each is an
`OAuthProvider` from `better_auth.social_providers`. The crypto plumbing
(`generate_state`/`parse_state`, `handle_oauth_user_info`) is shared with the
`generic_oauth` plugin.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.api.request import RedirectResponse
from better_auth.context import create_session
from better_auth.error import APIError
from better_auth.oauth2 import pkce_verifier
from better_auth.oauth2.link_account import handle_oauth_user_info
from better_auth.oauth2.state import generate_state, parse_state
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions


class SignInSocialBody(BaseModel):
    provider: str
    callback_url: str | None = None
    error_callback_url: str | None = None
    new_user_callback_url: str | None = None
    request_sign_up: bool = False
    scopes: list[str] | None = None
    disable_redirect: bool = False


def _redirect_uri_for(ctx: EndpointContext, provider_id: str) -> str:
    return f"{ctx.auth.base_url}/callback/{provider_id}"


async def _sign_in_social(ctx: EndpointContext) -> dict[str, Any]:
    body: SignInSocialBody = ctx.body
    provider = ctx.auth.options.social_providers.get(body.provider)
    if provider is None:
        raise APIError(400, "PROVIDER_NOT_FOUND", message=f"unknown provider: {body.provider}")

    # PKCE: enable when the provider declares so (most OIDC providers don't
    # require it but happily accept it).
    code_verifier = pkce_verifier()
    state_token = generate_state(
        secret=ctx.auth.secret,
        callback_url=body.callback_url or ctx.auth.base_url,
        provider_id=body.provider,
        error_callback_url=body.error_callback_url,
        new_user_callback_url=body.new_user_callback_url,
        code_verifier=code_verifier,
    )
    url = await provider.authorize(
        redirect_uri=_redirect_uri_for(ctx, body.provider),
        state=state_token,
        code_verifier=code_verifier,
        nonce=None,
    )
    if body.disable_redirect:
        return {"url": url, "redirect": False}
    return {"url": url, "redirect": True}


async def _callback(ctx: EndpointContext) -> RedirectResponse:
    provider_id = ctx.path_params.get("provider") or ctx.path_params.get("providerId")
    if not provider_id:
        raise APIError(400, "PROVIDER_NOT_FOUND")
    provider = ctx.auth.options.social_providers.get(provider_id)
    if provider is None:
        raise APIError(400, "PROVIDER_NOT_FOUND")

    if ctx.request.method == "POST":
        from urllib.parse import parse_qs

        raw = await ctx.request.body()
        parsed = parse_qs(raw.decode("utf-8")) if raw else {}
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

    state = parse_state(params["state"], secret=ctx.auth.secret)
    code_verifier = state.get("codeVerifier")
    callback_url = state.get("callbackURL", ctx.auth.base_url)
    link_to_user_id = state.get("linkToUserId")

    tokens = await provider.validate_token(
        code=params["code"],
        redirect_uri=_redirect_uri_for(ctx, provider_id),
        code_verifier=code_verifier,
    )
    profile = await provider.user_profile(tokens=tokens)

    trusted = ctx.auth.options.account.account_linking.trusted_providers
    user, _ = await handle_oauth_user_info(
        ctx.auth,
        provider_id=provider_id,
        profile=profile,
        tokens=tokens,
        link_to_user_id=link_to_user_id,
        disable_sign_up=False,
        trusted_providers=tuple(trusted),
    )

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


SOCIAL_ROUTES: tuple[AuthEndpoint, ...] = (
    create_auth_endpoint(
        "/sign-in/social",
        EndpointOptions(method="POST", body=SignInSocialBody),
        _sign_in_social,
    ),
    create_auth_endpoint(
        "/callback/:provider",
        EndpointOptions(method="GET"),
        _callback,
    ),
    create_auth_endpoint(
        "/callback/:provider",
        EndpointOptions(method="POST"),
        _callback,
    ),
)
