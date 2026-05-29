"""Captcha plugin construction.

Mirrors `reference/packages/better-auth/src/plugins/captcha/index.ts`. The plugin
contributes a before-hook bound to a configurable set of "protected" endpoints;
the hook reads the captcha token off the request header, asks the provider to
verify it, and short-circuits with `CAPTCHA_FAILED` on rejection.

A direct `/captcha/verify` endpoint is also exposed for client-driven flows
that want to verify a token out of band.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.plugins.captcha.providers import CaptchaProvider
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from better_auth.types.hooks import BeforeHook, PluginHooks
from better_auth.types.plugin import BetterAuthPlugin

CAPTCHA_ERROR_CODES: Mapping[str, str] = {
    "CAPTCHA_FAILED": "Captcha verification failed.",
    "CAPTCHA_TOKEN_MISSING": "Captcha token is missing.",
}


DEFAULT_PROTECTED_ENDPOINTS: tuple[str, ...] = (
    "/sign-in/email",
    "/sign-up/email",
    "/forget-password",
)


class CaptchaVerifyBody(BaseModel):
    token: str


def _extract_token(ctx: EndpointContext) -> str | None:
    headers = ctx.request.headers
    return headers.get("x-captcha-token") or headers.get("x-captcha-response")


def _client_ip(ctx: EndpointContext) -> str | None:
    headers = ctx.request.headers
    fwd = headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return headers.get("x-real-ip") or None


def _build_before_hook(
    provider: CaptchaProvider, protected: tuple[str, ...]
) -> BeforeHook:
    paths = set(protected)

    def matcher(ctx: EndpointContext) -> bool:
        return ctx.request.path in paths

    async def handler(ctx: EndpointContext) -> None:
        token = _extract_token(ctx)
        if not token:
            raise APIError(400, "CAPTCHA_TOKEN_MISSING")
        result = await provider.verify(token, _client_ip(ctx))
        if not result.success:
            raise APIError(
                403,
                "CAPTCHA_FAILED",
                message=f"Captcha verification failed ({result.error or 'unknown'}).",
            )

    return BeforeHook(match=matcher, handler=handler)


def _build_verify_endpoint(provider: CaptchaProvider) -> AuthEndpoint:
    async def verify_handler(ctx: EndpointContext) -> dict[str, object]:
        body: CaptchaVerifyBody = ctx.body
        result = await provider.verify(body.token, _client_ip(ctx))
        return {"success": result.success, "error": result.error}

    return create_auth_endpoint(
        "/captcha/verify",
        EndpointOptions(method="POST", body=CaptchaVerifyBody),
        verify_handler,
    )


@dataclass(frozen=True, slots=True)
class _CaptchaPlugin:
    id: str
    version: str | None
    endpoints: tuple[AuthEndpoint, ...]
    hooks: PluginHooks
    error_codes: Mapping[str, str]
    schema: None = None
    middlewares: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    init: None = None


def captcha(
    provider: CaptchaProvider,
    *,
    protected_endpoints: tuple[str, ...] = DEFAULT_PROTECTED_ENDPOINTS,
) -> BetterAuthPlugin:
    """Build the captcha plugin.

    `provider` is any object implementing `CaptchaProvider`. `protected_endpoints`
    is the list of paths to gate behind a captcha token check (defaults match
    better-auth's TS defaults).
    """
    hooks = PluginHooks(before=(_build_before_hook(provider, protected_endpoints),))
    return _CaptchaPlugin(  # type: ignore[return-value]
        id="captcha",
        version=None,
        endpoints=(_build_verify_endpoint(provider),),
        hooks=hooks,
        error_codes=dict(CAPTCHA_ERROR_CODES),
    )


__all__ = ["captcha", "CAPTCHA_ERROR_CODES", "DEFAULT_PROTECTED_ENDPOINTS"]
