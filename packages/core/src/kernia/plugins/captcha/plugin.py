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

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.plugins.captcha.providers import CaptchaProvider
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.hooks import BeforeHook, PluginHooks
from kernia.types.plugin import KerniaPlugin

CAPTCHA_ERROR_CODES: Mapping[str, str] = {
    "CAPTCHA_FAILED": "Captcha verification failed.",
    "CAPTCHA_TOKEN_MISSING": "Captcha token is missing.",
    # Raised (HTTP 500) when the siteverify service is unreachable or the
    # provider is misconfigured (missing secret) — distinct from a clean
    # validation failure (403). Mirrors upstream's SERVICE_UNAVAILABLE /
    # MISSING_SECRET_KEY internal errors surfaced as UNKNOWN_ERROR (500).
    "CAPTCHA_SERVICE_UNAVAILABLE": "Captcha service unavailable.",
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


def _build_before_hook(provider: CaptchaProvider, protected: tuple[str, ...]) -> BeforeHook:
    paths = set(protected)

    def matcher(ctx: EndpointContext) -> bool:
        return ctx.request.path in paths

    # Mirror upstream's `if (!options.secretKey) throw ... (→ 500)`: a provider
    # built without a secret is a server misconfiguration, not a 400/403.
    missing_secret = hasattr(provider, "secret") and not provider.secret

    async def handler(ctx: EndpointContext) -> None:
        if missing_secret:
            raise APIError(500, "CAPTCHA_SERVICE_UNAVAILABLE", message="Missing secret key")
        token = _extract_token(ctx)
        if not token:
            raise APIError(400, "CAPTCHA_TOKEN_MISSING")
        result = await provider.verify(token, _client_ip(ctx))
        if getattr(result, "service_error", False):
            # The siteverify call failed to reach/parse — surface as 500, not 403.
            raise APIError(
                500,
                "CAPTCHA_SERVICE_UNAVAILABLE",
                message=f"Captcha service unavailable ({result.error or 'unknown'}).",
            )
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
) -> KerniaPlugin:
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


__all__ = ["CAPTCHA_ERROR_CODES", "DEFAULT_PROTECTED_ENDPOINTS", "captcha"]
