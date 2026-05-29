"""SSO plugin assembly.

Returns a `BetterAuthPlugin` value that contributes the SSO endpoints, schema,
error codes, and the `/sign-in/email` BeforeHook that redirects users with a
verified-SSO email domain into the matching OIDC or SAML flow.

Configuration lives under `BetterAuthOptions.advanced["sso"]`:

    advanced={
        "sso": {
            "is_admin": lambda user: user.get("role") == "admin",
            "disable_admin_check": False,
            "http_transport": some_httpx_transport,   # tests
            "saml_validation": "strict" | "permissive",
            "enforce_email_domain": True,             # default True
        }
    }
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import BeforeHook, PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

from better_auth_sso import routes as _routes
from better_auth_sso.domain import provider_for_email
from better_auth_sso.errors import SSO_ERROR_CODES
from better_auth_sso.schema import SSO_MODELS

_OPTS_KEY = "sso"


async def _enforce_sso_on_email_signin(ctx: EndpointContext) -> None:
    """Hijack `/sign-in/email` if the email belongs to a verified SSO domain.

    We don't want to mutate the response shape directly here (BeforeHooks return
    `None`). Instead we raise a structured `APIError` with status 200 disguised
    as a redirect payload: tests + clients use the `code` to detect this.

    Convention here mirrors better-auth's TS plugin: return 200 with a
    `redirect` field so the client follows the SSO flow instead of submitting
    the password.
    """
    opts = ctx.auth.options.advanced.get(_OPTS_KEY) or {}
    if not opts.get("enforce_email_domain", True):
        return
    body = ctx.body
    email = getattr(body, "email", None)
    if isinstance(body, dict):
        email = body.get("email")
    if not email:
        return
    match = await provider_for_email(ctx.auth, email)
    if match is None:
        return
    provider_id, _domain = match
    # Find the provider so we know which sign-in URL to point at.
    provider = await ctx.auth.adapter.find_one(
        model="ssoProvider",
        where=(Where(field="id", value=provider_id),),
    )
    if provider is None:
        return
    kind = provider["kind"]
    if kind == "oidc":
        path = f"/sso/oidc/sign-in/{provider_id}"
    else:
        path = f"/sso/saml/sign-in/{provider_id}"
    redirect = f"{ctx.auth.base_url}{path}"
    # Short-circuit with a 200 payload: APIError lets us set status freely.
    raise _SSORedirect(redirect=redirect, provider_id=provider_id)


class _SSORedirect(APIError):
    """Special-cased 200 short-circuit carrying a redirect URL.

    BeforeHooks can't return a body, but they can `raise`. We use this to
    bubble a structured `{redirect, provider}` payload out of the hook with
    HTTP 200.
    """

    def __init__(self, *, redirect: str, provider_id: str) -> None:
        super().__init__(200, "SSO_REDIRECT", message="SSO redirect")
        self.redirect = redirect
        self.provider_id = provider_id

    def to_dict(self) -> dict[str, object]:
        return {
            "redirect": self.redirect,
            "providerId": self.provider_id,
            "code": "SSO_REDIRECT",
        }


SSO_HOOKS = PluginHooks(
    before=(
        BeforeHook(
            match="/sign-in/email",
            handler=_enforce_sso_on_email_signin,
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class _SSOPlugin:
    id: str = "sso"
    version: str | None = "0.1.0"
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(tables=SSO_MODELS)
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: _routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = SSO_HOOKS
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sso/oidc/sign-in/*", window=60, max=20),
        RateLimitRule(path="/sso/saml/sign-in/*", window=60, max=20),
        RateLimitRule(path="/sso/saml/acs/*", window=60, max=30),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(SSO_ERROR_CODES) | {"SSO_REDIRECT": "SSO redirect"}
    )
    init: None = None


def sso() -> BetterAuthPlugin:
    """Build the SSO plugin."""
    return _SSOPlugin()  # type: ignore[return-value]


__all__ = ["SSO_HOOKS", "sso"]
