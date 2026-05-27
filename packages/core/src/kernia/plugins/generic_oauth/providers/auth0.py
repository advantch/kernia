"""Auth0 helper for the generic OAuth plugin.

Mirrors `reference/.../plugins/generic-oauth/providers/auth0.ts`.
"""

from __future__ import annotations

from kernia.plugins.generic_oauth.config import GenericOAuthConfig


def auth0(
    *,
    client_id: str,
    client_secret: str,
    domain: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
    redirect_uri: str | None = None,
    pkce: bool = False,
    disable_implicit_sign_up: bool = False,
    disable_sign_up: bool = False,
    override_user_info: bool = False,
) -> GenericOAuthConfig:
    """Construct an Auth0 generic-OAuth config.

    `domain` is the tenant hostname, e.g. ``dev-xxx.eu.auth0.com``.
    """
    clean = domain.replace("https://", "").replace("http://", "").rstrip("/")
    return GenericOAuthConfig(
        provider_id="auth0",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        discovery_url=f"https://{clean}/.well-known/openid-configuration",
        pkce=pkce,
        disable_implicit_sign_up=disable_implicit_sign_up,
        disable_sign_up=disable_sign_up,
        override_user_info=override_user_info,
    )


__all__ = ["auth0"]
