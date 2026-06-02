"""Keycloak helper for the generic OAuth plugin."""

from __future__ import annotations

from kernia.plugins.generic_oauth.config import GenericOAuthConfig


def keycloak(
    *,
    client_id: str,
    client_secret: str,
    issuer: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
    redirect_uri: str | None = None,
    pkce: bool = False,
    disable_implicit_sign_up: bool = False,
    disable_sign_up: bool = False,
    override_user_info: bool = False,
) -> GenericOAuthConfig:
    base = issuer.rstrip("/")
    return GenericOAuthConfig(
        provider_id="keycloak",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        discovery_url=f"{base}/.well-known/openid-configuration",
        pkce=pkce,
        disable_implicit_sign_up=disable_implicit_sign_up,
        disable_sign_up=disable_sign_up,
        override_user_info=override_user_info,
    )


__all__ = ["keycloak"]
