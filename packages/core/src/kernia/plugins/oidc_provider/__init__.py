"""OIDC provider plugin compatibility entry point.

The implementation lives in the standalone ``kernia-oauth-provider`` package so
projects that do not issue OAuth/OIDC tokens do not need those dependencies.
"""

try:
    from kernia_oauth_provider import OAuthClient, OAuthProviderOptions, oauth_provider
except ImportError as exc:  # pragma: no cover - dependency packaging guard
    raise ImportError(
        "kernia.plugins.oidc_provider requires the kernia-oauth-provider package"
    ) from exc

oidc_provider = oauth_provider

__all__ = ["oidc_provider", "oauth_provider", "OAuthProviderOptions", "OAuthClient"]
