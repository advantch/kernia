"""OAuth2 / OIDC Provider (issuer side) plugin.

Implements the server side of the OAuth2 + OIDC flow: clients register, users
authorize, codes exchange for access/refresh/id tokens. Mirrors the layout in
`reference/packages/oauth-provider/src/`.

Public entry point: `oauth_provider(options)`.
"""

from kernia_oauth_provider.plugin import (
    OAuthClient,
    OAuthProviderOptions,
    oauth_provider,
)

__all__ = ["OAuthClient", "OAuthProviderOptions", "oauth_provider"]
