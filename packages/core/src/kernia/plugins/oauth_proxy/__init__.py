"""OAuth Proxy plugin.

Mirrors `reference/packages/better-auth/src/plugins/oauth-proxy/`.

Endpoints:
  * GET  /oauth-proxy-callback — upstream passthrough receiver: decrypt an
    encrypted profile payload, validate + freshness-check it, create the user +
    session, and 302 to the final callback URL.
  * POST /oauth-proxy/authorize — SPA helper: returns the authorize URL as JSON.
  * GET  /oauth-proxy/callback — SPA helper: server-side callback that creates a
    session.
"""

from kernia.plugins.oauth_proxy.plugin import OAuthProxyOptions, oauth_proxy

__all__ = ["oauth_proxy", "OAuthProxyOptions", "symmetric_encrypt", "symmetric_decrypt"]
