"""OAuth Proxy plugin.

Mirrors `reference/packages/better-auth/src/plugins/oauth-proxy/` for a simpler
use case: an SPA can't safely hold an OAuth client_secret, so the server proxies
the entire flow.

Endpoints:
  * POST /oauth-proxy/authorize — returns the authorize URL as JSON
  * GET  /oauth-proxy/callback — server-side callback that creates a session
"""

from better_auth.plugins.oauth_proxy.plugin import OAuthProxyOptions, oauth_proxy

__all__ = ["oauth_proxy", "OAuthProxyOptions"]
