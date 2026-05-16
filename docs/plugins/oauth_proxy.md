# Oauth Proxy

> Module: `better_auth.plugins.oauth_proxy`
> Constructor: `oauth_proxy`

OAuth Proxy plugin.

Mirrors `reference/packages/better-auth/src/plugins/oauth-proxy/` for a simpler
use case: an SPA can't safely hold an OAuth client_secret, so the server proxies
the entire flow.

Endpoints:
  * POST /oauth-proxy/authorize — returns the authorize URL as JSON
  * GET  /oauth-proxy/callback — server-side callback that creates a session

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.oauth_proxy import oauth_proxy
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            oauth_proxy(),
        ],
    )
)
```
