# Oauth Proxy

> Module: `kernia.plugins.oauth_proxy`
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
from kernia.plugins.oauth_proxy import oauth_proxy
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            oauth_proxy(),
        ],
    )
)
```
