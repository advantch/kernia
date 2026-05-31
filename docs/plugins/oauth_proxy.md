# Oauth Proxy

> Module: `kernia.plugins.oauth_proxy`
> Constructor: `oauth_proxy`

OAuth Proxy plugin.

Mirrors `Better Auth reference: plugins/oauth-proxy/` for a simpler
use case: an SPA can't safely hold an OAuth client_secret, so the server proxies
the entire flow.

Endpoints:
  * GET  /oauth-proxy-callback — upstream passthrough receiver: decrypt an
    encrypted profile payload, validate + freshness-check it, create the user +
    session, and 302 to the final callback URL.
  * POST /oauth-proxy/authorize — SPA helper: returns the authorize URL as JSON.
  * GET  /oauth-proxy/callback — SPA helper: server-side callback that creates a
    session.

## Endpoints

| Method | Path |
| --- | --- |
| `GET` | `/oauth-proxy-callback` |
| `POST` | `/oauth-proxy/authorize` |
| `GET` | `/oauth-proxy/callback` |

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
