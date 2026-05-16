# Oidc Provider

> Module: `better_auth.plugins.oidc_provider`
> Constructor: `oidc_provider`

oidc_provider — see reference/packages/better-auth/src/plugins/oidc-provider/.

Implemented in Lane C/D/E/F per the parity plan.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.oidc_provider import oidc_provider
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            oidc_provider(),
        ],
    )
)
```
