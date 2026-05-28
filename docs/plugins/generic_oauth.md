# Generic Oauth

> Module: `kernia.plugins.generic_oauth`
> Constructor: `generic_oauth`

Generic OAuth plugin.

Mirrors `Better Auth reference: plugins/generic-oauth/`. Lets users
plug in any OAuth2/OIDC provider by URL — discovery, code exchange, userinfo —
without writing a dedicated provider module.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.generic_oauth import generic_oauth
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            generic_oauth(),
        ],
    )
)
```
