# Access

> Module: `better_auth.plugins.access`
> Constructor: `AccessControl`

access — primitives used by `admin`, `organization`, `api_key`, `scim` for RBAC.

Mirrors `reference/packages/better-auth/src/plugins/access/`.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.access import AccessControl
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            AccessControl(),
        ],
    )
)
```
