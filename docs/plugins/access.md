# Access

> Module: `kernia.plugins.access`
> Constructor: `AccessControl`

access — primitives used by `admin`, `organization`, `api_key`, `scim` for RBAC.

Mirrors `reference/packages/better-auth/src/plugins/access/`.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.access import AccessControl
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            AccessControl(),
        ],
    )
)
```
