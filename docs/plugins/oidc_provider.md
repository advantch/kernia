# Oidc Provider

> Module: `kernia.plugins.oidc_provider`
> Constructor: `oidc_provider`

OIDC provider plugin compatibility entry point.

The implementation lives in the standalone ``kernia-oauth-provider`` package so
projects that do not issue OAuth/OIDC tokens do not need those dependencies.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.oidc_provider import oidc_provider
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            oidc_provider(),
        ],
    )
)
```
