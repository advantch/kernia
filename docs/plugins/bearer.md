# Bearer

> Module: `better_auth.plugins.bearer`
> Constructor: `bearer`

bearer — see reference/packages/better-auth/src/plugins/bearer/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.bearer import bearer
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            bearer(),
        ],
    )
)
```
