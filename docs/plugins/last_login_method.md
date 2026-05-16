# Last Login Method

> Module: `better_auth.plugins.last_login_method`
> Constructor: `last_login_method`

last_login_method — see reference/packages/better-auth/src/plugins/last-login-method/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.last_login_method import last_login_method
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            last_login_method(),
        ],
    )
)
```
