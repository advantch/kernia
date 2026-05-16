# Custom Session

> Module: `better_auth.plugins.custom_session`
> Constructor: `SessionProvider`

custom_session — see reference/packages/better-auth/src/plugins/custom-session/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.custom_session import SessionProvider
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            SessionProvider(),
        ],
    )
)
```
