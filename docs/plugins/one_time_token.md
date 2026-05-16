# One Time Token

> Module: `better_auth.plugins.one_time_token`
> Constructor: `ONE_TIME_TOKEN_ERROR_CODES`

one_time_token — see reference/packages/better-auth/src/plugins/one-time-token/.

Generates a single-use disposable token bound to a session's user id + a caller
provided purpose string. Backed by the `verification` core table.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.one_time_token import ONE_TIME_TOKEN_ERROR_CODES
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            ONE_TIME_TOKEN_ERROR_CODES(),
        ],
    )
)
```
