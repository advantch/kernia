# Username

> Module: `better_auth.plugins.username`
> Constructor: `USERNAME_ERROR_CODES`

username plugin — port of `reference/packages/better-auth/src/plugins/username/`.

Adds username-based sign-up/sign-in alongside the email/password credential rows.
The username column is stored in normalized (lower-case) form; `displayUsername`
preserves the originally-supplied casing.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.username import USERNAME_ERROR_CODES
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            USERNAME_ERROR_CODES(),
        ],
    )
)
```
