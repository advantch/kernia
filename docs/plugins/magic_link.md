# Magic Link

> Module: `better_auth.plugins.magic_link`
> Constructor: `MAGIC_LINK_ERROR_CODES`

magic_link — see reference/packages/better-auth/src/plugins/magic-link/.

Passwordless sign-in via emailed short-lived URLs. Tokens are persisted in the
core `verification` table with identifier `magic-link:<token>` and atomically
consumed on first GET to `/magic-link/verify`.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.magic_link import MAGIC_LINK_ERROR_CODES
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            MAGIC_LINK_ERROR_CODES(),
        ],
    )
)
```
