# Anonymous

> Module: `better_auth.plugins.anonymous`
> Constructor: `ANONYMOUS_ERROR_CODES`

anonymous plugin — port of `reference/packages/better-auth/src/plugins/anonymous/`.

Provides ephemeral, account-less sign-in for first-time visitors. Hooks into the
email-password and magic-link sign-in/sign-up flows so that when an anonymous user
later "graduates" to a real account, the anonymous user row is collapsed into the
new user (via an optional `on_link` callback) and then deleted.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.anonymous import ANONYMOUS_ERROR_CODES
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            ANONYMOUS_ERROR_CODES(),
        ],
    )
)
```
