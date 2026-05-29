# One Tap

> Module: `better_auth.plugins.one_tap`
> Constructor: `one_tap`

Google One Tap plugin.

Mirrors `reference/packages/better-auth/src/plugins/one-tap/`. The browser
obtains an id_token from Google's One Tap library and POSTs it here; we verify
it via the existing `better_auth.oauth2.verify_id_token` against Google's JWKS
and resolve a user via `handle_oauth_user_info`.

Endpoint: POST /one-tap/verify

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.one_tap import one_tap
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            one_tap(),
        ],
    )
)
```
