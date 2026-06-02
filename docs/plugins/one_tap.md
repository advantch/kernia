# One Tap

> Module: `kernia.plugins.one_tap`
> Constructor: `one_tap`

Google One Tap plugin.

Mirrors `Better Auth reference: plugins/one-tap/`. The browser
obtains an id_token from Google's One Tap library and POSTs it here; we verify
it via the existing `kernia.oauth2.verify_id_token` against Google's JWKS
and resolve a user via `handle_oauth_user_info`.

Endpoint: POST /one-tap/verify

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/one-tap/callback` |
| `POST` | `/one-tap/verify` |

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.one_tap import one_tap
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            one_tap(),
        ],
    )
)
```
