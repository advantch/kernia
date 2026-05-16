# One Tap

> Module: `better_auth.plugins.one_tap`
> Constructor: `one_tap`

one_tap — see reference/packages/better-auth/src/plugins/one-tap/.

Implemented in Lane C/D/E/F per the parity plan.

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
