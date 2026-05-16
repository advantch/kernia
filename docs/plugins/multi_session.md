# Multi Session

> Module: `better_auth.plugins.multi_session`
> Constructor: `multi_session`

multi_session — see reference/packages/better-auth/src/plugins/multi-session/.

## Endpoints

| Method | Path |
| --- | --- |
| `GET` | `/multi-session/list` |
| `POST` | `/multi-session/switch` |
| `POST` | `/multi-session/revoke` |

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.multi_session import multi_session
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            multi_session(),
        ],
    )
)
```
