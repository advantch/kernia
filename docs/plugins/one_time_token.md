# One Time Token

> Module: `kernia.plugins.one_time_token`
> Constructor: `one_time_token`

one_time_token — see Better Auth reference: plugins/one-time-token/.

Generates a single-use disposable token bound to a session's user id + a caller
provided purpose string. Backed by the `verification` core table.

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/generate-one-time-token` |
| `POST` | `/verify-one-time-token` |

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.one_time_token import one_time_token
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            one_time_token(),
        ],
    )
)
```
