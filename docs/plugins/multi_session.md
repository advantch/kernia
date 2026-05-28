# Multi Session

> Module: `kernia.plugins.multi_session`
> Constructor: `multi_session`

multi_session — see Better Auth reference: plugins/multi-session/.

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
from kernia.plugins.multi_session import multi_session
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            multi_session(),
        ],
    )
)
```
