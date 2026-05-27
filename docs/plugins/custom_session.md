# Custom Session

> Module: `kernia.plugins.custom_session`
> Constructor: `SessionProvider`

custom_session — see reference/packages/better-auth/src/plugins/custom-session/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.custom_session import SessionProvider
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            SessionProvider(),
        ],
    )
)
```
