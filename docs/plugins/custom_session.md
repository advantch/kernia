# Custom Session

> Module: `kernia.plugins.custom_session`
> Constructor: `with_custom_session`

custom_session — see Better Auth reference: plugins/custom-session/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.custom_session import with_custom_session
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            with_custom_session(),
        ],
    )
)
```
