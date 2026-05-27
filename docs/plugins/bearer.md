# Bearer

> Module: `kernia.plugins.bearer`
> Constructor: `bearer`

bearer — see reference/packages/better-auth/src/plugins/bearer/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.bearer import bearer
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            bearer(),
        ],
    )
)
```
