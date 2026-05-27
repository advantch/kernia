# Additional Fields

> Module: `kernia.plugins.additional_fields`
> Constructor: `additional_fields`

additional_fields — see reference/packages/better-auth/src/plugins/additional-fields/.

Implemented in Lane C/D/E/F per the parity plan.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.additional_fields import additional_fields
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            additional_fields(),
        ],
    )
)
```
