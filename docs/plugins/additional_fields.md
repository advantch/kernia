# Additional Fields

> Module: `kernia.plugins.additional_fields`
> Constructor: `additional_fields`

additional_fields plugin — declare extra user/session fields on the schema.

Mirrors `Better Auth reference: plugins/additional-fields/`.

Usage:

    additional_fields({
        "user": {
            "company":    {"type": "string", "required": True},
            "department": {"type": "string"},
        }
    })

Declared fields are merged into the plugin schema (contributed via
`PluginSchema.extend`). An `after` hook scoped to `/sign-up/email` pulls any
declared user-shape fields from the raw request body and writes them onto the
freshly created user row before the response is serialized.

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
