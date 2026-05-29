# Additional Fields

> Module: `better_auth.plugins.additional_fields`
> Constructor: `AdditionalFieldsConfig`

additional_fields plugin — declare extra user/session fields on the schema.

Mirrors `reference/packages/better-auth/src/plugins/additional-fields/`.

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
from better_auth.plugins.additional_fields import AdditionalFieldsConfig
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            AdditionalFieldsConfig(),
        ],
    )
)
```
