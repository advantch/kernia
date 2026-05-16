# {plugin_name}

> Module: `{plugin_module}`
> Constructor: `{plugin_constructor}`

{plugin_docstring}

## Endpoints

{endpoints_section}

## Schema contributions

{schema_section}

## Usage

```python
from {plugin_module} import {plugin_constructor}
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            {plugin_constructor}(),
        ],
    )
)
```
