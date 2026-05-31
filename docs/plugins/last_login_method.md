# Last Login Method

> Module: `kernia.plugins.last_login_method`
> Constructor: `last_login_method`

last_login_method — see Better Auth reference: plugins/last-login-method/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.last_login_method import last_login_method
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            last_login_method(),
        ],
    )
)
```
