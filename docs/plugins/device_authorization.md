# Device Authorization

> Module: `kernia.plugins.device_authorization`
> Constructor: `DEVICE_AUTHORIZATION_ERROR_CODES`

device_authorization — see reference/packages/better-auth/src/plugins/device-authorization/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.device_authorization import DEVICE_AUTHORIZATION_ERROR_CODES
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            DEVICE_AUTHORIZATION_ERROR_CODES(),
        ],
    )
)
```
