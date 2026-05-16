# Device Authorization

> Module: `better_auth.plugins.device_authorization`
> Constructor: `DEVICE_AUTHORIZATION_ERROR_CODES`

device_authorization — see reference/packages/better-auth/src/plugins/device-authorization/.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.device_authorization import DEVICE_AUTHORIZATION_ERROR_CODES
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            DEVICE_AUTHORIZATION_ERROR_CODES(),
        ],
    )
)
```
