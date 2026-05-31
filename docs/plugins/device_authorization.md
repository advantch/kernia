# Device Authorization

> Module: `kernia.plugins.device_authorization`
> Constructor: `device_authorization`

device_authorization — see Better Auth reference: plugins/device-authorization/.

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/device/code` |
| `POST` | `/device/token` |
| `GET` | `/device` |
| `POST` | `/device/approve` |
| `POST` | `/device/deny` |

## Schema contributions

**New tables:**

- `deviceCode` — fields: id, deviceCode, userCode, userId, expiresAt, status, pollingInterval, clientId, scope, lastPolledAt, createdAt, updatedAt

## Usage

```python
from kernia.plugins.device_authorization import device_authorization
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            device_authorization(),
        ],
    )
)
```
