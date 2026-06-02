# Admin Config

> Module: `kernia.plugins.admin_config`
> Constructor: `admin_config`

Database-backed admin configuration.

Persists runtime-facing settings for auth method availability, email clients,
Stripe setup, and the public sign-in UI. The plugin also gates configured auth
routes so disabled login methods fail before their handlers run.

## Endpoints

| Method | Path |
| --- | --- |
| `GET` | `/admin/config/public-auth` |
| `GET` | `/admin/config/auth-methods` |
| `POST` | `/admin/config/auth-methods` |
| `GET` | `/admin/config/email-clients` |
| `POST` | `/admin/config/email-clients` |
| `GET` | `/admin/config/stripe` |
| `POST` | `/admin/config/stripe` |

## Schema contributions

**New tables:**

- `adminConfig` — fields: id, key, value, secretFields, createdAt, updatedAt

## Usage

```python
from kernia.plugins.admin_config import admin_config
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            admin_config(),
        ],
    )
)
```
