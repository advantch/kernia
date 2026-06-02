# Admin config

`kernia.plugins.admin_config` stores runtime configuration in the Kernia
database. It is intended for SaaS control panels where operators need to enable
or disable auth methods, configure email providers, and manage Stripe settings
without editing Python code.

## Install

The plugin ships in the core `kernia` package.

```python
from kernia.plugins.admin_config import admin_config

auth = init(
    KerniaOptions(
        database=adapter,
        secret="change-me",
        plugins=[admin_config(), ...],
    )
)
```

## Routes

| Route | Purpose |
| --- | --- |
| `GET /api/auth/admin/config/public-auth` | Public login UI config. |
| `GET /api/auth/admin/config/auth-methods` | Read method toggles. |
| `POST /api/auth/admin/config/auth-methods` | Persist method toggles. |
| `GET /api/auth/admin/config/email-clients` | Read redacted email clients. |
| `POST /api/auth/admin/config/email-clients` | Write email clients. |
| `GET /api/auth/admin/config/stripe` | Read redacted Stripe settings. |
| `POST /api/auth/admin/config/stripe` | Write Stripe settings. |

Secret fields such as API keys, SMTP passwords, webhook secrets, and private
keys are write-only. Reads return `********`.

## Auth-method gate

Registered routes remain mounted so clients see a stable API surface. When a
method is disabled, Kernia rejects the request before the handler runs with
`AUTH_METHOD_DISABLED`.

The demo uses `allow_any_authenticated=True` to keep local setup simple. In
production, leave that off and use user roles or explicit admin IDs.
