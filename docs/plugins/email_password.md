# Email Password

> Module: `kernia.plugins.email_password`
> Constructor: `email_and_password`

Email/password plugin.

Built into `Better Auth` itself (not a third-party plugin). Mirrors
`Better Auth reference: api/routes/sign-up-email.ts`,
`sign-in-email.ts`, `forget-password.ts`, `reset-password.ts`.

Exposes the canonical routes:
  * POST /sign-up/email
  * POST /sign-in/email
  * POST /forget-password
  * POST /reset-password

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/sign-up/email` |
| `POST` | `/sign-in/email` |
| `POST` | `/sign-out` |
| `GET` | `/get-session` |
| `POST` | `/forget-password` |
| `POST` | `/reset-password` |

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.email_password import email_and_password
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            email_and_password(),
        ],
    )
)
```
