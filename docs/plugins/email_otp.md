# Email Otp

> Module: `kernia.plugins.email_otp`
> Constructor: `email_otp`

email_otp — see Better Auth reference: plugins/email-otp/.

Six-digit OTPs delivered out-of-band via a caller-provided `send_otp` callable.
Supports sign-in, email verification, password reset, and email change flows.
Tokens are stored on the core `verification` table keyed by
`email-otp:<purpose>:<email>`.

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/sign-in/email-otp` |
| `POST` | `/email-otp/verify` |
| `POST` | `/email-otp/send-verification-otp` |
| `POST` | `/email-otp/verify-email` |
| `POST` | `/forget-password/email-otp` |
| `POST` | `/email-otp/reset-password` |
| `POST` | `/email-otp/request-email-change` |
| `POST` | `/email-otp/change-email` |

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.email_otp import email_otp
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            email_otp(),
        ],
    )
)
```
