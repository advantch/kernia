# Email Otp

> Module: `kernia.plugins.email_otp`
> Constructor: `EMAIL_OTP_ERROR_CODES`

email_otp — see reference/packages/better-auth/src/plugins/email-otp/.

Six-digit OTPs delivered out-of-band via a caller-provided `send_otp` callable.
Supports sign-in, email verification, password reset, and email change flows.
Tokens are stored on the core `verification` table keyed by
`email-otp:<purpose>:<email>`.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.email_otp import EMAIL_OTP_ERROR_CODES
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            EMAIL_OTP_ERROR_CODES(),
        ],
    )
)
```
